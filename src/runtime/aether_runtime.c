#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define IDLE_TIMEOUT_NS (5ULL * 1000000000ULL)

struct aether_cfg {
    uint32_t target_port;
    uint32_t target_pid;
    uint32_t is_sleeping;
    uint32_t reserved;
    uint64_t last_pkt_ns;
    uint64_t wake_count;
};

struct aether_wake_event {
    uint32_t pid;
    uint32_t port;
    uint32_t pkt_len;
    uint32_t reserved;
    uint64_t pkt_ts_ns;
};

static volatile sig_atomic_t g_running = 1;
static pid_t g_target_pid = -1;
static int g_cfg_fd = -1;
static pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t now_ktime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void on_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

static double get_pid_rss_mb(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0.0;
    char line[256];
    double mb = 0.0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            unsigned long kb = 0;
            if (sscanf(line + 6, "%lu", &kb) == 1) {
                mb = (double)kb / 1024.0;
            }
            break;
        }
    }
    fclose(f);
    return mb;
}

static void evict_ram_via_socket(pid_t pid, char *out, size_t out_sz) {
    snprintf(out, out_sz, "N/A");
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/aether_ctl_%d.sock", pid);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        if (write(fd, "EVICT", 5) == 5) {
            ssize_t n = read(fd, out, out_sz - 1);
            if (n > 0) {
                out[n] = '\0';
                char *nl = strchr(out, '\n');
                if (nl) *nl = '\0';
            }
        }
    }
    close(fd);
}

static int handle_wake_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct aether_wake_event)) return 0;

    const struct aether_wake_event *ev = (const struct aether_wake_event *)data;
    uint64_t t0 = now_ktime_ns();
    pthread_mutex_lock(&g_state_lock);
    if (g_target_pid > 0) {
        kill(g_target_pid, SIGCONT);
    }
    pthread_mutex_unlock(&g_state_lock);
    uint64_t t1 = now_ktime_ns();

    double sig_ms = (double)(t1 - t0) / 1e6;
    double ebpf_ms = (double)(t1 - ev->pkt_ts_ns) / 1e6;

    printf("\n[eBPF-RINGBUF] Paquete TCP (%u bytes) -> puerto %u | Resucitando PID %u\n",
           ev->pkt_len, ev->port, ev->pid);
    printf("[AETHER-CORE]  SIGCONT: %.3f ms | Latencia kernel eBPF->Wake: %.3f ms\n",
           sig_ms, ebpf_ms > 0.0 ? ebpf_ms : sig_ms);
    fflush(stdout);
    return 0;
}

static void *idle_monitor_loop(void *arg) {
    (void)arg;
    while (g_running) {
        usleep(250000);
        if (!g_running) break;

        uint32_t key = 0;
        struct aether_cfg cfg;
        pthread_mutex_lock(&g_state_lock);
        if (bpf_map_lookup_elem(g_cfg_fd, &key, &cfg) == 0 && !cfg.is_sleeping) {
            uint64_t now = now_ktime_ns();
            if (now > cfg.last_pkt_ns && (now - cfg.last_pkt_ns) > IDLE_TIMEOUT_NS) {
                double rss_before = get_pid_rss_mb(g_target_pid);
                char evict_msg[160];
                evict_ram_via_socket(g_target_pid, evict_msg, sizeof(evict_msg));
                double rss_after = get_pid_rss_mb(g_target_pid);

                cfg.is_sleeping = 1;
                bpf_map_update_elem(g_cfg_fd, &key, &cfg, BPF_ANY);
                kill(g_target_pid, SIGSTOP);

                printf("\n[AETHER-MEM]   Inactivo > 5s | RAM antes: %.1f MB -> [%s]\n",
                       rss_before, evict_msg);
                printf("[AETHER-CORE]  PID %d SUSPENDIDO -> CPU: 0.0%% | VmRSS: %.1f MB\n",
                       g_target_pid, rss_after);
                fflush(stdout);
            }
        }
        pthread_mutex_unlock(&g_state_lock);
    }
    return NULL;
}

int main(int argc, char **argv) {
    uint32_t port = (argc > 1) ? (uint32_t)atoi(argv[1]) : 8765;
    const char *app_script = (argc > 2) ? argv[2] : "examples/stateful_ws_server.py";

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    char so_abs[PATH_MAX];
    if (!realpath("build/libaether_mem.so", so_abs) && !realpath("libaether_mem.so", so_abs)) {
        fprintf(stderr, "[ERROR] No se encuentra libaether_mem.so\n");
        return 1;
    }

    const char *bpf_obj = access("build/aether_wake.bpf.o", R_OK) == 0
                              ? "build/aether_wake.bpf.o"
                              : "aether_wake.bpf.o";
    struct bpf_object *obj = bpf_object__open_file(bpf_obj, NULL);
    if (!obj) {
        fprintf(stderr, "[ERROR] Abriendo aether_wake.bpf.o: %s\n", strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "[ERROR] Cargando eBPF en kernel (ejecuta con sudo): %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "aether_ingress_wake");
    g_cfg_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    int rb_fd = bpf_object__find_map_fd_by_name(obj, "wake_ringbuf");

    int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "[ERROR] Abriendo /sys/fs/cgroup: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_cgroup(prog, cgroup_fd);
    if (!link) {
        fprintf(stderr, "[ERROR] bpf_program__attach_cgroup fallo: %s\n", strerror(errno));
        close(cgroup_fd);
        bpf_object__close(obj);
        return 1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        const char *sudo_gid = getenv("SUDO_GID");
        const char *sudo_uid = getenv("SUDO_UID");
        const char *sudo_user = getenv("SUDO_USER");
        if (sudo_gid) {
            if (setgid((gid_t)atoi(sudo_gid)) != 0) _exit(126);
        }
        if (sudo_uid) {
            if (setuid((uid_t)atoi(sudo_uid)) != 0) _exit(126);
        }
        if (sudo_user) {
            char home_buf[128];
            snprintf(home_buf, sizeof(home_buf), "/home/%s", sudo_user);
            setenv("HOME", home_buf, 1);
        }
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%u", port);
        setenv("LD_PRELOAD", so_abs, 1);
        execlp("python3", "python3", "-u", app_script, port_str, NULL);
        _exit(127);
    }
    g_target_pid = pid;

    printf("==================================================================\n");
    printf("  AETHER CONTINUUM v3: KERNEL eBPF (ringbuf) + ZSTD + USERFAULTFD\n");
    printf("  Zero-Proxy Direct Socket en :%u | Backend PID: %d\n", port, g_target_pid);
    printf("==================================================================\n");
    fflush(stdout);

    usleep(1800000);

    uint32_t key = 0;
    struct aether_cfg cfg = {
        .target_port = port,
        .target_pid = (uint32_t)g_target_pid,
        .is_sleeping = 0,
        .reserved = 0,
        .last_pkt_ns = now_ktime_ns(),
        .wake_count = 0
    };
    bpf_map_update_elem(g_cfg_fd, &key, &cfg, BPF_ANY);

    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_wake_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ERROR] Creando ring_buffer\n");
        kill(g_target_pid, SIGKILL);
        bpf_link__destroy(link);
        close(cgroup_fd);
        bpf_object__close(obj);
        return 1;
    }

    pthread_t mon_th;
    pthread_create(&mon_th, NULL, idle_monitor_loop, NULL);

    while (g_running) {
        int err = ring_buffer__poll(rb, 250);
        if (err < 0 && err != -EINTR) break;
    }

    g_running = 0;
    pthread_join(mon_th, NULL);
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    close(cgroup_fd);
    bpf_object__close(obj);

    if (g_target_pid > 0) {
        kill(g_target_pid, SIGCONT);
        kill(g_target_pid, SIGKILL);
        waitpid(g_target_pid, NULL, 0);
    }
    return 0;
}
