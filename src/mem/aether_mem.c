#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define TRACK_MIN_SIZE (16UL * 1024UL * 1024UL)
#define MAX_REGIONS 64
#define PAGE_SIZE 4096UL
#define ZSTD_LEVEL 1

typedef struct {
    uint64_t file_off;
    uint16_t comp_len;
    uint8_t compressed;
    uint8_t valid;
} AetherPageMeta;

typedef struct {
    void *ptr;
    size_t len;
    size_t npages;
    AetherPageMeta *pages;
    int in_use;
    int uffd_registered;
    int evicted;
} AetherRegion;

static AetherRegion g_regions[MAX_REGIONS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_uffd = -1;
static int g_swap_fd = -1;
static off_t g_next_disk_offset = 0;
static volatile uint64_t g_total_faults = 0;
static volatile uint64_t g_total_disk_bytes = 0;
static char g_sock_path[100];
static char g_swap_path[100];

/* Dynamic Zstandard symbols loaded via dlopen(libzstd.so.1) */
static void *g_zstd_lib = NULL;
static size_t (*p_ZSTD_compress)(void *, size_t, const void *, size_t, int) = NULL;
static size_t (*p_ZSTD_decompress)(void *, size_t, const void *, size_t) = NULL;
static size_t (*p_ZSTD_compressBound)(size_t) = NULL;
static unsigned (*p_ZSTD_isError)(size_t) = NULL;
static size_t g_comp_bound = 8192;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int write_all_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;
    while (done < count) {
        ssize_t n = pwrite(fd, p + done, count - done, offset + (off_t)done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

static int read_all_pread(int fd, void *buf, size_t count, off_t offset) {
    uint8_t *p = (uint8_t *)buf;
    size_t done = 0;
    while (done < count) {
        ssize_t n = pread(fd, p + done, count - done, offset + (off_t)done);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

static int find_region_meta_for_addr(uint64_t addr, AetherPageMeta *out_meta) {
    for (int i = 0; i < MAX_REGIONS; i++) {
        if (g_regions[i].in_use && g_regions[i].pages) {
            uint64_t start = (uint64_t)g_regions[i].ptr;
            uint64_t end = start + g_regions[i].len;
            if (addr >= start && addr < end) {
                size_t p = (size_t)((addr - start) / PAGE_SIZE);
                *out_meta = g_regions[i].pages[p];
                return out_meta->valid;
            }
        }
    }
    return 0;
}

static void discover_large_anon_vmas_locked(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0, offset = 0, inode = 0;
        char perms[8] = {0};
        char dev[16] = {0};
        char path[256] = {0};

        int fields = sscanf(line, "%lx-%lx %7s %lx %15s %lu %255s",
                            &start, &end, perms, &offset, dev, &inode, path);
        if (fields < 6) continue;
        if (strcmp(perms, "rw-p") != 0) continue;
        if (inode != 0) continue;
        if (fields == 7 && path[0] != '\0') continue;

        size_t len = (size_t)(end - start);
        if (len < TRACK_MIN_SIZE) continue;

        int already = 0;
        for (int i = 0; i < MAX_REGIONS; i++) {
            if (g_regions[i].in_use && (unsigned long)g_regions[i].ptr == start && g_regions[i].len == len) {
                already = 1;
                break;
            }
        }
        if (already) continue;

        for (int i = 0; i < MAX_REGIONS; i++) {
            if (!g_regions[i].in_use) {
                size_t npages = len / PAGE_SIZE;
                size_t meta_sz = ((npages * sizeof(AetherPageMeta)) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
                AetherPageMeta *meta = (AetherPageMeta *)syscall(
                    SYS_mmap, NULL, meta_sz, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (meta == MAP_FAILED) break;

                g_regions[i].ptr = (void *)start;
                g_regions[i].len = len;
                g_regions[i].npages = npages;
                g_regions[i].pages = meta;
                g_regions[i].in_use = 1;
                g_regions[i].uffd_registered = 0;
                g_regions[i].evicted = 0;
                break;
            }
        }
    }
    fclose(f);
}

static void *uffd_fault_loop(void *arg) {
    (void)arg;
    uint8_t *page_buf = (uint8_t *)syscall(
        SYS_mmap, NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *comp_buf = (uint8_t *)syscall(
        SYS_mmap, NULL, g_comp_bound > PAGE_SIZE ? g_comp_bound : PAGE_SIZE * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    while (1) {
        struct pollfd pfd = { .fd = g_uffd, .events = POLLIN };
        int nready = poll(&pfd, 1, -1);
        if (nready < 0) {
            if (errno == EINTR) continue;
            break;
        }

        struct uffd_msg msg;
        ssize_t nread = read(g_uffd, &msg, sizeof(msg));
        if (nread <= 0) {
            if (nread < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            break;
        }

        if (msg.event == UFFD_EVENT_PAGEFAULT) {
            uint64_t fault_addr = msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
            AetherPageMeta meta;
            int found = 0;

            pthread_mutex_lock(&g_lock);
            found = find_region_meta_for_addr(fault_addr, &meta);
            pthread_mutex_unlock(&g_lock);

            if (!found) continue;

            if (read_all_pread(g_swap_fd, comp_buf, meta.comp_len, (off_t)meta.file_off) == 0) {
                if (meta.compressed && p_ZSTD_decompress) {
                    size_t dsz = p_ZSTD_decompress(page_buf, PAGE_SIZE, comp_buf, meta.comp_len);
                    if (p_ZSTD_isError && p_ZSTD_isError(dsz)) continue;
                } else {
                    memcpy(page_buf, comp_buf, PAGE_SIZE);
                }

                struct uffdio_copy uc;
                uc.src = (uint64_t)page_buf;
                uc.dst = fault_addr;
                uc.len = PAGE_SIZE;
                uc.mode = 0;
                uc.copy = 0;
                if (ioctl(g_uffd, UFFDIO_COPY, &uc) == 0) {
                    __sync_add_and_fetch(&g_total_faults, 1);
                }
            }
        }
    }
    return NULL;
}

static void evict_single_page(AetherRegion *r, size_t p, uint8_t *comp_buf) {
    const uint8_t *src = (const uint8_t *)r->ptr + (p * PAGE_SIZE);
    AetherPageMeta *m = &r->pages[p];

    const void *out_ptr = src;
    uint16_t out_len = PAGE_SIZE;
    uint8_t is_comp = 0;

    if (p_ZSTD_compress && p_ZSTD_isError) {
        size_t csz = p_ZSTD_compress(comp_buf, g_comp_bound, src, PAGE_SIZE, ZSTD_LEVEL);
        if (!p_ZSTD_isError(csz) && csz < PAGE_SIZE) {
            out_ptr = comp_buf;
            out_len = (uint16_t)csz;
            is_comp = 1;
        }
    }

    off_t write_off;
    if (m->valid && out_len <= m->comp_len) {
        write_off = (off_t)m->file_off;
        g_total_disk_bytes -= m->comp_len;
        g_total_disk_bytes += out_len;
    } else {
        write_off = g_next_disk_offset;
        g_next_disk_offset += out_len;
        if (m->valid) g_total_disk_bytes -= m->comp_len;
        g_total_disk_bytes += out_len;
    }

    if (write_all_pwrite(g_swap_fd, out_ptr, out_len, write_off) == 0) {
        m->file_off = (uint64_t)write_off;
        m->comp_len = out_len;
        m->compressed = is_comp;
        m->valid = 1;
    }
}

static size_t evict_all_regions(double *elapsed_ms) {
    double t0 = now_ms();
    size_t total_evicted_bytes = 0;

    uint8_t *comp_buf = (uint8_t *)syscall(
        SYS_mmap, NULL, g_comp_bound > PAGE_SIZE ? g_comp_bound : PAGE_SIZE * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (comp_buf == MAP_FAILED) return 0;

    pthread_mutex_lock(&g_lock);
    discover_large_anon_vmas_locked();

    for (int i = 0; i < MAX_REGIONS; i++) {
        AetherRegion *r = &g_regions[i];
        if (!r->in_use) continue;

        if (!r->evicted) {
            for (size_t p = 0; p < r->npages; p++) {
                evict_single_page(r, p, comp_buf);
            }
        } else {
            unsigned char *vec = (unsigned char *)syscall(
                SYS_mmap, NULL, r->npages, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (vec != MAP_FAILED) {
                if (mincore(r->ptr, r->len, vec) == 0) {
                    for (size_t p = 0; p < r->npages; p++) {
                        if (vec[p] & 1) {
                            evict_single_page(r, p, comp_buf);
                        }
                    }
                }
                syscall(SYS_munmap, vec, r->npages);
            }
        }

        if (!r->uffd_registered) {
            struct uffdio_register ur;
            memset(&ur, 0, sizeof(ur));
            ur.range.start = (uint64_t)r->ptr;
            ur.range.len = r->len;
            ur.mode = UFFDIO_REGISTER_MODE_MISSING;
            if (ioctl(g_uffd, UFFDIO_REGISTER, &ur) == 0) {
                r->uffd_registered = 1;
            }
        }

        if (r->uffd_registered) {
            if (madvise(r->ptr, r->len, MADV_DONTNEED) == 0) {
                r->evicted = 1;
                total_evicted_bytes += r->len;
            }
        }
    }
    pthread_mutex_unlock(&g_lock);
    syscall(SYS_munmap, comp_buf, g_comp_bound > PAGE_SIZE ? g_comp_bound : PAGE_SIZE * 2);

    *elapsed_ms = now_ms() - t0;
    return total_evicted_bytes;
}

static void *control_server_loop(void *arg) {
    (void)arg;
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) return NULL;

    unlink(g_sock_path);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_sock_path);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(srv, 8) != 0) {
        close(srv);
        return NULL;
    }

    while (1) {
        int cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            if (errno == EINTR) continue;
            break;
        }
        char buf[64] = {0};
        ssize_t n = read(cli, buf, sizeof(buf) - 1);
        if (n > 0) {
            if (strncmp(buf, "EVICT", 5) == 0) {
                double ms = 0.0;
                size_t bytes = evict_all_regions(&ms);
                double orig_mb = (double)bytes / (1024.0 * 1024.0);
                double zst_mb = (double)g_total_disk_bytes / (1024.0 * 1024.0);
                double ratio = zst_mb > 0.01 ? (orig_mb / zst_mb) : 1.0;
                char resp[160];
                int len = snprintf(resp, sizeof(resp),
                                   "OK %.1f MB -> %.1f MB Zstd (%.1fx) %.1f ms faults=%llu\n",
                                   orig_mb, zst_mb, ratio, ms,
                                   (unsigned long long)g_total_faults);
                ssize_t unused = write(cli, resp, (size_t)len);
                (void)unused;
            } else if (strncmp(buf, "STATS", 5) == 0) {
                char resp[128];
                int len = snprintf(resp, sizeof(resp), "FAULTS %llu ZSTD_MB %.1f\n",
                                   (unsigned long long)g_total_faults,
                                   (double)g_total_disk_bytes / (1024.0 * 1024.0));
                ssize_t unused = write(cli, resp, (size_t)len);
                (void)unused;
            }
        }
        close(cli);
    }
    return NULL;
}

__attribute__((constructor))
static void aether_mem_init(void) {
    pid_t pid = getpid();
    snprintf(g_sock_path, sizeof(g_sock_path), "/tmp/aether_ctl_%d.sock", pid);
    snprintf(g_swap_path, sizeof(g_swap_path), "/tmp/aether_swap_%d.zst", pid);

    g_zstd_lib = dlopen("libzstd.so.1", RTLD_LAZY);
    if (g_zstd_lib) {
        p_ZSTD_compress = (size_t (*)(void *, size_t, const void *, size_t, int))dlsym(g_zstd_lib, "ZSTD_compress");
        p_ZSTD_decompress = (size_t (*)(void *, size_t, const void *, size_t))dlsym(g_zstd_lib, "ZSTD_decompress");
        p_ZSTD_compressBound = (size_t (*)(size_t))dlsym(g_zstd_lib, "ZSTD_compressBound");
        p_ZSTD_isError = (unsigned (*)(size_t))dlsym(g_zstd_lib, "ZSTD_isError");
        if (p_ZSTD_compressBound) {
            g_comp_bound = (p_ZSTD_compressBound(PAGE_SIZE) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        }
    }

    g_uffd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (g_uffd < 0) return;

    struct uffdio_api api = { .api = UFFD_API, .features = 0 };
    if (ioctl(g_uffd, UFFDIO_API, &api) != 0) {
        close(g_uffd);
        g_uffd = -1;
        return;
    }

    g_swap_fd = open(g_swap_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (g_swap_fd < 0) {
        close(g_uffd);
        g_uffd = -1;
        return;
    }

    pthread_t t_uffd, t_ctl;
    pthread_create(&t_uffd, NULL, uffd_fault_loop, NULL);
    pthread_detach(t_uffd);
    pthread_create(&t_ctl, NULL, control_server_loop, NULL);
    pthread_detach(t_ctl);
}

__attribute__((destructor))
static void aether_mem_fini(void) {
    unlink(g_sock_path);
    unlink(g_swap_path);
}
