#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct aether_cfg {
    __u32 target_port;
    __u32 target_pid;
    __u32 is_sleeping;
    __u32 reserved;
    __u64 last_pkt_ns;
    __u64 wake_count;
};

struct aether_wake_event {
    __u32 pid;
    __u32 port;
    __u32 pkt_len;
    __u32 reserved;
    __u64 pkt_ts_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct aether_cfg);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} wake_ringbuf SEC(".maps");

SEC("cgroup_skb/ingress")
int aether_ingress_wake(struct __sk_buff *skb)
{
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return 1;

    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0)
        return 1;

    if (iph.protocol != IPPROTO_TCP || iph.ihl < 5)
        return 1;

    __u32 ip_hdr_len = (__u32)iph.ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60)
        return 1;

    struct tcphdr tcph;
    if (bpf_skb_load_bytes(skb, ip_hdr_len, &tcph, sizeof(tcph)) < 0)
        return 1;

    __u32 key = 0;
    struct aether_cfg *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg)
        return 1;

    if (bpf_ntohs(tcph.dest) != cfg->target_port)
        return 1;

    __u32 tcp_hdr_len = (__u32)tcph.doff * 4;
    __u32 payload_off = ip_hdr_len + tcp_hdr_len;
    int has_traffic = tcph.syn || tcph.psh || (skb->len > payload_off);
    if (!has_traffic)
        return 1;

    __u64 now = bpf_ktime_get_ns();
    cfg->last_pkt_ns = now;

    if (cfg->is_sleeping == 1) {
        struct aether_wake_event *ev = bpf_ringbuf_reserve(&wake_ringbuf, sizeof(*ev), 0);
        if (ev) {
            ev->pid = cfg->target_pid;
            ev->port = cfg->target_port;
            ev->pkt_len = skb->len;
            ev->reserved = 0;
            ev->pkt_ts_ns = now;
            bpf_ringbuf_submit(ev, 0);
        }
        cfg->is_sleeping = 0;
        __sync_fetch_and_add(&cfg->wake_count, 1);
    }

    return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
