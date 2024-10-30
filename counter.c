//go:build ignore
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/bpf.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, 1);
    __type(value, __u8[64]);
} payload_map SEC(".maps");

int key = 0;


SEC("xdp")
int read_payload(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int frame_length = data_end - data;
    if (frame_length > 64) frame_length = 64;
    __u8 frame[64];
    int len = 0;

    if (key > 9) {
        bpf_printk("Megvan a 100 elem.");
        return XDP_DROP;
    } 

    if (data + 64 <= data_end) {
        for (int i = 0; i < 64; i++)
        {
            frame[i] = *((__u8 *)data + i);
            bpf_printk("%02x", frame[i]);
        }
        bpf_map_update_elem(&payload_map, &key, &frame, BPF_ANY);
        key++;
    }
    bpf_printk("-------------------------------------------------------------");

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


/*


bpf_printk("ctx: %d",ctx);
    bpf_printk("ctx.data: %d",ctx->data);
    bpf_printk("ctx.data_end: %d",ctx->data_end);
    bpf_printk("ctx.data_meta: %d",ctx->data_meta);
    bpf_printk("ctx: %d",&ctx);
    bpf_printk("ctx.data: %d",&ctx->data);
    bpf_printk("ctx.data_end: %d",&ctx->data_end);
    bpf_printk("ctx.data_meta: %d",&ctx->data_meta);
    //bpf_printk("ctx.egress_ifindex: %d",ctx->egress_ifindex);
    //bpf_printk("ctx.ingress_ifindex: %d",ctx->ingress_ifindex);
    //bpf_printk("ctx.rx_queue_index: %d",ctx->rx_queue_index);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    bpf_printk("%d", data);
    bpf_printk("%d", data_end);

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    bpf_printk("ethsource: %d", eth->h_source);
    bpf_printk("ethdest: %d", eth->h_dest);

    // IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    bpf_printk("ip: %d", ip);
    bpf_printk("ipaddrs: %d", ip->addrs);
    bpf_printk("ipaddrssaddr: %d", ip->addrs.saddr);
    bpf_printk("ipaddrsdaddr: %d", ip->addrs.daddr);
    bpf_printk("ipcheck: %d", ip->check);
    bpf_printk("ipdaddr: %d", ip->daddr);
    bpf_printk("ipfrag_off: %d", ip->frag_off);
    bpf_printk("ipid: %d", ip->id);
    bpf_printk("ipihl: %d", ip->ihl);
    bpf_printk("ipprotocol: %d", ip->protocol);
    bpf_printk("ipsaddr: %d", ip->saddr);
    bpf_printk("iptos: %d", ip->tos);
    bpf_printk("iptot_len: %d", ip->tot_len);
    bpf_printk("ipttl: %d", ip->ttl);
    bpf_printk("ipversion: %d", ip->version);
    bpf_trace_printk("payload= %x %x %x\n", *data, *(data+1), *(data+2));


    // Csak IPv4 csomagokat kezelünk
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    // UDP csomagokat szűrünk
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;


    //bpf_printk("%d %d %d %d %d %d %d %d", ctx->data & 0xFF, (ctx->data >> 4) & 0xFF, (ctx->data >> 8) & 0xFF, (ctx->data >> 12) & 0xFF,
     //                                       (ctx->data >> 16) & 0xFF, (ctx->data >> 20) & 0xFF, (ctx->data >> 24) & 0xFF, (ctx->data >> 28) & 0xFF);



    // Írjuk ki a forrás és cél IP címeket
    //bpf_printk("%d.%d.%d.%d to %d.%d.%d.%d\n",
    //    ip->saddr & 0xFF, (ip->saddr >> 8) & 0xFF,
    //    (ip->saddr >> 16) & 0xFF, (ip->saddr >> 24) & 0xFF,
    //    ip->daddr & 0xFF, (ip->daddr >> 8) & 0xFF,
    //    (ip->daddr >> 16) & 0xFF, (ip->daddr >> 24) & 0xFF);


    __u8 *stored_frame = bpf_map_lookup_elem(&payload_map, &key);
    if (stored_frame) {
        //bpf_printk("Stored frame:");
        for (int i = 0; i < 64; i++) {
            //bpf_printk("%02x", stored_frame[i]); // Kiírjuk a lekérdezett adatokat
        }
    } else {
        bpf_printk("Failed to retrieve data for key: %u", key);
    }
    //bpf_printk("-------------------------------------------------------------");

*/