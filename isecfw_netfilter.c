#include "isecfw_netfilter.h"

static struct nf_hook_ops isecfw_nfho_in;
static struct nf_hook_ops isecfw_nfho_out;

unsigned int netflt_parse_packet(struct sk_buff *skb, __u8 direction) {

    struct packet_info packet;
    struct iphdr *ip;
    __u8 action;

    memset(&packet, 0, sizeof(struct packet_info));

    ip = (struct iphdr *) skb_network_header(skb);
    packet.srcip = ip->saddr;
    packet.dstip = ip->daddr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr * tcp;
        packet.proto = IPPROTO_TCP;
        tcp = (struct tcphdr *) ((char *)ip + (ip->ihl * 4));
        packet.srcport = ntohs(tcp->source);
        packet.dstport = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        packet.proto = IPPROTO_UDP;
        udp = (struct udphdr *) ((char *)ip + (ip->ihl * 4));
        packet.srcport = ntohs(udp->source);
        packet.dstport = ntohs(udp->dest);
    } else if (ip->protocol == IPPROTO_ICMP) {
        packet.proto = IPPROTO_ICMP;
        //TODO
    } else
        packet.proto = ip->protocol;

    action = packet_rule_match(&packet, direction);
    switch(action) {
        case NET_RULE_DROP:
            return NF_DROP;
        case NET_RULE_PASS:
            return NF_STOP;
	case NET_RULE_ALLOW:
            return NF_ACCEPT;
        default:
	    printk(KERN_INFO "packet accept %x\n", packet.srcip);
            return NF_ACCEPT;
    }
    return NF_ACCEPT;
    
}
// Function called by the hook ingress
unsigned int netflt_hookfn_in(unsigned int num, struct sk_buff *skb,
                            const struct net_device *in,
                            const struct net_device *out, 
                            int (*okfn)(struct sk_buff *)) {

    return netflt_parse_packet(skb, RULE_INGRESS);
}

// Function called by the hook egress
unsigned int netflt_hookfn_out(unsigned int num, struct sk_buff *skb, 
                            const struct net_device *in,
                            const struct net_device *out, 
                            int (*okfn)(struct sk_buff *)) {

    return netflt_parse_packet(skb, RULE_EGRESS);
}

// Called by the init module
int isecfw_netfilter_init(void) {

    isecfw_nfho_in.hook = netflt_hookfn_in;
    isecfw_nfho_in.hooknum = NF_INET_PRE_ROUTING;  // First stage to hook
    isecfw_nfho_in.pf = PF_INET;                   // IPv4 Protocol hook                   
    isecfw_nfho_in.priority = NF_IP_PRI_FIRST;     // Hook to come first priority
    nf_register_hook(&isecfw_nfho_in);
    
    isecfw_nfho_out.hook = netflt_hookfn_out;
    isecfw_nfho_out.hooknum = NF_INET_POST_ROUTING;  // First stage to hook
    isecfw_nfho_out.pf = PF_INET;                   // IPv4 Protocol hook                   
    isecfw_nfho_out.priority = NF_IP_PRI_FIRST;     // Hook to come first priority
    nf_register_hook(&isecfw_nfho_out);

    return 0;
}

// Called by the cleanup module
void isecfw_netfilter_exit(void) {

    nf_unregister_hook(&isecfw_nfho_in);
    nf_unregister_hook(&isecfw_nfho_out);
    rule_process(NULL, RULE_FLUSH);
}
