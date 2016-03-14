#ifndef ISECFW_NETFILTER_H
#define ISECFW_NETFILTER_H

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "isecfw_rule.h"

#define INBOUND 1
#define OUTBOUND 2

struct packet_info {
    __u8    proto;      // default:all, 1:IN, 2:OUT
    __u32   srcip;
    __u32   dstip;
    __u16   srcport;
    __u16   dstport;
};

#endif
