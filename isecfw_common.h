/*
 * Structure between to communicate between kernel and userspace
 */

#ifndef ISECFW_COMMON_H
#define ISECFW_COMMON_H

#include <linux/types.h>

#define ISECFW_SET_RULE 0
#define ISECFW_DEL_RULE 1

#define RULE_ADD     1
#define RULE_DELETE  2
#define RULE_FLUSH   3

#define RULE_INGRESS 1
#define RULE_EGRESS 2

#define NET_RULE_ALLOW  0x01
#define NET_RULE_DROP   0x02
#define NET_RULE_PASS   0x04


struct isecfw_rule_arg {
    __u8    direction;  // default:all, 1:IN, 2:OUT
    __u8    proto;      // default:all, 1:IN, 2:OUT
    __u32   srcip;
    __u32   dstip;
    __u16   srcport;
    __u16   dstport;
    __u8    action;
};

#ifdef ISECFW_KERNELSPACE
struct isecfw_rule {
    __u8    direction;  // default:all, 1:IN, 2:OUT
    __u8    proto;      // default:all, 1:IN, 2:OUT
    __u32   srcip;
    __u32   dstip;
    __u16   srcport;
    __u16   dstport;
    __u8    action;
    __u8    index;
    __u16   hits;
    struct list_head list;
};
#endif

#endif
