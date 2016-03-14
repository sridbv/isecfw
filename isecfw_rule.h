#ifndef ISECFW_RULE_H
#define ISECFW_RULE

#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include "isecfw_common.h"
#include "isecfw_netfilter.h"

struct packet_info;

void rule_process(struct isecfw_rule_arg *rule, __u8 action);
unsigned int packet_rule_match(struct packet_info *packet, __u8 direction);
void rule_show(struct seq_file *m);

#endif
