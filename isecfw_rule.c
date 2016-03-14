#define ISECFW_KERNELSPACE
#include "isecfw_rule.h"

static LIST_HEAD(isecfw_rule_list);
static int index;

static void ip_to_str(unsigned int ip, char *ipstr) {

    unsigned char iparray[4];

    memset(iparray, 0, 4);

    iparray[0] = (iparray[0] | ip);
    iparray[1] = (iparray[1] | (ip >> 8));
    iparray[2] = (iparray[2] | (ip >> 16));
    iparray[3] = (iparray[3] | (ip >> 24));

    sprintf(ipstr, "%u.%u.%u.%u", iparray[0], iparray[1], 
               iparray[2], iparray[3]);
    return;
}
static void proto_to_str(__u16 proto, char *protostr) {
    
    switch(proto) {
        case IPPROTO_TCP:
            strcpy(protostr, "tcp");
            break;
        case IPPROTO_UDP:
            strcpy(protostr, "udp");
            break;
        case IPPROTO_ICMP:
            strcpy(protostr, "icmp");
            break;
        default:
            strcpy(protostr, "Any");
            break;
    }
}
static int rule_match_entry(struct isecfw_rule *rule1, struct isecfw_rule *rule2) {

    int match = 0;
    
    if ((rule1->direction == rule2->direction) &&
        (rule1->proto == rule2->proto) &&
        (rule1->srcip == rule2->srcip) &&
        (rule1->dstip == rule2->dstip) &&
        (rule1->srcport == rule2->srcport) &&
        (rule1->dstport == rule2->dstport))
            match = 1;

    return match;
}
static int rule_match(struct isecfw_rule_arg *arg) {
    
    struct isecfw_rule *rule, *tmp;
    struct isecfw_rule *arg_rule = NULL;

    arg_rule = kmalloc(sizeof(struct isecfw_rule), GFP_KERNEL);
    memcpy(arg_rule, arg, sizeof(struct isecfw_rule_arg));

    list_for_each_entry_safe(rule, tmp, &isecfw_rule_list, list)
        if (rule_match_entry(arg_rule, rule)) {
            return rule->action;
        }
    kfree(arg_rule);
    return 0;
} 
static void rule_add(struct isecfw_rule_arg *recv_rule) {
    
    struct isecfw_rule *new_rule = NULL;
    struct isecfw_rule *rule = NULL;

    if (rule_match(recv_rule)) {
        //Nothing to do
        return;
    }

    new_rule = kmalloc(sizeof(struct isecfw_rule), GFP_KERNEL);
    if (!new_rule)
        return;

    memcpy(new_rule, recv_rule, sizeof(struct isecfw_rule_arg));
    new_rule->index = index;
    index += 1;

    list_for_each_entry(rule, &isecfw_rule_list, list) {
        if(rule->index > new_rule->index)
            break;
    }
    printk(KERN_INFO "srcip %x dstip %x\n", new_rule->srcip, new_rule->dstip);
    if (rule)
        list_add_tail(&new_rule->list, &rule->list);
    else
        list_add_tail(&new_rule->list, &isecfw_rule_list);

}

static void rule_free(struct isecfw_rule *rule) {
    kfree(rule);
}

static void rule_delete(struct isecfw_rule_arg *del_arg) {

    struct isecfw_rule *rule, *tmp;
    struct isecfw_rule *del_rule = NULL;

    del_rule = kmalloc(sizeof(struct isecfw_rule), GFP_KERNEL);
    memcpy(del_rule, del_arg, sizeof(struct isecfw_rule_arg));

    list_for_each_entry_safe(rule, tmp, &isecfw_rule_list, list)
        if (rule_match_entry(del_rule, rule)) {
            list_del(&rule->list);
            rule_free(rule);
            kfree(del_rule);
            return;
        }
    kfree(del_rule);
    return;
}

static void rules_delete(void) {
    struct isecfw_rule *rule, *tmp;

    list_for_each_entry_safe(rule, tmp, &isecfw_rule_list, list) {
        list_del(&rule->list);
        rule_free(rule);
    }
}

void rule_process(struct isecfw_rule_arg *rule, __u8 action) {
    
    switch (action) {
        case RULE_ADD:
            rule_add(rule);
            break;
        case RULE_DELETE:
            rule_delete(rule);
            break;
        case RULE_FLUSH:
            rules_delete();
            break;
        default:
            printk(KERN_INFO "Unknow rule process action\n");
            break;
    }
    return;
}
void rule_show(struct seq_file *m) {

    struct isecfw_rule *rule;
    list_for_each_entry(rule, &isecfw_rule_list, list) {
        char srcipstr[20];
        char dstipstr[20];
        char protostr[10];
        ip_to_str(rule->srcip, srcipstr);
        ip_to_str(rule->dstip, dstipstr);
        proto_to_str(rule->proto, protostr);
        seq_printf(m, "%d|%s|%s|%s|%s|%s|%d|%d|%d\n",
                    rule->index, 
                    (rule->direction == 1) ? "In" : "Out", 
                    (rule->action == 1) ? "Allow" : "Deny",
                    protostr, srcipstr, dstipstr,
                    rule->srcport, rule->dstport, rule->hits);	
    }
    return;
}
unsigned int packet_rule_match(struct packet_info *packet, __u8 direction) {

    struct isecfw_rule *rule;

    list_for_each_entry(rule, &isecfw_rule_list, list) {
	
        if (direction != rule->direction)
		continue;
	if (rule->proto && rule->proto != packet->proto)
		{printk(KERN_INFO "proto failed\n");continue;}
	if (rule->srcip && rule->srcip != packet->srcip)
		{printk(KERN_INFO "srcip failed\n");continue;}
	if (rule->dstip && rule->dstip != packet->dstip)
		{printk(KERN_INFO "dstip failed\n");continue;}
	if (rule->srcport && rule->srcport != packet->srcport)
		{printk(KERN_INFO "srcport failed\n");continue;}
	if (rule->dstport && rule->dstport != packet->dstport)
		{printk(KERN_INFO "dstport failed\n");continue;}
	
        rule->hits += 1;
	return rule->action;
    }
    return 0;
}
