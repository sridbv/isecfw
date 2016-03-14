#include "isecfw.h"
#include "isecfw_rule.h"

static int
isecfw_proc_show(struct seq_file *m, void *v) {
    
    seq_printf(m, "ISECFIREWALL RUlES LIST\n");
    seq_printf(m, "Index|Dir|Proto|SrcIP|DstIP|SrcPort|DstPort|Hits\n");
    rule_show(m);
    return 0;
}
static int
isecfw_proc_open(struct inode *inode, struct file *file) {
    
    return single_open(file, isecfw_proc_show, NULL);
}
static const struct file_operations isecfw_proc_fops = {
    
    .owner = THIS_MODULE,
    .open  = isecfw_proc_open,
    .read  = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
int isecfw_proc_init(void) {

    proc_create("isecfw_proc", 0, NULL, &isecfw_proc_fops);
    return 0;
}
void isecfw_proc_exit(void) {

    remove_proc_entry("isecfw_proc", NULL);
}

#if 0
static ssize_t isecfirewall_write(struct file *filp, const char __user *buff,
                            unsigned long len, void *data) {
    
    int space_avail = (MAX_ISEC_RULE_LENGTH - isec_index) + 1;

    if (len > space_avail) {
        printk(KERN_INFO "isecfirewall write is full\n");
        return -ENOSPC;
    }

    if (copy_from_user(&isec_rule[isec_index], buff, len)) {
        return -EFAULT;
    }

    isec_rule_index += len;
    isec_rule[isec_rule_index - 1] = 0;

    return len;
}

static ssize_t isecfirewall_read(char *page, char **start, off_t off, int count, int *eof, void *data) {
    
    ssize_t len;
    if (off > 0) {
        *eof = 1;
        return 0;
    }

    /*Wrap around */
    if (isec_next_rule >= isec_index) isec_next_rule = 0;

    len = sprintf(page, "%s\n", &isec_rule[isec_next_rule]);

    isec_next_rule += len;

    return len;
}
#endif
