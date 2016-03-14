#include <linux/module.h>   // for all modules
#include <linux/init.h>     // for entry/exit macros
#include <linux/kernel.h>   // for printk macros
#include <linux/sched.h>    // forstruct task)struct
#include <linux/proc_fs.h>  // for proc file system
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/seq_file.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>

//MODULE_AUTH0R("Sridhar");
MODULE_LICENSE("Dual BSD/GPL");

#if 0
#define MAX_ISEC_RULE_LENGTH PAGE_SIZE
static struct proc_dir_entry *proc_entry;

static char *isec_rule;
static int isec_index;
static int isec_next_rule;
#endif
extern int isecfw_proc_init(void);
extern void isecfw_proc_exit(void);

extern int isecfw_netfilter_init(void);
extern int isecfw_netfilter_exit(void);

extern int isecfw_dev_init(void);
extern void isecfw_dev_exit(void);

#if 0
extern ssize_t isecfirewall_write(struct file *filp, const char __user *buff, 
                            unsigned long len, void *data);
extern ssize_t isecfirewall_read(char *page, char **start, off_t off, int count,
                            int *eof, void *data);
#endif
