#include "isecfw_dev.h"

static int isecfw_dev_open(struct inode *i, struct file *f) {

    printk(KERN_INFO "Driver open \n");
    return 0;
}
static int isecfw_dev_close(struct inode *i, struct file *f) {

    printk(KERN_INFO "Driver close\n");
    return 0;
}
static ssize_t isecfw_dev_read(struct file *f, 
                            char __user *buf,
                            size_t len, loff_t *off) {

    printk(KERN_INFO "Driver read\n");
    return 0;
}
static ssize_t isecfw_dev_write(struct file *f,
                            const char __user *buf,
                            size_t len, loff_t *off) {
                            
    printk(KERN_INFO "Driver write\n");
    return len;
}
static long isecfw_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {

    struct isecfw_rule_arg rule;

    switch(cmd) {
    
        case ISECFW_SET_RULE:
            printk(KERN_INFO "Received option set rule\n");
            if (copy_from_user(&rule, (struct isecfw_rule_arg *)arg,
				sizeof(struct isecfw_rule_arg))) 
            {
                return -EACCES;
            }
            printk(KERN_INFO "srcip %x dstip %x proto %d action %d",
			rule.srcip, rule.dstip, rule.proto, rule.action);
            rule_process(&rule, RULE_ADD);
            break;
        case ISECFW_DEL_RULE:
            printk(KERN_INFO "Received option del rule\n");
            if (copy_from_user(&rule, (struct isecfw_rule_arg *)arg, sizeof(struct isecfw_rule_arg))) 
            {
                return -EACCES;
            }
            rule_process(&rule, RULE_DELETE);
            break;
        default:
            return -EINVAL;
    }

    return 0;
}
static struct file_operations isecfw_dev_fops = {

    .owner = THIS_MODULE,
    .open  = isecfw_dev_open,
    .release = isecfw_dev_close,
    .read = isecfw_dev_read,
    .write = isecfw_dev_write,
    .unlocked_ioctl = isecfw_dev_ioctl,
};
int isecfw_dev_init(void) {

    int ret;

    if ((ret = alloc_chrdev_region(&isecfw_dev, 0, 1, "isecfw_dev")) < 0) {
        return -1;
    }
    printk(KERN_INFO "<Major, Minor>: <%d, %d>\n", MAJOR(isecfw_dev), MINOR(isecfw_dev));

    if ((isecfw_cl = class_create(THIS_MODULE, "chardrv")) == NULL) {
        unregister_chrdev_region(isecfw_dev, 1);
        printk(KERN_INFO "class_create failed\n");
        return -1;
    }
    if (device_create(isecfw_cl, NULL, isecfw_dev, NULL, "isecfw_dev") == NULL) {
        class_destroy(isecfw_cl);
        unregister_chrdev_region(isecfw_dev, 1);
        printk(KERN_INFO "device_create failed\n");
        return -1;
    }
    cdev_init(&isecfw_cdev, &isecfw_dev_fops);

    if (cdev_add(&isecfw_cdev, isecfw_dev, 1) == -1) {
        printk(KERN_INFO "cdev_add failed \n");
        unregister_chrdev_region(isecfw_dev, 1);
        device_destroy(isecfw_cl, isecfw_dev);
        class_destroy(isecfw_cl);
        return -1;
    }
    return 0;
}

void isecfw_dev_exit(void) {

    cdev_del(&isecfw_cdev);
    device_destroy(isecfw_cl, isecfw_dev);
    class_destroy(isecfw_cl);
    unregister_chrdev_region(isecfw_dev, 3);
    printk(KERN_INFO "isecfw_dev unregister\n");
}
