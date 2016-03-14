#include "isecfw.h"

//Firewall kernel module

int isecfw_init(void) {

    printk(KERN_INFO "init module isec_fw called\n");

    // Create /proc/isecfw_proc

    isecfw_proc_init();
    isecfw_netfilter_init();
    isecfw_dev_init();
    return 0;
}
void isecfw_cleanup(void) {
    printk(KERN_INFO "isecfw cleanup modeule\n");
    isecfw_dev_exit();
    isecfw_proc_exit();
    isecfw_netfilter_exit();
}

//Declare entry and exit functions
module_init(isecfw_init);
module_exit(isecfw_cleanup);
