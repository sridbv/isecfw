#ifndef ISECFW_DEV_H
#define ISECFW_DEV_H
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>

#include "isecfw.h"
#include "isecfw_rule.h"

static dev_t isecfw_dev;            // Device structure which holds major and minor number
static struct cdev isecfw_cdev;   // Character device structure
static struct class *isecfw_cl;     // Device class variable
#endif
