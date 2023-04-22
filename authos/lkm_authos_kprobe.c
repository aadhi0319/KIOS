#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aadhithya Kannan");
MODULE_DESCRIPTION("AuthOS Kernel Probe");
MODULE_VERSION("0.0.1");

#define MAX_FILEPATH_SIZE 4096

char* filepath;

static int __kprobes sys_openat_pre(struct kprobe* kp, struct pt_regs* regs) {
  char __user *pathname = (char*)regs->si;

  if (filepath == NULL) {
	printk(KERN_ERR "lkm_authos: filepath is NULL\n");
	return 0;
  }

  if (pathname == NULL) {
	  printk(KERN_ERR "lkm_authos: pathname is NULL\n");
	  return 0;
  }

  if (strncpy_from_user(filepath, pathname, MAX_FILEPATH_SIZE) < 0) {
    printk(KERN_INFO "lkm_authos: error reading filepath\n");
  }

  if (strcmp(filepath, "bob.txt") == 0) {
	printk(KERN_INFO "this was triggered.");
  }

  printk(KERN_INFO "lkm_authos: [openat]: %s\n", filepath);
  return 0;
}

struct kprobe sys_openat_kp = {
  .symbol_name = "do_sys_openat2",
  .pre_handler = sys_openat_pre,
};

static int __init lkm_authos_init(void) {
  printk(KERN_INFO "lkm_authos: start initialization\n");

  filepath = kmalloc(sizeof(char)*MAX_FILEPATH_SIZE, GFP_KERNEL);
  if (filepath == NULL) {
	  printk(KERN_ERR "lkm_authos: failed to allocate memory for filepath\n");
  }

  if (register_kprobe(&sys_openat_kp) < 0) {
          printk(KERN_ERR "lkm_authos: failed to hook sys_openat\n");
  }
  return 0;
}

static void __exit lkm_authos_exit(void) {
  unregister_kprobe(&sys_openat_kp);
  printk(KERN_INFO "lkm_authos: module exiting\n");
}

module_init(lkm_authos_init);
module_exit(lkm_authos_exit);
