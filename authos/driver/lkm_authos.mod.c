#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x8798f688, "pv_ops" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x9a994cf7, "current_task" },
	{ 0x32ec4737, "get_task_pid" },
	{ 0x37a0cba, "kfree" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x105dd2a8, "module_put" },
	{ 0x6bce40fa, "try_module_get" },
	{ 0x24c7d1b8, "d_path" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xf301d0c, "kmalloc_caches" },
	{ 0x35789eee, "kmem_cache_alloc_trace" },
	{ 0x92997ed8, "_printk" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x6a6e05bf, "kstrtou8" },
	{ 0x7682ba4e, "__copy_overflow" },
	{ 0x670ecece, "__x86_indirect_thunk_rbx" },
	{ 0xc1352057, "__register_chrdev" },
	{ 0xaee657ee, "__class_create" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xf3e489db, "device_create" },
	{ 0x645620c0, "class_destroy" },
	{ 0xbdee1658, "device_destroy" },
	{ 0x7377b2e, "class_unregister" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x541a6db8, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "E90002DD802DCD8E6CC0D93");
