#include <linux/device.h>
#include <linux/hashtable.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/stringhash.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aadhithya Kannan");
MODULE_DESCRIPTION("AuthOS Kernel Probe");
MODULE_VERSION("0.0.1");

#define DEVICE_NAME "authos_policy"
#define DEVICE_CLASS "authos_class"
#define FD_CACHE_BUCKET_BITS 11
#define MAX_FILEPATH_SIZE 4096
#define PERM_READ 4
#define PERM_WRITE 2
#define PERM_EXEC 1
#define POLICY_TABLE_BUCKET_BITS 6
#define pr_fmt(fmt) "%s: [%s] " fmt, KBUILD_MODNAME, __func__

#define GEN_FD_KEY(fd) ((pid_nr(get_task_pid(current, PIDTYPE_PID)) << 10) | (fd & ((1 << 10) - 1)))

static char* policy_memory = NULL;

void** syscall_table = NULL;
asmlinkage long (*__sys_read) (struct pt_regs*);
asmlinkage long (*__sys_close) (struct pt_regs*);

char* kernel_filepath_buffer;

// character device implementation
static int major_number;
static struct class* device_class = NULL;
static struct device* policy_device = NULL;

// hash table implementation
struct fd_node {
  uint32_t key;
  uint8_t permissions;
  struct hlist_node fd_node_next;
};

DECLARE_HASHTABLE(fd_cache, FD_CACHE_BUCKET_BITS);

struct policy_node {
	char* filepath;
	uint8_t permissions;
	struct hlist_node policy_node_next;
};

DECLARE_HASHTABLE(policy_table, POLICY_TABLE_BUCKET_BITS);

// enable/disable page write protection
extern unsigned long __force_order;
static inline void write_cr0_bypass(unsigned long cr0) {
  asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

static inline void protect_memory(void) {
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0_bypass(cr0);
}

static inline void unprotect_memory(void) {
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0_bypass(cr0);
}

// string helper functions
static unsigned long hash_str(char* str) {
	unsigned long hash = init_name_hash(0x133713371337);
	while (*str) {
		hash = partial_name_hash(*str++, hash);
	}
	return end_name_hash(hash);
}

// use kprobes to lookup kernel kallsyms (not exported by default)
static unsigned long lookup_name(const char *name) {
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) {
		return 0;
	}
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}

// hook functions
asmlinkage static long lkm_authos_sys_close(struct pt_regs* regs) {
	const int fd = (int)regs->di;
	const int fd_key = GEN_FD_KEY(fd);
	struct fd_node* fd_node_cursor = NULL;
	struct fd_node* fd_node_match = NULL;
	
	// find node to delete
	hash_for_each_possible(fd_cache, fd_node_cursor, fd_node_next, fd_key) {
		if (fd_node_cursor->key == fd_key) {
			fd_node_match = fd_node_cursor;
			break;
		}
	}

	if (fd_node_match != NULL) {
		hash_del(&(fd_node_match->fd_node_next));
		kfree(fd_node_match);
	}
	
	return __sys_close(regs);
}

asmlinkage static long lkm_authos_sys_read(struct pt_regs* regs) {
  const int fd = (int)regs->di;
	const int fd_key = GEN_FD_KEY(fd);
	struct fd_node* fd_entry = NULL;
	struct fdtable* files_table = NULL;
	struct fd_node* fd_node_cursor = NULL;
	struct fd_node* fd_node_match = NULL;
	struct policy_node* policy_node_cursor = NULL;
	struct policy_node* policy_node_match = NULL;
	char* absolute_path = NULL;
	uint8_t permissions = 0;

	// search hash table for node first, if doesn't exist, then check permissions, make node, and add to hash table.
	hash_for_each_possible(fd_cache, fd_node_cursor, fd_node_next, fd_key) {
		if (fd_node_cursor->key == fd_key) {
			fd_node_match = fd_node_cursor;
			break;
		}
	}

	if (fd_node_match != NULL) {
		//pr_info("found fd_node: %d\n", fd_node_match->permissions);
		permissions = fd_node_match->permissions;
	} else {
		// get absolute filepath of fd
		files_table = files_fdtable(current->files);
		if (files_table == NULL || files_table->fd == NULL) {
			pr_err("file descriptor table is NULL\n");
			return -EFAULT;
		}
		if (fd < 0 || fd > files_table->max_fds) {
			pr_err("invalid file descriptor\n");
			return -EINVAL;
		}
		absolute_path = d_path(&(files_table->fd[fd]->f_path), kernel_filepath_buffer, MAX_FILEPATH_SIZE);
		// search policy_table for filepath
		hash_for_each_possible(policy_table, policy_node_cursor, policy_node_next, hash_str(absolute_path)) {
			//pr_info("path: %s %s\n", policy_node_cursor->filepath, absolute_path);
			if (strcmp(policy_node_cursor->filepath, absolute_path) == 0) {
				policy_node_match = policy_node_cursor;
				break;
			}
		}
		if (policy_node_match != NULL) {
			permissions = policy_node_match->permissions;
			//pr_info("basn: %s %d\n", absolute_path, permissions);
		} else {
			// no policy concerning this file, so default to DAC
			//pr_info("arns: %s\n", absolute_path);
			permissions = PERM_READ | PERM_WRITE | PERM_EXEC;
		}
		// update fd_cache with fd and permissions
		fd_entry = kmalloc(GFP_KERNEL, sizeof(struct fd_node));
		fd_entry->key = GEN_FD_KEY(fd);
		//pr_info("pid: %d, fd: %d, key: %d\n", pid_nr(get_task_pid(current, PIDTYPE_PID)), fd, fd_entry->key);
		fd_entry->permissions = permissions;
		hash_add(fd_cache, &(fd_entry->fd_node_next), fd_entry->key);
	}

	if ((permissions & PERM_READ) == 0) {
		return -EACCES;
	}

  return __sys_read(regs);
}

// charcter device setup
static int device_busy = 0;
static int device_open(struct inode *inode, struct file *file) {
	if (device_busy) {
		return -EBUSY;
	}

	device_busy = 1;
	try_module_get(THIS_MODULE);

	return 0;
}

static int device_release(struct inode *inode, struct file *file) {
	module_put(THIS_MODULE);

	device_busy = 0;

	return 0;
}

static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t * offset) {
	// does nothing now, but in the future, this should return the current loaded policy
	return -EACCES;
}

static ssize_t device_write(struct file* filp, const char __user* buf, size_t len, loff_t* off) {
	int idx;
	struct policy_node* policy_node_cursor;
	long copy_ret;
	int strtou8_ret;
	u8 strtou8_res;

	if (*off != 0) {
		pr_err("device write offset must be 0\n");
		return -EINVAL;
	}

	if (policy_memory != NULL) {
		kfree(policy_memory);
	}
	policy_memory = kmalloc(GFP_KERNEL, sizeof(char)*len + 1);
	policy_memory[len] = '\0';
	copy_ret = copy_from_user(policy_memory, buf, len);

	for (idx = 0; idx < len;) {
		policy_node_cursor = kmalloc(GFP_KERNEL, sizeof(struct policy_node));
		policy_node_cursor->filepath = policy_memory + idx;
		while (*(policy_memory + idx++)){};
		strtou8_ret = kstrtou8(policy_memory + idx, 10, &strtou8_res);
		if (strtou8_ret < 0) {
			pr_err("failed to convert string to u8\n");
			return -EINVAL;
		}
		policy_node_cursor->permissions = strtou8_res;
		while (*(policy_memory + idx++)){};
		hash_add(policy_table, &(policy_node_cursor->policy_node_next), hash_str(policy_node_cursor->filepath));
		//pr_info("added hash table entry: %s %d\n", policy_node_cursor->filepath, policy_node_cursor->permissions);
	}
	
	pr_info("policy updated\n");

	return len - copy_ret;
}

static struct file_operations fops = {
	.write = device_write,
	.open = device_open,
	.release = device_release
};

// initialize kernel module
static int __init lkm_authos_init(void) {
  unsigned long (*kallsyms_lookup_name)(const char *name);

  pr_info("module loaded\n");

  // locate kallsysms_lookup_name function
  kallsyms_lookup_name = (void*) lookup_name("kallsyms_lookup_name");
  if (!kallsyms_lookup_name) {
	  pr_err("failed to find kallsyms_lookup_name\n");
  }

  // locate system call table
  syscall_table = (void**) kallsyms_lookup_name("sys_call_table");
  if (!syscall_table) {
		pr_err("failed to locate syscall table\n");
		return 0;
  }

	// allocate memory for the filepath buffer
	kernel_filepath_buffer = kmalloc(GFP_KERNEL, sizeof(char)*MAX_FILEPATH_SIZE);

	// initialize hash tables
	hash_init(fd_cache);
	hash_init(policy_table);

	// create character device
	major_number = register_chrdev(0, DEVICE_NAME, &fops);
	if (major_number < 0) {
		pr_err("failed to register character device\n");
		return -EFAULT;
	}

	device_class = class_create(THIS_MODULE, DEVICE_CLASS);
	if (IS_ERR(device_class)) {
		pr_err("failed to create class\n");
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(device_class);
	}

	policy_device = device_create(device_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
	if (IS_ERR(policy_device)) {
		pr_err("failed to create device\n");
		class_destroy(device_class);
		unregister_chrdev(major_number, DEVICE_NAME);
		return PTR_ERR(policy_device);
	}

	// need to hook close syscall to remove hash table entry
	__sys_close = (void*)syscall_table[__NR_close];
	__sys_read = (void*)syscall_table[__NR_read];
	unprotect_memory();
	syscall_table[__NR_close] = (void*)lkm_authos_sys_close;
	syscall_table[__NR_read] = (void*)lkm_authos_sys_read;
	protect_memory();

  return 0;
}

// unload kernel module
static void __exit lkm_authos_exit(void) {
	uint32_t bkt_idx;
	struct fd_node* fd_node_cursor = NULL;
	struct policy_node* policy_node_cursor = NULL;

	// unhook syscalls
	unprotect_memory();
	syscall_table[__NR_close] = (void*)__sys_close;
	syscall_table[__NR_read] = (void*)__sys_read;
	protect_memory();

	// destroy character device
	device_destroy(device_class, MKDEV(major_number, 0));
	class_unregister(device_class);
	class_destroy(device_class);
	unregister_chrdev(major_number, DEVICE_NAME);

	// free fd_cache
	hash_for_each(fd_cache, bkt_idx, fd_node_cursor, fd_node_next) {
		//pr_info("deleting node: %d\n", fd_node_cursor->key);
		hash_del(&(fd_node_cursor->fd_node_next));
		kfree(fd_node_cursor);
	}
	// free policy_table
	hash_for_each(policy_table, bkt_idx, policy_node_cursor, policy_node_next) {
		//pr_info("deleting node: %s\n", policy_node_cursor->filepath);
		hash_del(&(policy_node_cursor->policy_node_next));
		kfree(policy_node_cursor);
	}

	// free filepath buffer
	kfree(kernel_filepath_buffer);

	// free policy
	if (policy_memory != NULL) {
		kfree(policy_memory);
	}
	
	pr_info("module unloaded\n");
}

module_init(lkm_authos_init);
module_exit(lkm_authos_exit);
