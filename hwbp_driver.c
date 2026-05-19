#undef CONFIG_MODVERSIONS
#undef CONFIG_MODULE_SIG
#undef CONFIG_MODULE_SIG_FORCE
#undef CONFIG_MODVERSIONS
#undef CONFIG_MODULE_SIG
#undef CONFIG_MODULE_SIG_FORCE

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#define CMD_CHECK_DRIVER 0x400010
#define CMD_READ 0x400011
#define CMD_WRITE 0x400012
#define CMD_MODULE_BASE 0x400013
#define CMD_INST_PROCESS_HWBP 0x400014
#define CMD_UNINST_PROCESS_HWBP 0x400015
#define CMD_SUSPEND_PROCESS_HWBP 0x400016
#define CMD_RESUME_PROCESS_HWBP 0x400017
#define CMD_GET_HWBP_HIT_COUNT 0x400018
#define CMD_GET_HWBP_HIT_DETAIL 0x400019
#define CMD_SET_REGISTER_MODIFY 0x400021
#define CMD_CLEAR_REGISTER_MODIFY 0x400022

#define HW_BREAKPOINT_LEN_4 4
#define HW_BREAKPOINT_X 0

#define MAX_MODIFY_REGS 10
#define REG_TYPE_FLOAT 3

struct COPY_MEMORY {
    int pid;
    unsigned long addr;
    void __user *buffer;
    size_t size;
};

struct MODULE_BASE {
    int pid;
    char __user *name;
    unsigned long base;
};

struct DRIVER_CHECK {
    char name[64];
    int is_loaded;
};

struct PERF_REQUEST {
    int pid;
    unsigned long proc_virt_addr;
    unsigned short hwbp_len;
    unsigned short hwbp_type;
    size_t buf_size;
    unsigned long src_buf;
};

struct REG_MODIFY_CONFIG {
    int reg_index;
    unsigned char reg_type;
    union {
        unsigned int int32_val;
        unsigned long long int64_val;
        float float_val;
        double double_val;
    } value;
};

struct hwbp_ctx {
    struct perf_event * __percpu *pevent;
    unsigned long addr;
    int type;
    int len;
    int target_pid;
    unsigned long long hit_count;
    unsigned long long handle;
    struct list_head list;
};

static struct list_head hwbp_list;
static DEFINE_MUTEX(hwbp_lock);
static int major;
static struct class *hwbp_class;
static struct device *hwbp_device;
static struct cdev hwbp_cdev;
static unsigned long long next_handle = 1;
static char node_name[32];

static void gen_random_name(char *buf, int len)
{
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int i;
    unsigned char r;
    for (i = 0; i < len - 1; i++) {
        get_random_bytes(&r, 1);
        buf[i] = charset[r % 36];
    }
    buf[len - 1] = '\0';
}

static int read_process_mem(int pid, unsigned long addr, void __user *buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf;
    int ret = -EFAULT;
    
    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;
    
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    
    if (!task) { kfree(kbuf); return -ESRCH; }
    
    mm = get_task_mm(task);
    if (mm) {
        mmap_read_lock(mm);
        ret = access_remote_vm(mm, addr, kbuf, size, 0);
        mmap_read_unlock(mm);
        mmput(mm);
    }
    
    if (ret == size) {
        if (copy_to_user(buf, kbuf, size)) ret = -EFAULT;
        else ret = 0;
    }
    
    put_task_struct(task);
    kfree(kbuf);
    return ret;
}

static void hwbp_callback(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs)
{
    struct hwbp_ctx *ctx = bp->overflow_handler_context;
    if (ctx) ctx->hit_count++;
}

static int install_hwbp(struct hwbp_ctx *ctx)
{
    struct perf_event_attr attr = {0};
    struct perf_event * __percpu *pevent;
    int cpu;
    
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_addr = ctx->addr;
    attr.bp_len = ctx->len;
    attr.bp_type = ctx->type == HW_BREAKPOINT_X ? HW_BREAKPOINT_X : 0;
    attr.disabled = 1;
    
    pevent = alloc_percpu(typeof(*pevent));
    if (!pevent) return -ENOMEM;
    
    for_each_possible_cpu(cpu) {
        struct task_struct *task = NULL;
        if (ctx->target_pid > 0) {
            rcu_read_lock();
            task = find_task_by_vpid(ctx->target_pid);
            rcu_read_unlock();
        }
        struct perf_event *event = perf_event_create_kernel_counter(&attr, cpu, task, hwbp_callback, ctx);
        if (IS_ERR(event)) {
            int err = PTR_ERR(event);
            for_each_possible_cpu(cpu) {
                struct perf_event *e = *per_cpu_ptr(pevent, cpu);
                if (e) perf_event_release_kernel(e);
            }
            free_percpu(pevent);
            return err;
        }
        *per_cpu_ptr(pevent, cpu) = event;
    }
    ctx->pevent = pevent;
    return 0;
}

static void uninstall_hwbp(struct hwbp_ctx *ctx)
{
    int cpu;
    if (!ctx->pevent) return;
    for_each_possible_cpu(cpu) {
        struct perf_event *event = *per_cpu_ptr(ctx->pevent, cpu);
        if (event) perf_event_release_kernel(event);
    }
    free_percpu(ctx->pevent);
    ctx->pevent = NULL;
}

static long hwbp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    void __user *argp = (void __user *)arg;
    
    switch (cmd) {
        case CMD_CHECK_DRIVER: {
            struct DRIVER_CHECK dc;
            if (copy_from_user(&dc, argp, sizeof(dc))) return -EFAULT;
            dc.is_loaded = 1;
            if (copy_to_user(argp, &dc, sizeof(dc))) return -EFAULT;
            return 1;
        }
        case CMD_READ: {
            struct COPY_MEMORY cm;
            if (copy_from_user(&cm, argp, sizeof(cm))) return -EFAULT;
            return read_process_mem(cm.pid, cm.addr, cm.buffer, cm.size);
        }
        case CMD_INST_PROCESS_HWBP: {
            struct PERF_REQUEST req;
            struct hwbp_ctx *ctx;
            if (copy_from_user(&req, argp, sizeof(req))) return -EFAULT;
            ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
            if (!ctx) return -ENOMEM;
            ctx->addr = req.proc_virt_addr;
            ctx->len = req.hwbp_len;
            ctx->type = req.hwbp_type;
            ctx->target_pid = req.pid;
            ctx->handle = next_handle++;
            if (install_hwbp(ctx)) { kfree(ctx); return -EINVAL; }
            mutex_lock(&hwbp_lock);
            list_add_tail(&ctx->list, &hwbp_list);
            mutex_unlock(&hwbp_lock);
            if (copy_to_user((void __user *)req.src_buf, &ctx->handle, sizeof(ctx->handle))) return -EFAULT;
            return 1;
        }
        case CMD_UNINST_PROCESS_HWBP: {
            struct PERF_REQUEST req;
            struct hwbp_ctx *ctx, *tmp;
            if (copy_from_user(&req, argp, sizeof(req))) return -EFAULT;
            mutex_lock(&hwbp_lock);
            list_for_each_entry_safe(ctx, tmp, &hwbp_list, list) {
                if (ctx->handle == req.src_buf) {
                    list_del(&ctx->list);
                    uninstall_hwbp(ctx);
                    kfree(ctx);
                    mutex_unlock(&hwbp_lock);
                    return 1;
                }
            }
            mutex_unlock(&hwbp_lock);
            return 0;
        }
        default:
            return -ENOTTY;
    }
}

static int hwbp_open(struct inode *inode, struct file *file) { return 0; }
static int hwbp_release(struct inode *inode, struct file *file) { return 0; }

static struct file_operations hwbp_fops = {
    .owner = THIS_MODULE,
    .open = hwbp_open,
    .release = hwbp_release,
    .unlocked_ioctl = hwbp_ioctl,
};

static int __init hwbp_init(void)
{
    dev_t dev;
    int ret;
    INIT_LIST_HEAD(&hwbp_list);
    gen_random_name(node_name, sizeof(node_name));
    ret = alloc_chrdev_region(&dev, 0, 1, node_name);
    if (ret < 0) return ret;
    major = MAJOR(dev);
    cdev_init(&hwbp_cdev, &hwbp_fops);
    cdev_add(&hwbp_cdev, dev, 1);
    hwbp_class = class_create("hwbp");
    if (IS_ERR(hwbp_class)) { cdev_del(&hwbp_cdev); unregister_chrdev_region(dev, 1); return PTR_ERR(hwbp_class); }
    hwbp_device = device_create(hwbp_class, NULL, dev, NULL, "%s", node_name);
    if (IS_ERR(hwbp_device)) { class_destroy(hwbp_class); cdev_del(&hwbp_cdev); unregister_chrdev_region(dev, 1); return PTR_ERR(hwbp_device); }
    printk(KERN_INFO "hwbp: loaded, node=%s major=%d\n", node_name, major);
    return 0;
}

static void __exit hwbp_exit(void)
{
    dev_t dev = MKDEV(major, 0);
    struct hwbp_ctx *ctx, *tmp;
    mutex_lock(&hwbp_lock);
    list_for_each_entry_safe(ctx, tmp, &hwbp_list, list) {
        uninstall_hwbp(ctx);
        kfree(ctx);
    }
    mutex_unlock(&hwbp_lock);
    device_destroy(hwbp_class, dev);
    class_destroy(hwbp_class);
    cdev_del(&hwbp_cdev);
    unregister_chrdev_region(dev, 1);
}

module_init(hwbp_init);
module_exit(hwbp_exit);
MODULE_LICENSE("GPL");
