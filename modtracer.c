#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sort.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MatheuZSec");
MODULE_DESCRIPTION("Detect hidden LKM Rootkits and then make visible again.");
MODULE_VERSION("1.0");

struct module_region {
    unsigned long start;
    unsigned long end;
};

static struct module_region *module_regions = NULL;
static int module_count = 0;

static int cmp_func(const void *a, const void *b) {
    struct module_region *region_a = (struct module_region *)a;
    struct module_region *region_b = (struct module_region *)b;
    return (region_a->start > region_b->start) - (region_a->start < region_b->start);
}

static int gather_module_regions(void) {
    struct module *mod;
    struct module_region *new_regions;
    int i = 0;

    list_for_each_entry(mod, THIS_MODULE->list.prev, list) {
        new_regions = krealloc(module_regions, (module_count + 1) * sizeof(*module_regions), GFP_KERNEL);
        if (!new_regions) {
            pr_err("Memory allocation failed for module regions\n");
            return -ENOMEM;
        }

        module_regions = new_regions;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
        module_regions[module_count].start = (unsigned long)mod->mem->base;
        module_regions[module_count].end = (unsigned long)mod->mem->base + mod->mem->size;
#else
        module_regions[module_count].start = (unsigned long)mod->core_layout.base;
        module_regions[module_count].end = (unsigned long)mod->core_layout.base + mod->core_layout.size;
#endif

        module_count++;
    }

    // Sort the regions by their start address
    sort(module_regions, module_count, sizeof(struct module_region), cmp_func, NULL);

    return 0;
}

static void modtracer_memory_gaps(void) {
    unsigned long addr, value;
    struct module *mod;
    size_t ptr_size = sizeof(void *);
    int i;

    for (i = 0; i < module_count - 1; i++) {
        for (addr = module_regions[i].end; addr < module_regions[i + 1].start; addr += ptr_size) {
            if (
                copy_from_kernel_nofault(&value, (void *)addr, sizeof(value)) == 0 &&
                value == (unsigned long)LIST_POISON1 &&
                copy_from_kernel_nofault(&value, (void *)(addr + ptr_size), sizeof(value)) == 0 &&
                value == (unsigned long)LIST_POISON2
            ) {
                mod = (struct module *)(addr - ptr_size);
                pr_info("Hidden LKM Rootkit detected: %s! Check lsmod and then remove it", mod->name);
                list_add(&mod->list, THIS_MODULE->list.prev);
                break;
            }
        }
    }
}

static int __init modtracer_init(void) {
    pr_info("ModTracer Loaded...\n");
    if (gather_module_regions() < 0) return -ENOMEM;
    modtracer_memory_gaps();
    pr_info("ModTracer completed!\n");
    return 0;
}

static void __exit modtracer_exit(void) {
    kfree(module_regions);
    pr_info("ModTracer Unloaded!\n");
}

module_init(modtracer_init);
module_exit(modtracer_exit);
