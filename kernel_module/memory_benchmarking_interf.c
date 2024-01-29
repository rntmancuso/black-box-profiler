#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "memory_benchmarking.h"

static struct dentry *membench_dir;
static struct experiment_info cur_exp;

static char * map_type2string [] = {"MAP_CACHE", "MAP_NCACHE"}; 
static char * access_type2string [] = {
	"ACCESS_BW_READ", /* Normal read-only access to bufffer */
	"ACCCESS_BW_WRITE", /* Normal write-only access to bufffer */
	"ACCESS_BW_RW", /* Normal read+write access to bufffer */
	"ACCESS_BW_READ_NT", /* Read-only access to bufffer, non-temporal loads */
	"ACCESS_BW_WRITE_NT", /* Write-only access to bufffer, non-tempral stores */
	"ACCESS_BW_RW_NT", /* Read+write access to bufffer, non-temporal load/stores */
	"ACCESS_LATENCY", /* Access in read-only with data dependencies */
	"ACCESS_LATENCY_NT", /* Access in read-only with data dependencies, non-temporal loads */
};

/* 'pools' file operations */
/* The 'pools' file is read-only and it will provide the list of
   detected pools and how they have been initialized */
static int pools_show(struct seq_file *m, void *v)
{
	int i;
	seq_printf(m, "=== Configured Pools ===\n");

	for (i = 0; i < g_pools_count; ++i) {
		struct mem_pool * pool = &g_pools[i];
		seq_printf(m, "\tPool ID: %d\n", i);
		seq_printf(m, "\tPhys Start: 0x%08llx\n", pool->phys_start);
		seq_printf(m, "\tSize: 0x%08llx\n", pool->size);
		seq_printf(m, "\tPool KVA: 0x%08lx\n", pool->pool_kva);
		seq_printf(m, "\tReady: %s\n\n", (pool->ready?"Y":"N"));
	}
	seq_printf(m, "==========================\n");

	return 0;
}

static int pools_open(struct inode *inode, struct file *file)
{
	return single_open(file, pools_show, NULL);
}

static const struct file_operations pools_fops = {
	.owner = THIS_MODULE,
	.open = pools_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* 'experiment' file operations */
/* The 'experiment' file is R/W. 

   When the file is read, it provides information about how the last
   experiment to be conducted has been interpreted by the kernel
   module.

   When the file is written, it allows users to define a new
   benchmarking activity to be performed.
 */
static int experiment_show(struct seq_file *m, void *v)
{
	seq_printf(m, "=== Current Experiment ===\n");
	seq_printf(m, "OBSERVED:\n");
	seq_printf(m, "\t Map Type: %s\n", map_type2string[cur_exp.obs_info.map_type]);
	seq_printf(m, "\t Access Type: %s\n", access_type2string[cur_exp.obs_info.access_type]);
	seq_printf(m, "\t Buffer Size: 0x%08lx\n", cur_exp.obs_info.buffer_size);
	seq_printf(m, "\t Pool ID: %d\n", cur_exp.obs_info.pool_id);
	seq_printf(m, "INTERFERENCE:\n"); 
	seq_printf(m, "\t Map Type: %s\n", map_type2string[cur_exp.interf_info.map_type]);
	seq_printf(m, "\t Access Type: %s\n", access_type2string[cur_exp.interf_info.access_type]);
	seq_printf(m, "\t Buffer Size: 0x%08lx\n", cur_exp.interf_info.buffer_size);
	seq_printf(m, "\t Pool ID: %d\n", cur_exp.interf_info.pool_id);
	seq_printf(m, "\nUSAGE: Provide new experiment definition with format:\n");
	seq_printf(m, "<OBS map type: c/n> <OBS access type: r/w/b/s/x/c/l/m> "
		   "<OBS buffer size> <OBS pool ID> "
		   "<INT map type: c/n> <INT access type: r/w/b/s/x/c/l/m> "
		   "<INT buffer size> <INT pool ID>\n"
		);
	seq_printf(m, "==========================\n");
	return 0;
}

static int experiment_open(struct inode *inode, struct file *file)
{
	return single_open(file, experiment_show, NULL);
}

ssize_t experiment_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *data)
{
	char *kbuf;
	int ret;
	
	/* Allocate kernel buffer */
	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	
	/*  Copy data from user space */
	if (copy_from_user(kbuf, buffer, count)) {
		kfree(kbuf);
		return -EFAULT;
	}
	
	kbuf[count] = '\0'; // Null-terminate the string
	
	/* Parse the input string */
	/* FORMAT: OBS-map-type OBS-access-type OBS-buffer-size OSB-pool-id 
	   INT-map-type INT-access-type INT-buffer-size INT-pool-id*/
	ret = sscanf(kbuf, "%c %c %ld %d %c %c %ld %d",
		     &cur_exp.obs_info.__raw_map_type, &cur_exp.obs_info.__raw_access_type,
		     &cur_exp.obs_info.buffer_size, &cur_exp.obs_info.pool_id,
		     &cur_exp.interf_info.__raw_map_type, &cur_exp.interf_info.__raw_access_type,
		     &cur_exp.interf_info.buffer_size, &cur_exp.interf_info.pool_id
		);

	/* Convert human-readable access/map type to enum/integer value */
	if (cur_exp.obs_info.__raw_map_type == 'c' ||
	    cur_exp.obs_info.__raw_map_type == 'C') {
		cur_exp.obs_info.map_type = MAP_CACHE;
	} else if (cur_exp.obs_info.__raw_map_type == 'c' ||
		   cur_exp.obs_info.__raw_map_type == 'N') {
		cur_exp.obs_info.map_type = MAP_NCACHE;
	} else {
		cur_exp.obs_info.map_type = MAP_CACHE;
	}

	if (cur_exp.interf_info.__raw_map_type == 'c' ||
	    cur_exp.interf_info.__raw_map_type == 'C') {
		cur_exp.interf_info.map_type = MAP_CACHE;
	} else if (cur_exp.interf_info.__raw_map_type == 'c' ||
		   cur_exp.interf_info.__raw_map_type == 'N') {
		cur_exp.interf_info.map_type = MAP_NCACHE;
	} else {
		cur_exp.interf_info.map_type = MAP_CACHE;
	}
	
	if (cur_exp.obs_info.__raw_access_type == 'r' ||
	    cur_exp.obs_info.__raw_access_type == 'R') {
		cur_exp.obs_info.access_type = ACCESS_BW_READ;
	} else if (cur_exp.obs_info.__raw_access_type == 'w' ||
	    cur_exp.obs_info.__raw_access_type == 'W') {
		cur_exp.obs_info.access_type = ACCESS_BW_WRITE;
	} else if (cur_exp.obs_info.__raw_access_type == 'b' ||
	    cur_exp.obs_info.__raw_access_type == 'B') {
		cur_exp.obs_info.access_type = ACCESS_BW_RW;
	} else if (cur_exp.obs_info.__raw_access_type == 's' ||
	    cur_exp.obs_info.__raw_access_type == 'S') {
		cur_exp.obs_info.access_type = ACCESS_BW_READ_NT;
	} else if (cur_exp.obs_info.__raw_access_type == 'x' ||
	    cur_exp.obs_info.__raw_access_type == 'X') {
		cur_exp.obs_info.access_type = ACCESS_BW_WRITE_NT;
	} else if (cur_exp.obs_info.__raw_access_type == 'c' ||
	    cur_exp.obs_info.__raw_access_type == 'C') {
		cur_exp.obs_info.access_type = ACCESS_BW_RW_NT;
	} else if (cur_exp.obs_info.__raw_access_type == 'l' ||
	    cur_exp.obs_info.__raw_access_type == 'L') {
		cur_exp.obs_info.access_type = ACCESS_LATENCY;
	} else if (cur_exp.obs_info.__raw_access_type == 'm' ||
	    cur_exp.obs_info.__raw_access_type == 'M') {
		cur_exp.obs_info.access_type = ACCESS_LATENCY_NT;
	} else {
		cur_exp.obs_info.access_type = ACCESS_BW_WRITE;
	}

	if (cur_exp.interf_info.__raw_access_type == 'r' ||
	    cur_exp.interf_info.__raw_access_type == 'R') {
		cur_exp.interf_info.access_type = ACCESS_BW_READ;
	} else if (cur_exp.interf_info.__raw_access_type == 'w' ||
	    cur_exp.interf_info.__raw_access_type == 'W') {
		cur_exp.interf_info.access_type = ACCESS_BW_WRITE;
	} else if (cur_exp.interf_info.__raw_access_type == 'b' ||
	    cur_exp.interf_info.__raw_access_type == 'B') {
		cur_exp.interf_info.access_type = ACCESS_BW_RW;
	} else if (cur_exp.interf_info.__raw_access_type == 's' ||
	    cur_exp.interf_info.__raw_access_type == 'S') {
		cur_exp.interf_info.access_type = ACCESS_BW_READ_NT;
	} else if (cur_exp.interf_info.__raw_access_type == 'x' ||
	    cur_exp.interf_info.__raw_access_type == 'X') {
		cur_exp.interf_info.access_type = ACCESS_BW_WRITE_NT;
	} else if (cur_exp.interf_info.__raw_access_type == 'c' ||
	    cur_exp.interf_info.__raw_access_type == 'C') {
		cur_exp.interf_info.access_type = ACCESS_BW_RW_NT;
	} else if (cur_exp.interf_info.__raw_access_type == 'l' ||
	    cur_exp.interf_info.__raw_access_type == 'L') {
		cur_exp.interf_info.access_type = ACCESS_LATENCY;
	} else if (cur_exp.interf_info.__raw_access_type == 'm' ||
	    cur_exp.interf_info.__raw_access_type == 'M') {
		cur_exp.interf_info.access_type = ACCESS_LATENCY_NT;
	} else {
		cur_exp.interf_info.access_type = ACCESS_BW_WRITE;
	}

	if (cur_exp.results) {
		pr_warn(PREFIX "WARNING: Deallocating previous experiment results.\n");
	}
	
	dealloc_results(&cur_exp);
	
	kfree(kbuf);
	
	return count;
}

static const struct file_operations experiment_fops = {
	.owner = THIS_MODULE,
	.open = experiment_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = experiment_write,
};

/* 'cmd' file operations */
static int cmd_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Available commands:\n");
	seq_printf(m, "\tstart|START: begin new experiment\n");
	seq_printf(m, "\treset|RESET: reset experiment history\n");
	seq_printf(m, "\tvalid|VALID: validate current experiment setup\n");
	return 0;
}

static int cmd_open(struct inode *inode, struct file *file)
{
	return single_open(file, cmd_show, NULL);
}

ssize_t cmd_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *data)
{
	char *kbuf;
	
	/* Allocate kernel buffer */
	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	
	/*  Copy data from user space */
	if (copy_from_user(kbuf, buffer, count)) {
		kfree(kbuf);
		return -EFAULT;
	}
	
	kbuf[count] = '\0'; // Null-terminate the string

	if (strcmp(kbuf, "start") == 0 || strcmp(kbuf, "START") == 0) {
		run_experiment(&cur_exp);
	} else if (strcmp(kbuf, "reset") == 0 || strcmp(kbuf, "RESET") == 0) {
		;/* TODO -- Erase results once results array is implemented */
	} else if (strcmp(kbuf, "validate") == 0 || strcmp(kbuf, "VALIDATE") == 0) {
		;/* TODO -- Add call to experiment validation */
	} else {
		;/* TODO -- Handle invalid command */
	}
	
	kfree(kbuf);
	
	return count;	
}

static const struct file_operations cmd_fops = {
	.owner = THIS_MODULE,
	.open = cmd_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = cmd_write,
};

/* 'results' file operations */
static int results_show(struct seq_file *m, void *v)
{
	int exp_len = 4; /* TODO get this from struct */
	int i;
	struct experiment_result * results = cur_exp.results;
	
	seq_printf(m, "== Displaying results information ==\n");

	experiment_show(m, v);

	seq_printf(m, "RESULTS:\n");

	if (!results) {
		seq_printf(m, "No results available for this experiment. Did you run it?\n");
		return 0;
	}
	
	for (i = 0; i < exp_len; ++i) {
		results = &cur_exp.results[i];
		
		seq_printf(m, "Active Cores: %d; Start (ns): %lld; End (ns): %lld;"
			   " Diff (ns): %lld;"
			   " Bytes R: %lld; Bytes W: %lld\n",
			   i, results->exp_start, results->exp_end,
			   results->exp_end - results->exp_start,
			   results->bytes_r, results->bytes_w);
	}
	// Add logic to display results information
	return 0;
}

static int results_open(struct inode *inode, struct file *file)
{
	return single_open(file, results_show, NULL);
}

static const struct file_operations results_fops = {
	.owner = THIS_MODULE,
	.open = results_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

void err_debugfs_interface_exit(void)
{
	debugfs_remove_recursive(membench_dir);
}

/* Debugfs initialization routine */
int __init debugfs_interface_init(void)
{
	struct dentry * retval;

	/* If everything looks good, initialize the buffer pointers. */
	cur_exp.obs_info.buffer_va = NULL;
	cur_exp.interf_info.buffer_va = NULL;
	cur_exp.results = NULL;
	
	membench_dir = debugfs_create_dir("membench", NULL);
	if (IS_ERR(membench_dir)) {
		pr_err(PREFIX "Failed to create membench directory\n");
		return PTR_ERR(membench_dir);
	}
	
	retval = debugfs_create_file("pools", 0444, membench_dir, NULL, &pools_fops);
	if (IS_ERR(retval)) {
		pr_err(PREFIX "Unable to create debugfs file: %s.\n", "pools");
		return PTR_ERR(retval);
	}
	
	retval = debugfs_create_file("experiment", 0644, membench_dir, NULL, &experiment_fops);
	if (IS_ERR(retval)) {
		pr_err(PREFIX "Unable to create debugfs file: %s.\n", "experiment");
		return PTR_ERR(retval);
	}

	retval = debugfs_create_file("cmd", 0644, membench_dir, NULL, &cmd_fops);
	if (IS_ERR(retval)) {
		pr_err(PREFIX "Unable to create debugfs file: %s.\n", "cmd");
		return PTR_ERR(retval);
	}

	retval = debugfs_create_file("results", 0444, membench_dir, NULL, &results_fops);
	if (IS_ERR(retval)) {
		pr_err(PREFIX "Unable to create debugfs file: %s.\n", "results");
		return PTR_ERR(retval);
	}

	return 0;
}

void __exit debugfs_interface_exit(void)
{
	debugfs_remove_recursive(membench_dir);
}
