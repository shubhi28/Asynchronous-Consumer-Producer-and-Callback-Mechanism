#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include "utilities.h"
#include "consumer.h"

#define __NR_submitjob 359

asmlinkage extern long (*sysptr) (void *arg);

struct job *prepare_job(struct job *my_job)
{
	int ret = 0;
	struct filename *infile = NULL, *outfile = NULL;
	char *key = NULL;
	char *algo = NULL;

	infile = getname(my_job->infile);
	if (IS_ERR(infile)) {
		ret = PTR_ERR(infile);
		goto out;
	}
	my_job->infile = kmalloc(strlen(infile->name), GFP_KERNEL);
	strcpy(my_job->infile, infile->name);
	j_id += 1;
	my_job->job_id = j_id;

	if (my_job->priority != 1 && my_job->priority != 2 &&
	    my_job->priority != 3) {
		ret = -EINVAL;
		goto out;

	}
	if (my_job->job_type == ENCRYPT || my_job->job_type == DECRYPT) {
		outfile = getname(my_job->outfile);
		if (IS_ERR(outfile)) {
			ret = PTR_ERR(outfile);
			goto out;
		}
		my_job->outfile =
		    kmalloc(strlen(outfile->name), GFP_KERNEL);
		strcpy(my_job->outfile, outfile->name);
		key = kmalloc(KEYLEN, GFP_KERNEL);
		if (!key) {
			ret = -ENOMEM;
			goto out;
		}
		if (my_job->key == NULL) {
			ret = -EINVAL;
			goto out;
		}
		if (copy_from_user(key, my_job->key, KEYLEN)) {
			ret = -ENOMEM;
			goto out;
		}
		my_job->key = key;
	}
	if (my_job->job_type == CHECKSUM) {
		if (my_job->algo == NULL) {
			ret = -EINVAL;
			goto out;
		}
		algo = kmalloc(strlen(my_job->algo), GFP_KERNEL);
		if (!algo) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(algo, my_job->algo, ALGOSIZE)) {
			ret = -ENOMEM;
			goto out;
		}
		my_job->algo = algo;

	}
	if (my_job->job_type == CONCAT || my_job->job_type == COMPRESS ||
	    my_job->job_type == DECOMPRESS) {
		outfile = getname(my_job->outfile);
		if (IS_ERR(outfile)) {
			ret = PTR_ERR(outfile);
			goto out;
		}
		my_job->outfile =
		    kmalloc(strlen(outfile->name), GFP_KERNEL);
		strcpy(my_job->outfile, outfile->name);
	}
	return my_job;
out:
	return ERR_PTR(ret);

}

asmlinkage long submitjob(void *arg)
{
	struct job *j;
	void *data = NULL;
	int ret = 0;
	char *list_buf = NULL;

	if (arg == NULL) {
		return -EINVAL;
	} else {
		j = kmalloc(sizeof(struct job), GFP_KERNEL);
		if (!j) {
			ret = -ENOMEM;
			goto out;
		}
		if (copy_from_user(j, arg, sizeof(struct job))) {
			ret = -EFAULT;
			goto out;
		}
		if (j->job_type == ENCRYPT || j->job_type == DECRYPT ||
		    j->job_type == CHECKSUM || j->job_type == CONCAT ||
		    j->job_type == COMPRESS || j->job_type == DECOMPRESS) {
			j = prepare_job(j);
			if (IS_ERR(j)) {
				ret = PTR_ERR(j);
				goto out;
			}

		}
		if (j->job_type == DISPLAY) {
			list_buf = kzalloc(PAGE_SIZE * 2, GFP_KERNEL);
			if (!list_buf) {
				ret = -ENOMEM;
				goto out;
			}
			list_buf = display_list(list_buf);
			if (copy_to_user
			    (j->outfile, list_buf, strlen(list_buf))) {
				ret = -EFAULT;
				goto out;
			}
			goto out;
		}
		if (j->job_type == REMOVEALL) {
			ret = remove_job(jq);
			goto out;
		}

		if (j->job_type == REMOVE) {
			ret = remove_single_job(j->job_id, jq);
			goto out;
		}
		if (j->job_type == CHANGEPR) {
			ret =
			    change_priority_main_queue(jq, j->job_id,
						       j->priority);
			goto out;
		}
	}
	data = (void *) j;
	MUTEX_LOCK_JQUEUE;
	MUTEX_LOCK_QLEN;
	if (wqlen >= MAX) {
		ret = -EBUSY;
		MUTEX_UNLOCK_JQUEUE;
		MUTEX_UNLOCK_QLEN;
		goto out;
	}
	MUTEX_UNLOCK_JQUEUE;
	MUTEX_UNLOCK_QLEN;
	ret = producer(data);
out:
	if (list_buf)
		kfree(list_buf);
	return ret;
}

static int __init init_sys_submitjob(void)
{
	int rc = 0;
	printk("installed new sys_submitjob module\n");
	rc = initialize_queue();
	if (rc) {
		printk(KERN_INFO "Job Queue initialization failed\n");
		rc = -EFAULT;
	}

	init_waitqueue_head(&wqc);
	init_waitqueue_head(&wqp);
	consumer_thread = kthread_create(consumer, NULL, "consumer");
	if (!consumer_thread) {
		printk(KERN_INFO "Thread creation failed.\n");
		return -EFAULT;
	}
	wake_up_process(consumer_thread);
	nl_skt = netlink_kernel_create(&init_net, NETLINK_USER, NULL);
	if (!nl_skt) {
		printk(KERN_ALERT "Error Creating Socket.\n");
		return -ENOMEM;
	} else {
		printk(KERN_INFO "Socket Initialized\n");
	}
	if (sysptr == NULL)
		sysptr = submitjob;
	return rc;
}
static void __exit exit_sys_submitjob(void)
{
	kill_thread++;
	MUTEX_LOCK_JQUEUE;
	MUTEX_LOCK_QLEN;
	qlen++;
	MUTEX_UNLOCK_QLEN;
	MUTEX_UNLOCK_JQUEUE;
	wake_up_process(consumer_thread);
	UDBG;
	if (consumer_thread) {
		UDBG;
		kthread_stop(consumer_thread);
	}
	MUTEX_LOCK_JQUEUE;
	MUTEX_LOCK_QLEN;
	if (jq) {
		remove_job(jq);
		kfree(jq);
	}
	MUTEX_UNLOCK_QLEN;
	MUTEX_UNLOCK_JQUEUE;
	if (nl_skt) {
		printk(KERN_INFO "Releasing Socket\n");
		netlink_kernel_release(nl_skt);
	}
	if (sysptr != NULL)
		sysptr = NULL;
	printk(KERN_INFO "removed sys_submitjob module\n");
}

module_init(init_sys_submitjob);
module_exit(exit_sys_submitjob);
MODULE_LICENSE("GPL");
