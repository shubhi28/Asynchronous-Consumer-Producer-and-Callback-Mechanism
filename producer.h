#include "job_queue.h"

static int producer(void *data)
{
	int rc = 0;
	struct job *j = NULL;
start:
	printk("in producer\n");
	printk("producer woke up\n");
	j = (struct job *) data;
	MUTEX_LOCK_QLEN;
	if (qlen < MAX) {
		rc = add_job(jq, j);
		if (rc < 0) {
			MUTEX_UNLOCK_QLEN;
			printk("Producer: error adding job\n");
			goto out;
		}
		qlen += 1;
	} else if (wqlen < MAX) {
		rc = add_job(wq, j);
		if (rc < 0) {
			MUTEX_UNLOCK_QLEN;
			printk
			    ("Producer: error adding job to wait queue\n");
			goto out;
		}
		wqlen += 1;
		printk("node added in wait queue\n");
	} else {
		MUTEX_UNLOCK_QLEN;
		printk("producer waiting for interrupt\n");
		wait_event_interruptible(wqp, wqlen < MAX);
		goto start;
	}
	MUTEX_UNLOCK_QLEN;
	wake_up_process(consumer_thread);
out:
	printk("exiting producer\n");
	return rc;

}
