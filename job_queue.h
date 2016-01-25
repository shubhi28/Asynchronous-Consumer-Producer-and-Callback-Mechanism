#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/kthread.h>

#include "submitjob.h"

#define MAX 5
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#define MUTEX_LOCK_QLEN mutex_lock(&m_qlen)
#define MUTEX_LOCK_WQLEN mutex_lock(&m_wqlen)
#define MUTEX_LOCK_JQUEUE mutex_lock(&jq->mq)
#define MUTEX_LOCK_WQUEUE mutex_lock(&wq->mq)
#define MUTEX_UNLOCK_QLEN mutex_unlock(&m_qlen)
#define MUTEX_UNLOCK_WQLEN mutex_unlock(&m_wqlen)
#define MUTEX_UNLOCK_JQUEUE mutex_unlock(&jq->mq)
#define MUTEX_UNLOCK_WQUEUE mutex_unlock(&wq->mq)

int qlen = 0;
int wqlen = 0;
int is_job = 0;
struct mutex m_qlen;
struct mutex m_wqlen;
struct mutex m_job;

struct job_queue {
	struct job *job;
	struct list_head head;
	struct mutex mq;
};
struct job_queue *jq;
struct job_queue *wq;

static struct task_struct *consumer_thread;
wait_queue_head_t wqc;
wait_queue_head_t wqp;
int j_id, kill_thread;

static int initialize_queue(void)
{
	j_id = 0;
	kill_thread = 0;
	jq = kmalloc(sizeof(struct job_queue), GFP_KERNEL);
	if (!jq) {
		return -ENOMEM;
	}
	printk("init queue.. %d\n", qlen);
	INIT_LIST_HEAD(&jq->head);
	mutex_init(&jq->mq);
	mutex_init(&m_qlen);
	wq = kmalloc(sizeof(struct job_queue), GFP_KERNEL);
	if (!wq) {
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&wq->head);
	mutex_init(&wq->mq);
	mutex_init(&m_job);
	return 0;
}

static int add_job(struct job_queue *jq, struct job *j)
{
	int rc = 0;
	struct job_queue *temp = NULL;
	temp = kmalloc(sizeof(struct job_queue), GFP_KERNEL);
	if (!temp)
		return -ENOMEM;
	temp->job = j;
	temp->job->infile = j->infile;
	MUTEX_LOCK_JQUEUE;
	INIT_LIST_HEAD(&(temp->head));
	list_add_tail(&(temp->head), &jq->head);
	MUTEX_UNLOCK_JQUEUE;
	return rc;
}

static char *display_list(char *list_buf)
{
	struct job_queue *curr = NULL, *temp = NULL;
	int pos = 0;
	char size[5], priority[5];
	MUTEX_LOCK_JQUEUE;
	list_for_each_entry_safe(curr, temp, &jq->head, head) {
		snprintf(size, 5, "%d", curr->job->job_id);
		memcpy(list_buf + pos, size, 5);
		pos = pos + strlen(size);
		memcpy(list_buf + pos, "\t", 1);
		pos = pos + 1;
		snprintf(priority, 5, "%d", curr->job->priority);
                memcpy(list_buf + pos, priority, 5);
                pos = pos + strlen(priority);
                memcpy(list_buf + pos, "\t", 1);
                pos = pos + 1;
		if (curr->job->job_type == ENCRYPT) {
			memcpy(list_buf + pos, "Encrypt",
			       strlen("Encrypt"));
			pos = pos + strlen("Encrypt");
		}
		if (curr->job->job_type == DECRYPT) {
			memcpy(list_buf + pos, "Decrypt",
			       strlen("Decrypt"));
			pos = pos + strlen("Decrypt");
		}
		if (curr->job->job_type == CHECKSUM) {
			memcpy(list_buf + pos, "Checksum",
			       strlen("Checksum"));
			pos = pos + strlen("Checksum");
		}
		if (curr->job->job_type == CONCAT) {
			memcpy(list_buf + pos, "Concat", strlen("Concat"));
			pos = pos + strlen("Concat");
		}
		if (curr->job->job_type == COMPRESS) {
			memcpy(list_buf + pos, "Compress",
			       strlen("Compress"));
			pos = pos + strlen("Compress");
		}
		if (curr->job->job_type == DECOMPRESS) {
			memcpy(list_buf + pos, "Decompress",
			       strlen("Decompress"));
			pos = pos + strlen("Decompress");
		}
		memcpy(list_buf + pos, "\t", 1);
		pos = pos + 1;
		memcpy(list_buf + pos, curr->job->infile,
		       strlen(curr->job->infile));
		pos = pos + strlen(curr->job->infile);
		memcpy(list_buf + pos, "\n", 1);
		pos = pos + 1;
	}
	MUTEX_UNLOCK_JQUEUE;
	return list_buf;
}

static int remove_job(struct job_queue *jq)
{
	struct job_queue *curr = NULL, *temp = NULL;
	list_for_each_entry_safe(curr, temp, &jq->head, head) {
		list_del(&(curr->head));
		qlen--;
		if (curr->job->infile) {
			kfree(curr->job->infile);
		}
		if (curr->job) {
			printk("Deleting jobid : %d\n", curr->job->job_id);
			kfree(curr->job);
		}
		if (curr) {
			kfree(curr);
		}
	}
	return 0;
}

static int remove_single_job(int job_id, struct job_queue *jq)
{
	struct job_queue *curr = NULL, *temp = NULL;
	int flag = 0;
	MUTEX_LOCK_JQUEUE;
	MUTEX_LOCK_QLEN;
	list_for_each_entry_safe(curr, temp, &jq->head, head) {
		if (curr->job->job_id == job_id) {
			flag = 1;
			list_del(&(curr->head));
			qlen--;
			if (curr->job->infile) {
				kfree(curr->job->infile);
			}
			if (curr->job) {
				kfree(curr->job);
			}
			if (curr) {
				kfree(curr);
			}
		}
	}
	MUTEX_UNLOCK_QLEN;
	MUTEX_UNLOCK_JQUEUE;
	if (!flag)
		return -EINVAL;
	return 0;

}

static struct job_queue *remove_priority(struct job_queue *jq)
{
	struct job_queue *curr = NULL, *temp = NULL, *work = NULL;
	int priority = 0;
	MUTEX_LOCK_JQUEUE;
	for (priority = 1; priority <= 3; priority++) {
		list_for_each_entry_safe(curr, temp, &jq->head, head) {
			if (curr->job->priority == priority) {
				work = curr;
				list_del(&(curr->head));
				goto out;
			}
		}
	}

out:
	MUTEX_UNLOCK_JQUEUE;
	printk("remove_priority: job_id = %d, priority = %d\n",
	       work->job->job_id, work->job->priority);
	return work;

}

static struct job_queue *move_priority(struct job_queue *wq)
{
	struct job_queue *curr = NULL, *temp = NULL, *work = NULL;
	int priority = 0;
	MUTEX_LOCK_WQUEUE;
	for (priority = 1; priority <= 3; priority++) {
		list_for_each_entry_safe(curr, temp, &wq->head, head) {
			if (curr->job->priority == priority) {
				work = curr;
				list_del(&(curr->head));
				goto out;
			}
		}
	}

out:
	MUTEX_UNLOCK_WQUEUE;
	return work;

}

static int change_priority_main_queue(struct job_queue *jq, int job_id,
				      int new_priority)
{
	struct job_queue *curr = NULL, *temp = NULL;
	MUTEX_LOCK_JQUEUE;
	MUTEX_LOCK_QLEN;
	list_for_each_entry_safe(curr, temp, &jq->head, head) {
		if (curr->job->job_id == job_id) {
			curr->job->priority = new_priority;
			goto out;
		}
	}

out:
	MUTEX_UNLOCK_QLEN;
	MUTEX_UNLOCK_JQUEUE;
	return 0;

}
