#include "producer.h"
#include "callback.h"

static int execute_md5_checksum(struct job *job);
static int execute_sha1_checksum(struct job *job);
static int execute_concat(struct job *job);
static int execute_compress(struct job *job);
static int execute_decompress(struct job *job);
static int execute_encrypt(struct job *job);
static int execute_decrypt(struct job *job);

static int consumer(void *data)
{
	struct job_queue *exec_job = NULL, *shift_job = NULL;
	int rc = 0;
      start:
	wait_event_interruptible(wqc, qlen > 0);
	if (kill_thread > 0)
		goto out;
	MUTEX_LOCK_QLEN;
	if (qlen > 0) {
		exec_job = remove_priority(jq);
		if (IS_ERR(exec_job)) {
			rc = PTR_ERR(exec_job);
			MUTEX_UNLOCK_QLEN;
			goto free_job;
		}
		qlen--;
		if (wqlen > 0) {
			shift_job = move_priority(wq);
			if (IS_ERR(shift_job)) {
				rc = PTR_ERR(shift_job);
				MUTEX_UNLOCK_QLEN;
				goto free_job;
			}
			rc = add_job(jq, shift_job->job);
			if (rc < 0) {
				MUTEX_UNLOCK_QLEN;
				goto free_job;
			}
			wqlen--;
			qlen++;
		}
	}
	MUTEX_UNLOCK_QLEN;
	wake_up_all(&wqp);
	if (exec_job != NULL && exec_job->job != NULL) {
		if (exec_job->job->job_type == CHECKSUM) {
			if (!strcmp(exec_job->job->algo, "MD5")) {
				rc = execute_md5_checksum(exec_job->job);
				if (rc) {
					callback(exec_job->job->pid,
						 "Checksum Failed!");
				}
			} else if (!strcmp(exec_job->job->algo, "SHA1")) {
				rc = execute_sha1_checksum(exec_job->job);
				if (rc) {
					callback(exec_job->job->pid,
						 "Checksum Failed!");
				}
			}
		}
		if (exec_job->job->job_type == CONCAT) {

			rc = execute_concat(exec_job->job);
		}
		if (exec_job->job->job_type == ENCRYPT) {

			rc = execute_encrypt(exec_job->job);
		}
		if (exec_job->job->job_type == DECRYPT) {

			rc = execute_decrypt(exec_job->job);
		}
		if (exec_job->job->job_type == COMPRESS) {

			rc = execute_compress(exec_job->job);
		}
		if (exec_job->job->job_type == DECOMPRESS) {

			rc = execute_decompress(exec_job->job);
		}
free_job:
		if (exec_job->job->infile)
			kfree(exec_job->job->infile);
		if (exec_job->job)
			kfree(exec_job->job);
		if (exec_job)
			kfree(exec_job);
		UDBG;
	}
	schedule();
	goto start;

out:
	return rc;
}

static int execute_md5_checksum(struct job *job)
{
	int rc = 0, i = 0;
	char c[33];
	unsigned char *digest = NULL;
	char file[] = { "Value of checksum is: " };
	digest = kzalloc(16, GFP_KERNEL);
	if (!digest) {
		rc = -ENOMEM;
		goto free_job;
	}
	digest = md5_checksum(job->infile, digest);
	if (IS_ERR(digest)) {
		printk("error in digest\n");
		rc = PTR_ERR(digest);
		goto free_job;
	}
	printk("digest is \n");
	for (i = 0; i < 16; ++i)
		sprintf(&c[i * 2], "%02x", (unsigned int) digest[i]);
	printk("%s\n", c);
	strcat(file, c);
	callback(job->pid, file);
	if (digest)
		kfree(digest);
free_job:
	return rc;

}

static int execute_sha1_checksum(struct job *job)
{
	int rc = 0, i = 0;
	char c[41];
	unsigned char *digest = NULL;
	char file[] = { "Value of checksum is: " };
	digest = kzalloc(20, GFP_KERNEL);
	if (!digest) {
		rc = -ENOMEM;
		goto free_job;
	}
	digest = sha1_checksum(job->infile, digest);
	if (IS_ERR(digest)) {
		rc = PTR_ERR(digest);
		goto free_job;
	}
	for (i = 0; i < 20; ++i)
		sprintf(&c[i * 2], "%02x", (unsigned int) digest[i]);
	strcat(file, c);
	callback(job->pid, file);
	if (digest)
		kfree(digest);
free_job:
	return rc;

}

static int execute_concat(struct job *job)
{
	int rc = 0;
	rc = concat_files(job->infile, job->outfile);
	if (rc) {
		callback(job->pid, "Concat Failed!");
	} else {
		callback(job->pid, "Concat Successful!");
	}
	return rc;
}

static int execute_compress(struct job *job)
{
	int rc = 0;
	rc = compress(job->infile, job->outfile);
	if (rc) {
		callback(job->pid, "Compression Failed!");
	} else {
		callback(job->pid, "Compression Successful!");
	}
	return rc;
}

static int execute_decompress(struct job *job)
{
	int rc = 0;
	rc = decompress(job->infile, job->outfile);
	if (rc) {
		callback(job->pid, "Decompression Failed!");
	} else {
		callback(job->pid, "Decompression Successful!");
	}

	return rc;
}
static int execute_encrypt(struct job *job)
{
	int rc = 0;
	rc = encrypt(job->infile, job->outfile, job->key);
	if (rc) {
		callback(job->pid, "Encryption Failed!");
	} else {
		callback(job->pid, "Encryption Successful!");
	}
	return rc;
}

static int execute_decrypt(struct job *job)
{
	int rc = 0;
	rc = decrypt(job->infile, job->outfile, job->key);
	if (rc) {
		callback(job->pid, "Decryption Failed!");
	} else {
		callback(job->pid, "Decryption Successful!");
	}
	return rc;
}
