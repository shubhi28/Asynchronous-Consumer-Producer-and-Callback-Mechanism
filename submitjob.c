#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <getopt.h>
#include <asm/page.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <openssl/md5.h>
#include <pthread.h>

#include "submitjob.h"

#define MAX_PAYLOAD 1024
#define NETLINK_USER 31
#define __NR_submitjob 359

#ifndef __NR_submitjob
#error submitjob system call not defined
#endif


struct sockaddr_nl src_addr;
struct sockaddr_nl dest_addr;
struct nlmsghdr *nlmh = NULL;
struct iovec iv;
int skt_fd;
struct msghdr msg;
pthread_t th1;

int validate_file(char *);


int netlink_skt()
{
	if (skt_fd < 0)
		return -1;
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();

	bind(skt_fd, (struct sockaddr *) &src_addr, sizeof(src_addr));
	nlmh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlmh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlmh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlmh->nlmsg_pid = getpid();
	nlmh->nlmsg_flags = 0;

	iv.iov_base = (void *) nlmh;
	iv.iov_len = nlmh->nlmsg_len;
	msg.msg_iov = &iv;
	msg.msg_iovlen = 1;

	recvmsg(skt_fd, &msg, 0);
	printf("CALLBACK: %s\n", (char *) NLMSG_DATA(nlmh));

	close(skt_fd);
	return 0;

}

int main(int argc, char *argv[])
{
	int rc, option = 0, result = 0, priority = 0, flagk = 0, flage = 0;
	int flagd = 0, flaga = 0, flagh = 0, flagc = 0, flagz = 0, flagu =
	    0;
	int count =1;
	int flagr = 0, flagR = 0, flagl = 0, flagC = 0, job_id = 0;
	char *algo = NULL, *key = NULL, *infile = NULL, *outfile = NULL;
	void *dummy = NULL;
	struct job my_job;
	unsigned char *digest = NULL;
	MD5_CTX md5;
	MD5_Init(&md5);

	while ((option = getopt(argc, argv, "edk:a:hiczur:RlC")) != -1) {
		switch (option) {
		case 'e':
			flage++;
			my_job.job_type = ENCRYPT;
			break;
		case 'd':
			flagd++;
			my_job.job_type = DECRYPT;
			break;
		case 'k':
			flagk++;
			key = optarg;
			if (strlen(key) < 6) {
				printf
				    ("Key length should be minimum 6 characters.\n");
				rc = -EINVAL;
				goto out;
			}
			break;
		case 'a':
			flaga++;
			algo = optarg;
			break;
		case 'h':
			flagh++;
			my_job.job_type = CHECKSUM;
			break;
		case 'c':
			flagc++;
			my_job.job_type = CONCAT;
			break;
		case 'z':
			flagz++;
			my_job.job_type = COMPRESS;
			break;
		case 'u':
			flagu++;
			my_job.job_type = DECOMPRESS;
			break;
		case 'r':
			flagr++;
			job_id = atoi(optarg);
			my_job.job_type = REMOVE;
			break;
		case 'R':
			flagR++;
			printf("remove all jobs\n");
			my_job.job_type = REMOVEALL;
			break;
		case 'l':
			flagl++;
			my_job.job_type = DISPLAY;
			break;
		case 'C':
			flagC++;
			my_job.job_type = CHANGEPR;
			break;
		default:
			printf("Invalid option.\n");
			goto out;
		}
	}
	if (flage && (flagd || flagc || flagh || flagz || flagu ||
		      flagr || flagR || flagl)) {
		printf("error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flage > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagd && (flage || flagc || flagh || flagz || flagu ||
		      flagr || flagR || flagl)) {
		printf("error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagd > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (!flagk && (flage || flagd)) {
		printf("Please provide key.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flaga && (flagc || flagz || flagu || flagr || flagR || flagl)) {
		printf("error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (!flaga) {
		if ((flage) || (flagd)) {
			algo = "AES";
		} else {
			algo = "MD5";
		}
	}
	if (flagc && (flagd || flage || flagh || flagz || flagu ||
		      flagr || flagR || flagl)) {
		printf("error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagc > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagh && (flagd || flagc || flage || flagz || flagu ||
		      flagr || flagR || flagl)) {
		printf("error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagh > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagz && (flagd || flagc || flagh || flage || flagu ||
		      flagr || flagR || flagl)) {
		printf("error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagz > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagu && (flagd || flagc || flagh || flagz || flage ||
		      flagr || flagR || flagl)) {
		printf("error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagu > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagr > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagR > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagl > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagC > 1) {
		printf("Error in parameters passed.\n");
		rc = -EINVAL;
		goto out;
	}
	if (flagr)
		goto out_hash;
	if (flagR)
		goto out_hash;
	if (flagl) {
		goto out_hash;
	}
	if (flagC) {
		if (!argv[optind]) {
			printf("Please provide job id.\n");
			goto out;
		}
		my_job.job_id = atoi(argv[optind]);
		if (!argv[optind + 1]) {
			printf("Please provide job priority.\n");
			goto out;
		}
		my_job.priority = atoi(argv[optind + 1]);
		goto out_hash;
	}
	if (!argv[optind]) {
		printf("Please provide priority of job.\n");
		goto out;
	}
	my_job.job_id = 0;
	priority = atoi(argv[optind]);
	my_job.priority = priority;
	if (!argv[optind + 1]) {
		printf("Please provide input file.\n");
		goto out;
	}
	infile = argv[optind + 1];
	result = validate_file(infile);
	if (result == -1)
		goto out;
	my_job.infile = infile;
	if (argv[optind + 2]) {
		if (flagh) {
                        printf("Output file not needed.\n");
                        goto out;
                }
	}
	else if (!argv[optind + 2] && !flagh) {
		printf("Please provide output file.\n");
		goto out;
	}
	outfile = argv[optind + 2];
out_hash:
	my_job.pid = getpid();
	if (my_job.job_type == ENCRYPT || my_job.job_type == DECRYPT) {
		my_job.outfile = outfile;
		my_job.algo = algo;
		digest = malloc(sizeof(unsigned char) * 16);
		if (!digest)
			goto out;
		MD5_Update(&md5, key, 16);
		MD5_Final(digest, &md5);
		my_job.key = digest;
	}
	if (my_job.job_type == CHECKSUM) {
		my_job.algo = algo;
		my_job.outfile = NULL;
		my_job.key = NULL;
	}
	if (my_job.job_type == CONCAT || my_job.job_type == COMPRESS
	    || my_job.job_type == DECOMPRESS) {
		my_job.outfile = outfile;
		my_job.key = NULL;
		my_job.algo = NULL;
	}
	if (my_job.job_type == DISPLAY) {
		my_job.outfile = malloc(PAGE_SIZE * 2);
		my_job.infile = NULL;
		my_job.algo = NULL;
		my_job.key = NULL;
		goto sys_call_returned;
	}
	if (my_job.job_type == REMOVEALL) {
		my_job.infile = NULL;
		my_job.outfile = NULL;
		my_job.algo = NULL;
		my_job.key = NULL;
		goto sys_call_returned;
	}
	if (my_job.job_type == REMOVE) {
		my_job.job_id = job_id;
		my_job.infile = NULL;
		my_job.outfile = NULL;
		my_job.algo = NULL;
		my_job.key = NULL;
		goto sys_call_returned;
	}
	if (my_job.job_type == CHANGEPR) {
		my_job.infile = NULL;
		my_job.outfile = NULL;
		my_job.algo = NULL;
		my_job.key = NULL;
		goto sys_call_returned;
	}
	skt_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);

	if (flagh || flage || flagd || flagc || flagz || flagu) {
		if (pthread_create
		    (&th1, NULL, (void *) &netlink_skt, (void *) skt_fd)) {
			printf("Error in thread creation\n");
		} else
			printf("Thread Created\n");
	}
sys_call_returned:
	dummy = (void *) &my_job;
	rc = syscall(__NR_submitjob, dummy);
	if (rc == 0) {
		if (flagl) {
			printf("Job_id\t Job_Priority Job Type\tInput File\n");
			printf("%s", my_job.outfile);
			goto out;
		}
		if (flagR) {
			printf("All jobs deleted.\n");
			goto out;
		}
		if (flagr) {
			printf("Job deleted.\n");
			goto out;
		}
		if (flagC) {
			printf("Job priority changed.\n");
			goto out;
		}
		printf("syscall returned %d\n", rc);

	} else {
		if (flagl) {
			printf("Error while listing jobs.\n");
			goto out_err2;
		}
		if (flagR) {
			printf("Error while deleting jobs.\n");
			goto out_err2;
		}
		if (flagr) {
			printf("Job with job id %d doesn't exist.\n",
			       my_job.job_id);
			goto out_err2;
		}
out_err2:
		printf("syscall returned %d (errno=%d)\n", rc, errno);
		perror("Error");
		goto out;
	}

	printf("count = %d\n",++count);
	if (pthread_join(th1, NULL)) {
		printf("Error joining thread\n");
	}

	printf("count = %d\n",++count);
out:
	if (my_job.outfile && flagl)
		free(my_job.outfile);
	if (digest)
		free(digest);
	exit(rc);
}

int validate_file(char *file)
{
	struct stat st;
	int ret;
	ret = stat(file, &st);
	if (ret) {
		printf("Either input or output file doesn't exist\n");
		return -1;

	}
	if (S_ISREG(st.st_mode) == 0) {
		printf("Input or output file is not a regular file\n");
		return -1;
	}
	return 0;
}
