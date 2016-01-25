
#define KEYLEN 16
#define ALGOSIZE 10
#define NETLINK_USER 31

enum job_type {
	ENCRYPT,
	DECRYPT,  
	CHECKSUM, 
	CONCAT,   
	COMPRESS, 
	DECOMPRESS, 
	REMOVE,
	REMOVEALL,   
	DISPLAY,
	CHANGEPR
};

struct job {
	char *infile;
	char *outfile;
	int job_id;
	int job_type;
	int priority;
	char *algo;
	unsigned char *key;
	pid_t pid;
};

