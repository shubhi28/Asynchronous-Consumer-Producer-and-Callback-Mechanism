obj-m += sys_submitjob.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: user_submitjob kernel_submitjob

user_submitjob: submitjob.c
	gcc -g -Wall -Werror -pthread  submitjob.c -o submitjob -lcrypto

kernel_submitjob:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f submitjob
