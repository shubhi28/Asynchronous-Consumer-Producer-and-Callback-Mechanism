#!/bin/sh
set -x
# WARNING: this script doesn't check for errors, so you have to enhance it in case any of the commands
# below fail.
lsmod | grep sys_submitjob.ko
rmmod sys_submitjob
insmod sys_submitjob.ko
lsmod | grep sys_submitjob.ko
