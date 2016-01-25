/usr/src/hw3-cse506g14/hw3/submitjob -h 3 /usr/src/hw3-cse506g14/hw3/test/data_large
/usr/src/hw3-cse506g14/hw3/submitjob -c 2 /usr/src/hw3-cse506g14/hw3/test/concat_data_large /usr/src/hw3-cse506g14/hw3/test/concat_output_large
/usr/src/hw3-cse506g14/hw3/submitjob -z 1 /usr/src/hw3-cse506g14/hw3/test/data_large /usr/src/hw3-cse506g14/hw3/test/compress_output_large
/usr/src/hw3-cse506g14/hw3/submitjob -u 1 /usr/src/hw3-cse506g14/hw3/test/compress_output_large /usr/src/hw3-cse506g14/hw3/test/decompress_output_large
/usr/src/hw3-cse506g14/hw3/submitjob -e -k password 1 /usr/src/hw3-cse506g14/hw3/test/data_large /usr/src/hw3-cse506g14/hw3/test/encrypt_output_large
/usr/src/hw3-cse506g14/hw3/submitjob -d -k password 1 /usr/src/hw3-cse506g14/hw3/test/encrypt_output_large /usr/src/hw3-cse506g14/hw3/test/decrypt_output_large
/usr/src/hw3-cse506g14/hw3/submitjob -h -a MD5 3 /usr/src/hw3-cse506g14/hw3/test/data_large
/usr/src/hw3-cse506g14/hw3/submitjob -h -a SHA1 3 /usr/src/hw3-cse506g14/hw3/test/data_large
