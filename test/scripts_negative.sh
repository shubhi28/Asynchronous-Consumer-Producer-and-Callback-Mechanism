/usr/src/hw3-cse506g14/hw3/submitjob -c 2 /usr/src/hw3-cse506g14/hw3/test/concat_data_negative /usr/src/hw3-cse506g14/hw3/test/concat_output_negative
/usr/src/hw3-cse506g14/hw3/submitjob -z 1 /usr/src/hw3-cse506g14/hw3/test/data_large /usr/src/hw3-cse506g14/hw3/test/compress_output_negative
/usr/src/hw3-cse506g14/hw3/submitjob -z 1 data_large /usr/src/hw3-cse506g14/hw3/test/compress_output_fail
/usr/src/hw3-cse506g14/hw3/submitjob -u 1 /usr/src/hw3-cse506g14/hw3/test/compress_output_negative /usr/src/hw3-cse506g14/hw3/test/decompress_output_negative
/usr/src/hw3-cse506g14/hw3/submitjob -u 1 /usr/src/hw3-cse506g14/hw3/test/compress_output_fail /usr/src/hw3-cse506g14/hw3/test/decompress_output_fail
/usr/src/hw3-cse506g14/hw3/submitjob -e -k password 1 /usr/src/hw3-cse506g14/hw3/test/data_large /usr/src/hw3-cse506g14/hw3/test/encrypt_output_negative
/usr/src/hw3-cse506g14/hw3/submitjob -d -k password 1 /usr/src/hw3-cse506g14/hw3/test/data_large /usr/src/hw3-cse506g14/hw3/test/decrypt_output_negative
/usr/src/hw3-cse506g14/hw3/submitjob -d -k pasword 1 /usr/src/hw3-cse506g14/hw3/test/data_large /usr/src/hw3-cse506g14/hw3/test/decrypt_output_fail
/usr/src/hw3-cse506g14/hw3/submitjob -d -k paord 1 /usr/src/hw3-cse506g14/hw3/test/data_large /usr/src/hw3-cse506g14/hw3/test/decrypt_output_fail
