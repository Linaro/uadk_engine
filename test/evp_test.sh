#!/bin/bash

set -x

TEST_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ $# -eq 0 ]; then
	echo "No para: evp_test.sh /path/to/openssl"
	exit
fi

export OPENSSL_CONF=$TEST_SCRIPT_DIR/../uadk_provider.cnf

cd "$1"/test

#Cipher test
digest_algs=$(openssl list -digest-algorithms)
if [[ $digest_algs =~ "uadk_provider" ]]; then
	./evp_test ./recipes/30-test_evp_data/evpmd_sm3.txt
	./evp_test ./recipes/30-test_evp_data/evpmd_sha.txt
fi

cipher_algs=$(openssl list -cipher-algorithms)
if [[ $cipher_algs =~ "uadk_provider" ]]; then
	./evp_test ./recipes/30-test_evp_data/evpciph_sm4.txt
	./evp_test ./recipes/30-test_evp_data/evpciph_aes_common.txt
	./evp_test ./recipes/30-test_evp_data/evpciph_des3_common.txt
fi

signature_algs=$(openssl list -signature-algorithms)
if [[ $signature_algs =~ "uadk_provider" ]]; then
	./evp_test ./recipes/30-test_evp_data/evppkey_rsa.txt
	./evp_test ./recipes/30-test_evp_data/evppkey_rsa_common.txt
fi

keyexch_algs=$(openssl list -key-exchange-algorithms)
if [[ $keyexch_algs =~ "uadk_provider" ]]; then
	./evp_test ./recipes/30-test_evp_data/evppkey_dh.txt
fi
