#!/bin/bash

set -x
sudo chmod 666 /dev/hisi_*

TEST_SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

version=$(openssl version)
echo $version

# Extract the major version number (e.g., "3") from the version string
major_version=$(echo $version | awk -F'[ .]' '{print $2}')
echo "OpenSSL major version is "$major_version

# Check if the major version is equal to or greater than 3
if ((major_version >= 3)); then
	engine_id="$TEST_SCRIPT_DIR/../src/.libs/uadk_provider.so"
	digest_algs=$(openssl list -provider $engine_id -digest-algorithms)
	cipher_algs=$(openssl list -provider $engine_id -cipher-algorithms)
	signature_algs=$(openssl list -provider $engine_id -signature-algorithms)
	keyexch_algs=$(openssl list -provider $engine_id -key-exchange-algorithms)
fi

if [[ $digest_algs =~ "uadk_provider" ]]; then
	echo "uadk_provider testing digest"
	openssl speed -provider $engine_id -evp md5
	openssl speed -provider $engine_id -evp sm3
	openssl speed -provider $engine_id -evp sha1
	openssl speed -provider $engine_id -evp sha224
	openssl speed -provider $engine_id -evp sha256
	openssl speed -provider $engine_id -evp sha384
	openssl speed -provider $engine_id -evp sha512

	openssl speed -provider $engine_id -async_jobs 1 -evp md5
	openssl speed -provider $engine_id -async_jobs 1 -evp sm3
	openssl speed -provider $engine_id -async_jobs 1 -evp sha1
	openssl speed -provider $engine_id -async_jobs 1 -evp sha224
	openssl speed -provider $engine_id -async_jobs 1 -evp sha256
	openssl speed -provider $engine_id -async_jobs 1 -evp sha384
	openssl speed -provider $engine_id -async_jobs 1 -evp sha512
fi

if [[ $cipher_algs =~ "uadk_provider" ]]; then
	echo "uadk_provider testing cipher"
	openssl speed -provider $engine_id -evp aes-128-cbc
	openssl speed -provider $engine_id -evp aes-192-cbc
	openssl speed -provider $engine_id -evp aes-256-cbc
	openssl speed -provider $engine_id -evp aes-128-ecb
	openssl speed -provider $engine_id -evp aes-192-ecb
	openssl speed -provider $engine_id -evp aes-256-ecb
	openssl speed -provider $engine_id -evp aes-128-xts
	openssl speed -provider $engine_id -evp aes-256-xts
	openssl speed -provider $engine_id -evp sm4-cbc
	openssl speed -provider $engine_id -evp sm4-ecb
	openssl speed -provider $engine_id -evp des-ede3-cbc
	openssl speed -provider $engine_id -evp des-ede3-ecb

	openssl speed -provider $engine_id -async_jobs 1 -evp aes-128-cbc
	openssl speed -provider $engine_id -async_jobs 1 -evp aes-192-cbc
	openssl speed -provider $engine_id -async_jobs 1 -evp aes-256-cbc
	openssl speed -provider $engine_id -async_jobs 1 -evp aes-128-ecb
	openssl speed -provider $engine_id -async_jobs 1 -evp aes-192-ecb
	openssl speed -provider $engine_id -async_jobs 1 -evp aes-256-ecb
	openssl speed -provider $engine_id -async_jobs 1 -evp aes-128-xts
	openssl speed -provider $engine_id -async_jobs 1 -evp aes-256-xts
	openssl speed -provider $engine_id -async_jobs 1 -evp sm4-cbc
	openssl speed -provider $engine_id -async_jobs 1 -evp sm4-ecb
	openssl speed -provider $engine_id -async_jobs 1 -evp des-ede3-cbc
	openssl speed -provider $engine_id -async_jobs 1 -evp des-ede3-ecb
fi

if [[ $signature_algs =~ "uadk_provider" ]]; then
	echo "uadk_provider testing rsa"
	openssl speed -provider $engine_id rsa1024
	openssl speed -provider $engine_id rsa2048
	openssl speed -provider $engine_id rsa4096
	openssl speed -provider $engine_id -async_jobs 1 rsa1024
	openssl speed -provider $engine_id -async_jobs 1 rsa2048
	openssl speed -provider $engine_id -async_jobs 1 rsa4096

	openssl genrsa -out prikey.pem -provider $engine_id 1024
	openssl rsa -in prikey.pem -pubout -out pubkey.pem -provider $engine_id
	echo "Content to be encrypted" > plain.txt

	openssl pkeyutl -encrypt -in plain.txt -inkey pubkey.pem -pubin -out enc.txt \
	-pkeyopt rsa_padding_mode:pkcs1 -provider $engine_id

	openssl pkeyutl -decrypt -in enc.txt -inkey prikey.pem -out dec.txt \
        -pkeyopt rsa_padding_mode:pkcs1 -provider $engine_id

	echo "uadk_provider testing SM2"
	openssl speed -provider $engine_id sm2
	openssl speed -provider $engine_id -async_jobs 1 sm2
	#generate keypair
	openssl ecparam -name SM2 -genkey -out sm2.key -provider $engine_id
	#get pubkey
	openssl ec -in sm2.key -pubout -out sm2.pub
	#sign
	echo "Content to be signed" > sign.data
	openssl dgst -provider $engine_id -SM3 -sign sm2.key -out sm2_ec.sig sign.data
	#verify
	openssl dgst -provider $engine_id -SM3 -verify sm2.pub -signature sm2_ec.sig sign.data
	#encrypt
	echo "Content to be encrypted" > plaintext.txt
	openssl pkeyutl -encrypt -in plaintext.txt -out ciphertext.bin -inkey sm2.pub -pubin -provider $engine_id
	#decrypt
	openssl pkeyutl -decrypt -in ciphertext.bin -out plaintext.txt -inkey sm2.key -provider $engine_id
fi

if [[ $keyexch_algs =~ "uadk_provider" ]]; then
	echo "uadk_provider testing dh"

	#1. Generate global public parameters, and save them in the file dhparam.pem:
	openssl dhparam -out dhparam.pem 2048

	#2. Generate own private key:
	openssl genpkey -paramfile dhparam.pem -out privatekey1.pem -provider $engine_id
	openssl genpkey -paramfile dhparam.pem -out privatekey2.pem -provider $engine_id

	#3. Generate public key:
	openssl pkey -in privatekey1.pem -pubout -out publickey1.pem -provider $engine_id
	openssl pkey -in privatekey2.pem -pubout -out publickey2.pem -provider $engine_id

	#4. After exchanging public key, each user can derive the shared secret:
	openssl pkeyutl -derive -inkey privatekey1.pem -peerkey publickey2.pem -out secret1.bin -provider $engine_id
	openssl pkeyutl -derive -inkey privatekey2.pem -peerkey publickey1.pem -out secret2.bin -provider $engine_id

	#5. Check secret1.bin and secret2.bin:
	cmp secret1.bin secret2.bin
	xxd secret1.bin
	xxd secret2.bin
	#secret1.bin and secret2.bin should be same.
fi
