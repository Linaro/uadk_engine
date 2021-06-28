#!/bin/bash

chmod 666 /dev/hisi_*

if [ ! -n "$1" ]; then
	engine_id=uadk
else
	engine_id=$1
fi

algs=$(openssl engine -c $engine_id)
echo $algs

#digest
if [[ $algs =~ "MD5" ]]; then
	echo "testing MD5"
	openssl speed -engine $engine_id -evp md5
	openssl speed -engine $engine_id -async_jobs 1 -evp md5
fi

if [[ $algs =~ "SM3" ]]; then
	echo "testing SM3"
	openssl speed -engine $engine_id -evp sm3
	openssl speed -engine $engine_id -async_jobs 1 -evp sm3
fi

if [[ $algs =~ "SHA" ]]; then
	echo "testing SHA"
	openssl speed -engine $engine_id -evp sha1
	openssl speed -engine $engine_id -async_jobs 1 -evp sha1
	openssl speed -engine $engine_id -evp sha256
	openssl speed -engine $engine_id -async_jobs 1 -evp sha256
	openssl speed -engine $engine_id -evp sha512
	openssl speed -engine $engine_id -async_jobs 1 -evp sha512
fi

#cipher

if [[ $algs =~ "AES" ]]; then
	echo "testing AES"
	openssl speed -engine $engine_id -evp aes-128-cbc
	openssl speed -engine $engine_id -async_jobs 1 -evp aes-128-cbc
	openssl speed -engine $engine_id -evp aes-192-cbc
	openssl speed -engine $engine_id -async_jobs 1 -evp aes-192-cbc
	openssl speed -engine $engine_id -evp aes-256-cbc
	openssl speed -engine $engine_id -async_jobs 1 -evp aes-256-cbc
	openssl speed -engine $engine_id -evp aes-128-ecb
	openssl speed -engine $engine_id -async_jobs 1 -evp aes-128-ecb
	openssl speed -engine $engine_id -evp aes-192-ecb
	openssl speed -engine $engine_id -async_jobs 1 -evp aes-192-ecb
	openssl speed -engine $engine_id -evp aes-256-ecb
	openssl speed -engine $engine_id -async_jobs 1 -evp aes-256-ecb
	openssl speed -engine $engine_id -evp aes-128-xts
	openssl speed -engine $engine_id -async_jobs 1 -evp aes-128-xts
	openssl speed -engine $engine_id -evp aes-256-xts
	openssl speed -engine $engine_id -async_jobs 1 -evp aes-256-xts
fi

if [[ $algs =~ "SM4" ]]; then
	echo "testing SM4"
	openssl speed -engine $engine_id -evp sm4-cbc
	openssl speed -engine $engine_id -async_jobs 1 -evp sm4-cbc
	openssl speed -engine $engine_id -evp sm4-ecb
	openssl speed -engine $engine_id -async_jobs 1 -evp sm4-ecb
fi

if [[ $algs =~ "DES" ]]; then
	echo "testing DES"
	openssl speed -engine $engine_id -evp des-ede3-cbc
	openssl speed -engine $engine_id -async_jobs 1 -evp des-ede3-cbc
	openssl speed -engine $engine_id -evp des-ede3-ecb
	openssl speed -engine $engine_id -async_jobs 1 -evp des-ede3-ecb
fi

#rsa
if [[ $algs =~ "RSA" ]]; then
	echo "testing RSA"
	openssl speed -elapsed -engine $engine_id rsa1024
	openssl speed -elapsed -engine $engine_id -async_jobs 1 rsa1024
	openssl speed -elapsed -engine $engine_id rsa2048
	openssl speed -elapsed -engine $engine_id -async_jobs 1 rsa2048
	openssl speed -elapsed -engine $engine_id rsa4096
	openssl speed -elapsed -engine $engine_id -async_jobs 1 rsa4096
fi

#sm2 only supported in Kunpeng930 or later
if [[ $algs =~ "SM2" ]]; then
	echo "testing SM2"
	openssl speed -elapsed -engine $engine_id sm2
	openssl speed -elapsed -engine $engine_id -async_jobs 1 sm2
fi

#ecdsa only supported in Kunpeng930 or later
if [[ $algs =~ "ECDSA" ]]; then
	echo "testing ECDSA"
	openssl speed -elapsed -engine $engine_id ecdsap224
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdsap224
	openssl speed -elapsed -engine $engine_id ecdsap256
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdsap256
	openssl speed -elapsed -engine $engine_id ecdsap384
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdsap384
	openssl speed -elapsed -engine $engine_id ecdsap512
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdsap512
fi
