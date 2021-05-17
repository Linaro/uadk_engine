#!/bin/bash

chmod 666 /dev/hisi_*

algs=$(openssl engine -c uadk)
echo $algs

#digest
if [[ $algs =~ "MD5" ]]; then
	echo "testing MD5"
	openssl speed -engine uadk -evp md5
	openssl speed -engine uadk -async_jobs 1 -evp md5
fi

if [[ $algs =~ "SM3" ]]; then
	echo "testing SM3"
	openssl speed -engine uadk -evp sm3
	openssl speed -engine uadk -async_jobs 1 -evp sm3
fi

if [[ $algs =~ "SHA" ]]; then
	echo "testing SHA"
	openssl speed -engine uadk -evp sha1
	openssl speed -engine uadk -async_jobs 1 -evp sha1
	openssl speed -engine uadk -evp sha256
	openssl speed -engine uadk -async_jobs 1 -evp sha256
	openssl speed -engine uadk -evp sha512
	openssl speed -engine uadk -async_jobs 1 -evp sha512
fi

#cipher

if [[ $algs =~ "AES" ]]; then
	echo "testing AES"
	openssl speed -engine uadk -evp aes-128-cbc
	openssl speed -engine uadk -async_jobs 1 -evp aes-128-cbc
	openssl speed -engine uadk -evp aes-192-cbc
	openssl speed -engine uadk -async_jobs 1 -evp aes-192-cbc
	openssl speed -engine uadk -evp aes-256-cbc
	openssl speed -engine uadk -async_jobs 1 -evp aes-256-cbc
	openssl speed -engine uadk -evp aes-128-ecb
	openssl speed -engine uadk -async_jobs 1 -evp aes-128-ecb
	openssl speed -engine uadk -evp aes-192-ecb
	openssl speed -engine uadk -async_jobs 1 -evp aes-192-ecb
	openssl speed -engine uadk -evp aes-256-ecb
	openssl speed -engine uadk -async_jobs 1 -evp aes-256-ecb
	openssl speed -engine uadk -evp aes-128-xts
	openssl speed -engine uadk -async_jobs 1 -evp aes-128-xts
	openssl speed -engine uadk -evp aes-256-xts
	openssl speed -engine uadk -async_jobs 1 -evp aes-256-xts
fi

if [[ $algs =~ "SM4" ]]; then
	echo "testing SM4"
	openssl speed -engine uadk -evp sm4-cbc
	openssl speed -engine uadk -async_jobs 1 -evp sm4-cbc
	openssl speed -engine uadk -evp sm4-ecb
	openssl speed -engine uadk -async_jobs 1 -evp sm4-ecb
fi

if [[ $algs =~ "DES" ]]; then
	echo "testing DES"
	openssl speed -engine uadk -evp des-ede3-cbc
	openssl speed -engine uadk -async_jobs 1 -evp des-ede3-cbc
	openssl speed -engine uadk -evp des-ede3-ecb
	openssl speed -engine uadk -async_jobs 1 -evp des-ede3-ecb
fi

#rsa
if [[ $algs =~ "RSA" ]]; then
	echo "testing RSA"
	openssl speed -elapsed -engine uadk rsa1024
	openssl speed -elapsed -engine uadk -async_jobs 1 rsa1024
	openssl speed -elapsed -engine uadk rsa2048
	openssl speed -elapsed -engine uadk -async_jobs 1 rsa2048
	openssl speed -elapsed -engine uadk rsa4096
	openssl speed -elapsed -engine uadk -async_jobs 1 rsa4096
fi
