#!/bin/bash

chmod 666 /dev/hisi_*

if [ ! -n "$1" ]; then
	engine_id=uadk_engine
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
	openssl speed -engine $engine_id -evp sha224
	openssl speed -engine $engine_id -async_jobs 1 -evp sha224
	openssl speed -engine $engine_id -evp sha256
	openssl speed -engine $engine_id -async_jobs 1 -evp sha256
	openssl speed -engine $engine_id -evp sha384
	openssl speed -engine $engine_id -async_jobs 1 -evp sha384
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

if [[ $algs =~ "SM4-CBC" ]]; then
	echo "testing SM4-CBC"
	openssl speed -engine $engine_id -evp sm4-cbc
	openssl speed -engine $engine_id -async_jobs 1 -evp sm4-cbc
fi

if [[ $algs =~ "SM4-ECB" ]]; then
	echo "testing SM4-ECB"
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

#ecdsa only supported in Kunpeng930 or later
if [[ $algs =~ "id-ecPublicKey" ]]; then
	echo "testing ECDSA"
	openssl speed -elapsed -engine $engine_id ecdsap224
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdsap224
	openssl speed -elapsed -engine $engine_id ecdsap256
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdsap256
	openssl speed -elapsed -engine $engine_id ecdsap384
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdsap384
	openssl speed -elapsed -engine $engine_id ecdsap521
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdsap521
fi

#X25519 only supported in Kunpeng930 or later
if [[ $algs =~ "X25519" ]]; then
	echo "testing X25519"
	openssl speed -elapsed -engine $engine_id ecdhx25519
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdhx25519
fi

#X448 only supported in Kunpeng930 or later
if [[ $algs =~ "X448" ]]; then
	echo "testing X448"
	openssl speed -elapsed -engine $engine_id ecdhx448
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdhx448
fi

#ecdh only supported in Kunpeng930 or later
if [[ $algs =~ "id-ecPublicKey" ]]; then
	echo "testing ECDH"
	openssl speed -elapsed -engine $engine_id ecdhp192
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdhp192
	openssl speed -elapsed -engine $engine_id ecdhp224
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdhp224
	openssl speed -elapsed -engine $engine_id ecdhp256
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdhp256
	openssl speed -elapsed -engine $engine_id ecdhp384
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdhp384
	openssl speed -elapsed -engine $engine_id ecdhp521
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdhp521
	openssl speed -elapsed -engine $engine_id ecdhbrp384r1
	openssl speed -elapsed -engine $engine_id -async_jobs 1 ecdhbrp384r1
fi
