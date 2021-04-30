Build and Install
=================

This document describes installation of OpenSSL UADK.

Table of Contents
=================

- [Prerequisites](#prerequisites)
- [Installation Instruction](#installation-instruction)
	- [Build & Install OpenSSL](#build-&-install-openssl)
	- [Build & Install UADK](#build-&-install-uadk)
	- [Build & Install OpenSSL UADK engine](#build-&-install-openssl-uadk-engine)
	- [Testing](#testing)

Prerequisites
=============
* CPU:
	* aarch64
* OpenSSL:
	* 1.1.1a

Installation Instruction
========================

Build & Install OpenSSL
-----------------------

1. clone OpenSSL from Github:

    URL https://github.com/openssl/openssl/tree/OpenSSL_1_1_1a
```
    cd ~
    git clone https://github.com/openssl/openssl.git
    cd openssl
    git tag
    git checkout -b  OpenSSL_1_1_1a OpenSSL_1_1_1a
```
2. build and install OpenSSL:
```
    cd openssl
    ./config -Wl,-rpath=/usr/local/lib
    make
    make test
    sudo make install
```
 * Make sure you have installed gcc (Development tools kit), perl-core, zlib-devel before doing configuration.
 * Use "openssl version" to check the install result.
 * If you have installed older openssl, use follwing operations to update:
```
    mv /usr/bin/openssl /usr/bin/openssl.bak
    mv /usr/include/openssl /usr/include/openssl.bak
    ln -s /usr/local/bin/openssl /usr/bin/openssl
    ln -s /usr/local/include/openssl /usr/include/openssl
    echo "/usr/local/lib" >> /etc/ld.so.conf
    ldconfig -v
    openssl version
```

Build & Install UADK
--------------------

1. clone UADK frome Github:

    URL https://github.com/Linaro/uadk
```
    git clone https://github.com/Linaro/uadk.git
```
2. build and install UADK:
```
    cd uadk
    ./cleanup.sh
    ./autogen.sh
    ./conf.sh
    make
    sudo make install
```
 * If you meet the error:"cannot find -lnuma", please make sure you have installed the following libs:
	- libnuma-dev
	- numactl-devel.aarch64
	- numactl-libs.aarch64
	- numad.aarch64
	- numactl.aarch64
* If you meet the error:"fetal error: zlib.h: No such file or directory",please make sure you have installed the following libs:
	- zlib-devel.aarch64
	- zlib.aarch64
* You can use "yum install" or "apt-get install" instructions to install above libs.

Build & Install OpenSSL UADK Engine
-----------------------------------
1. clone OpenSSL UADK Engine from Github:

    URL https://github.com/Linaro/openssl-uadk
```
    git clone https://github.com/Linaro/openssl-uadk.git
```
2. build and install OpenSSL UADK Engine:
```
    cd openssl-uadk
    autoreconf -i
    ./configure --libdir=/usr/local/lib/engines-1.1/
    make
    sudo make install
```
 * Note: the version of glibc need >= 2.23.
 * If you meet the error "link failed: Bad Value" when you build OpenSSL UADK, please upgrade your glibc version.
 * After these steps, you will get:
    - /usr/local/lib/libssl.so
    - /usr/local/lib/libwd.so
    - /usr/local/lib/libwd_crypto.so
    - /usr/local/lib/libhisi_zip.so
    - /usr/local/lib/libhisi_hpre.so
    - /usr/local/lib/libhisi_sec.so
    - /usr/local/lib/engines-1.1/uadk.so

Testing
-------

1. Cipher
```
openssl enc -aes-128-cbc -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-128-cbc -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p -nopad
openssl enc -aes-192-cbc -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-192-cbc -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p -nopad
openssl enc -aes-256-cbc -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-256-cbc -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p -nopad
openssl enc -aes-128-ecb -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-128-ecb -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-192-ecb -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-192-ecb -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-256-ecb -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-256-ecb -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-128-ctr -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-128-ctr -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p -nopad
openssl enc -aes-192-ctr -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-192-ctr -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p -nopad
openssl enc -aes-256-ctr -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -aes-256-ctr -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p -nopad
openssl enc -sm4-cbc -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -sm4-cbc -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p -nopad
openssl enc -sm4-ecb -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -sm4-ecb -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -des-ede3-cbc -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -des-ede3-cbc -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p -nopad
openssl enc -des-ede3-ecb -a -in data -out data.en -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl enc -des-ede3-ecb -a -d -in data.en -out data.de -pass pass:123456  -K abc -iv abc -engine uadk -p
openssl speed -engine uadk -async_jobs 1 -evp aes-128-cbc
openssl speed -engine uadk -async_jobs 1 -evp sm4-cbc
openssl speed -engine uadk -async_jobs 1 -evp des-ede3-cbc
```
2. RSA
```
openssl genrsa -out prikey.pem -engine uadk 2048
openssl rsa -in prikey.pem -pubout -out pubkey.pem -engine uadk
openssl rsautl -encrypt -in plain.txt -inkey pubkey.pem -pubin -out enc.txt -engine uadk
openssl rsautl -decrypt -in enc.txt -inkey prikey.pem -out dec.txt -engine uadk
openssl rsautl -sign -in msg.txt -inkey prikey.pem -out sgined.txt -engine uadk
openssl rsautl -verify -in signed.txt -inkey pubkey.pem -pubin -out verified.txt -engine uadk
openssl speed -elapsed -engine uadk rsa2048
openssl speed -elapsed -engine uadk -async_jobs 10 rsa2048
```
3. SM3
```
openssl sm3 -engine uadk data
```
4. MD5
```
openssl speed -engine uadk -async_jobs 1 -evp md5
```
5. SHA
```
openssl sha1 -engine uadk data
openssl sha256 -engine uadk data
openssl sha512 -engine uadk data
```
