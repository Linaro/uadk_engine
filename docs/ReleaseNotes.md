
# UADK engine Release v1.7 Dec 2025

## New Features
- Provider: Added log configuration functionality with three levels
            (err, debug, info), configurable to output to a specified file.
- Provider: Supports dynamic enabling/disabling of algorithms via
            configuration file (dynamic algorithm cropping).
- Provider: Add support for multiple RSA padding modes
  - RSA_X931_PADDING and RSA_PKCS1_PSS_PADDING for signing and verification
  - RSA_PKCS1_OAEP_PADDING and RSA_PKCS1_WITH_TLS_PADDING for encryption
    and decryption.
- Added CI configuration.

## Fixes
- Engine: Fixed incorrect use of V2 interface in no-sva mode
- Provider: Fixed potential segmentation fault during encryption
            when ctx is not null-checked.
- Provider/sm2: Resolved SM2 authentication failure by ensuring
                the default ID is used in hardware calculations.
- Engine: Fixed DH shared secret key comparison failure
          by correctly padding high-order zeros.
- Engine: Optimized sec cipher and digest initialization to
          reduce redundant calls.

## Working combination

- UADK v2.10
- OpenSSL 1.1.1f & OpenSSL 3.0+


# UADK engine Release v1.6 June 2025

## New Features
- Provider: Support rsa digest interface.
- Provider: Add switching software computation function
- Provider: Support aead, x448, x25519 and ecdsa algorithms
- Provider: Support HMAC mode for digest

## Fixes
- Fix async issue when hardware error occurs
- Fix async packet reception timeout error

## Working combination

- UADK v2.9
- OpenSSL 1.1.1f & OpenSSL 3.0+


# UADK engine Release v1.5 Dec 2024

## New Features
- Support SM2 asymmetric algorithm with openssl 3.0 provider mechanism.
- Support processing single diesgt block function with openssl 3.0 provider mechanism.
- Support AES CTS alg with openssl 3.0 provider mechanism.

## Fixes
- Refactor uadk_provider DH implementation with unified data structure and FFC \
  extended functions.
- Add different AES algorithm key bit width specifications in the uadk_provider.
- For digest algorithms, for both uadk_engine and uadk_provider, increasing the \
  amount of data delivered to the hardware at a time to reduce the number of interactions.
- Fix bio fseek() suspending problem in uadk_provider.
- Fix an async problem: wake up async_poll_process_func before free async_poll_task_free.
- Fix cipher issue when input len is 0 in decrypto update.
- Fix the key and IV verification methods for cipher init.
- Remove update iv for cipher, as the iv has been updated by the UADK.

## Working combination

- UADK v2.8
- OpenSSL 1.1.1f & OpenSSL 3.0+


# UADK engine Release v1.4 June 2024

## New Features

## Fixes
- Add evp interface for rsa engine
- Fix padding for cipher provider
- Fix rsa provider in openssl 3.2

## Working combination

- UADK v2.7
- OpenSSL 1.1.1f & OpenSSL 3.0+


# UADK engine Release v1.3 Dec 2023

## New Features
- Support the following hardware acceleration algorithms with openssl 3.0 provider mechanism: \
  RSA, DH \
  AES, SM4 \
  SM3, MD5, SHA1, SHA224, SHA256, SHA384, SHA512

- Build uadk_engine with OpenSSL1.1.1x version, while build uadk_provider with OpenSSL3.x version.
- Support enable uadk_provider via uadk_provider.cnf file.
- Support hardware acceleration AES-GCM in uadk_engine.
- Add sanity_test.sh and correctness test: evp_test.sh for providers

## Fixes
- Add and modify some test cases in sanity_test.sh file.
- Fix some issues related to resources management.

## Working combination

- UADK v2.6
- OpenSSL 1.1.1f & OpenSSL 3.0+


# UADK engine Release v1.2 June 2023

## New Features

## Fixes
- Fixed the repeated alg device queries of ecc.
- Improved the performance of digest and ecc algorithms.

## Working combination

- UADK v2.5
- OpenSSL 1.1.1f


# UADK engine Release v1.1 December 2022

## New Features

- UADK engine consists of five sub-modules: RSA, DH, ECC, Cipher, and Digest.\
  After hardware accelerators from different vendors are registered to UADK general framework,\
  users can use the OpenSSL command line tools or OpenSSL standard interfaces through UADK engine,\
  and finish the computing task with the hardware accelerators.\
  The engine ID is 'uadk_engine'.

- The main features of UADK engine are as follows:
- RSA sub-module.\
  Supports RSA algorithm of 1024/2048/3072/4096-bits key size with standard mode and CRT mode.\
  Provides key generation, asymmetric encryption and decryption, and digital signature functions.
- DH sub-module.\
  Supports DH algorithms of 768/1024/1536/2048/3072/4096-bits key size.\
  Provides key exchange functions.
- ECC sub-module.\
  Supports elliptic-curve cryptography.\
  Provide ECDH/X25519/X448 key exchange, ECDSA elliptic curve digital signature,\
  SM2 digital signature and SM2 asymmetric encryption and decryption functions.
- Cipher sub-module.\
  Supports block cipher algorithms, including AES algorithm with CBC/ECB/CTR/XTS mode,\
  SM4 algorithm with CTR/CBC/ECB/OFB/CFB mode, and 3DES algorithm.\
  Provides symmetric encryption and decryption functions.
- Digest sub-module.\
  Supports MD5/SM3/SHA1/SHA224/SHA256/SHA384/SHA512 algorithms.\
  Provides generating message digest functions and supports digest multiple updates.\
- Supports switching to OpenSSL software method in abnormal cases.
- Supports configuring the engine with an environment variable.

## Fixes

- Fixed uadk engine compatibility problem when using a different mode of UADK.
- Fixed the init status of SM2 and decryption check.
- Fixed the init operation sequence of ECC-related algorithms.
- Improved the digest performance by about 5%.
- Added timeout protection mechanism when doing an asynchronous job.
- Fixed the repeatedly initializing problem, initializing resources only once.

## Working combination

- UADK v2.4
- OpenSSL 1.1.1f
