
# Contributor's Guide

## Getting Started

Clone UADK from [Github](https://github.com/Linaro/uadk).

Clone openssl-uadk from [Github](https://github.com/Linaro/openssl-uadk).

## License

Adopt Apache License 2.0.

## Coding Style

Adopt linux kernel coding style, so check with linux/scripts/checkpatch.pl

## Making Changes

```
Make patches
linux/scripts/checkpatch.pl *.patch
sudo test/sanity_test.sh
```

## Main maintainers

```
Zhangfei Gao <zhangfei.gao@linaro.org>
Zhou Wang <wangzhou1@hisilicon.com>
Hui Tang <tanghui20@huawei.com>
```
