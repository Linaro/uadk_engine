
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

## Release
Basically two releases each year, like in May and November.\
Tag x.y, and x.y+1 is for release, while x.y.z is for major bug fix.\
In the meantime, ReleaseNotes is required describing release contents.\
ReleasesNotes:\
Generals:\
Features:\
Fixes:

## Main maintainers

```
Zhangfei Gao <zhangfei.gao@linaro.org>
Zhou Wang <wangzhou1@hisilicon.com>
Zhiqi Song <songzhiqi1@huawei.com>
```
