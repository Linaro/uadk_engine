# uadk-engine

## Build

Build as follows:

```
$ autoreconf -i
$ ./configure
$ make
$ sudo make install
```

This will configure, build and install the package in a default location,
which is `/usr/local/lib`. It means that the uadk.so will be installed in
`/usr/local/lib/uadk.so` by default. If you want to install it anywhere
else, run "configure" passing the new location via prefix argument, for
example:

```
$ ./configure --libdir=/usr/local/lib/engines-1.1/
```


## Test
```
$ openssl engine -t uadk
```
