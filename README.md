cryptomaniac
============

CryptoManiac is a simple command line utility that encrypts a file using AES-256 (CTR/CBC, 256-bit keys, 128-bit IVs) and is compatible with the OpenSSL enc tool.

I wrote this program for fun, mostly while waiting for my laundry during a few really hot summer nights in Brooklyn.

Enjoy!  
http://alinush.org

To build:
=========
```
 $ cd cryptomaniac/
 $ make
```

To test:
========
```
 $ cd cryptomaniac/
 $ make
 $ chmod +x test.sh
 $ ./test.sh
```
