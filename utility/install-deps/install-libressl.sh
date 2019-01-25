#!/bin/sh

mkdir tmp
cd tmp

#############################################
## download libressl-2.9.0

wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.9.0.tar.gz

#############################################
## clean dir

rm -rf libressl-2.9.0

#############################################
## unpack

tar -xvzf libressl-2.9.0.tar.gz
cd libressl-2.9.0

#############################################
## build and install libressl

cmake .
make
make install
