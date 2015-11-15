#!/bin/bash
export LIBNFTNL_LIBS="-L/root/nft/libnftnl/src/.libs -lnftnl"
export LIBNFTNL_CFLAGS=-I/root/nft/libnftnl/include

cd /root/nft/libnftnl
sh autogen.sh
./configure
make

cd /root/nft/nftables
sh autogen.sh
./configure
make
