#!/bin/bash
export LIBNFTNL_LIBS="-L/root/nft/libnftnl/src/.libs -lnftnl"
export LIBNFTNL_CFLAGS=-I/root/nft/libnftnl/include

cd /root/nft/libnftnl
if [ ! -f /root/nft/libnftnl/configure ]; then
sh autogen.sh
fi
if [ ! -f /root/nft/libnftnl/Makefile ]; then
./configure
fi
make -j 16

cd /root/nft/nftables
if [ ! -f /root/nft/nftables/configure ]; then
sh autogen.sh
fi
if [ ! -f /root/nft/nftables/Makefile ]; then
./configure
fi
make -j 16


IPUGLY=`hostname -I`
IPCLEAN="$(echo -e "${IPUGLY}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

if [ ! -f /root/nft/pkt/interface.h ]; then
  IFS='.' read -r -a array <<< "$IPCLEAN";
  echo "#define MYIP ( ${array[0]}U,${array[1]}U,${array[2]}U,${array[3]}U ) " > /root/nft/pkt/interface.h
fi

make -j 16 -C /lib/modules/`uname -r`/build M=/root/nft/net/ipv4/netfilter modules
make -j 16 -C /lib/modules/`uname -r`/build KBUILD_EXTRA_SYMBOLS=/root/nft/net/ipv4/netfilter/Module.symvers M=/root/nft/net/netfilter modules

rm -f /root/nft/cli/pkfmap
gcc -o /root/nft/cli/pkfmap /root/nft/cli/pkfmap.c
rm -f /root/nft/cli/pkread
gcc -o /root/nft/cli/pkread /root/nft/cli/pkread.c

