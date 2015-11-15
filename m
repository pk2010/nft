#!/bin/bash
export LIBNFTNL_LIBS="-L/root/nft/libnftnl/src/.libs -lnftnl"
export LIBNFTNL_CFLAGS=-I/root/nft/libnftnl/include

cd /root/nft/libnftnl
sh autogen.sh
./configure
make -j 16

cd /root/nft/nftables
sh autogen.sh
./configure
make -j 16


IPUGLY=`hostname -I`
IPCLEAN="$(echo -e "${IPUGLY}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

if [ ! -f /root/nft/pkt/interface.h ]; then
  IFS='.' read -r -a array <<< "$IPCLEAN";
  echo "#define MYIP ( ${array[0]}U,${array[1]}U,${array[2]}U,${array[3]}U ) " > /root/nft/pkt/interface.h
fi

make -j 16 -C /lib/modules/`uname -r`/build M=/root/nft/net/ipv4/netfilter modules
make -j 16 -C /lib/modules/`uname -r`/build KBUILD_EXTRA_SYMBOLS=/root/nft/net/ipv4/netfilter/Module.symvers M=/root/nft/net/netfilter modules
