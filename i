#!/bin/bash
ker=`uname -r`

sysctl -w net.ipv4.ip_local_port_range="65001 65535"

if [ ! -d "/usr/lib/modules/$ker/kernel/net/netfilter_bck" ]; then
  mv /usr/lib/modules/$ker/kernel/net/netfilter /usr/lib/modules/$ker/kernel/net/netfilter_bck;
  ln -s /root/nft/net/netfilter /usr/lib/modules/$ker/kernel/net/netfilter;
else
  echo "/usr/lib/modules/$ker/kernel/net/netfilter_bck already there.Have you uninstalled other version?";
  exit;
fi

if [ ! -d "/usr/lib/modules/$ker/kernel/net/ipv4/netfilter_bck" ]; then
  mv /usr/lib/modules/$ker/kernel/net/ipv4/netfilter /usr/lib/modules/$ker/kernel/net/ipv4/netfilter_bck;
  ln -s /root/nft/net/ipv4/netfilter /usr/lib/modules/$ker/kernel/net/ipv4/netfilter;
else
  echo "/usr/lib/modules/$ker/kernel/net/ipv4/netfilter already there.Have you uninstalled other version?";
  exit;
fi

if [ -L "/usr/sbin/iptables-restore" ]; then
  rm -f /usr/sbin/iptables-restore
else
  echo "/usr/sbin/iptables-restore not there who took it?";
fi
ln -s /root/nft/iptables-restore /usr/sbin/iptables-restore

if [ -L "/usr/sbin/nft" ]; then
  rm -f /usr/sbin/nft
fi
ln -s /root/nft/nftables/src/nft /usr/sbin/nft

if [ -L "/lib64/libnftnl.so.4" ]; then
  rm -f /lib64/libnftnl.so.4
fi
ln -s  /root/nft/libnftnl/src/.libs/libnftnl.so.4 /lib64/libnftnl.so.4
