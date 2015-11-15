#!/bin/bash
echo "NET/"
ls -l /lib/modules/`uname -r`/kernel/net/
echo "NET/IPv4/"
ls -l /lib/modules/`uname -r`/kernel/net/ipv4/
ls -l /usr/sbin/iptables*
ls -l /lib64/libnftnl*
ls -l /usr/sbin/nft
cat /proc/sys/net/ipv4/ip_local_port_range
