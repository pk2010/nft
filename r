#!/bin/bash
nft flush ruleset
rmmod nft_nat
rmmod nft_masq_ipv4
rmmod nf_nat_masquerade_ipv4
rmmod nft_masq
rmmod nft_hash
rmmod nft_rbtree
rmmod nft_chain_nat_ipv4
rmmod nf_conntrack_ipv4
rmmod nf_defrag_ipv4
rmmod nf_nat_ipv4
rmmod nf_nat
rmmod nf_conntrack
rmmod nf_tables_ipv4
rmmod nf_tables
rmmod nfnetlink
rmmod nf_conntrack_ipv4
rmmod nf_defrag_ipv4
rmmod nf_conntrack
