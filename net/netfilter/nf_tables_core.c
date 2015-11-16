/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_log.h>


#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include "../../pkt/settings.h"
#include "../../pkt/map.h"

atomic_t atreadport=ATOMIC_INIT(0);
char kernbuf[KERNBUFSIZE];
mapdtype maps[65536];
spinlock_t maplock[65536];
unsigned long maplockflag[65536];
uint32_t maskset[33];

struct task_struct *cpstracker;
atomic_t pkt_numsyn[65536];
atomic_t pkt_cps[65536];
atomic_t pkt_activecon[65536];
EXPORT_SYMBOL(pkt_activecon);
u32 pkt_serverip;
EXPORT_SYMBOL(pkt_serverip);

bool iphasaccess(mapdtype m,uint32_t ip)
{
  int itr=0;
  if(m.allowall)return true;
  while(m.allowedips[itr].ip!=0){if(m.allowedips[itr].ip == (ip & maskset[m.allowedips[itr].mask])) return true;itr++;}
  return false;
}

ssize_t fetchdata(struct file* file, const char __user* buf, size_t size, loff_t* pos)
{
    int itr=0;
	unsigned long notcopied;
	mapcontainerdtype * cont;

	notcopied = copy_from_user(kernbuf, buf, size);
	if(notcopied){printk("Unlikely copy_from_user %lu/%zu failed\n",notcopied,size);}
	cont = (mapcontainerdtype *) buf;
	if(cont->cmd == 11) atomic_set(&atreadport,(int)cont->r1);
	if(cont->cmd==255){
		//printk("Clear command obtained for range %u - %u.\n",cont->r1,cont->r2);
		for(itr=cont->r1;itr<=cont->r2;itr++){
			spin_lock_irqsave(&maplock[itr],maplockflag[itr]);
			memset(&maps[itr],0,sizeof(mapdtype));
			spin_unlock_irqrestore(&maplock[itr],maplockflag[itr]);
		}
	}

	spin_lock_irqsave(&maplock[cont->port],maplockflag[cont->port]);
	maps[cont->port] = cont->map;
	spin_unlock_irqrestore(&maplock[cont->port],maplockflag[cont->port]);
	return size;
}

static int proc_show(struct seq_file *m, void *v) {
int itr=0;
int readport = atomic_read(&atreadport);
	spin_lock_irqsave(&maplock[readport],maplockflag[readport]);
	if(maps[readport].dip==0) {seq_printf(m,"%d : No Data",readport);goto fin;}
	seq_printf(m,"%d %d.%d.%d.%d:%u %d/%u %d",readport,NIPQUAD(maps[readport].dip),maps[readport].dport,atomic_read(&pkt_activecon[readport]),maps[readport].maxconn,atomic_read(&pkt_cps[readport]));

	for(itr=0;itr<MAXALLIPS;itr++)
	{
		if(maps[readport].allowedips[itr].ip==0) break;
		seq_printf(m," %d.%d.%d.%d/%d",NIPQUAD(maps[readport].allowedips[itr].ip),maps[readport].allowedips[itr].mask);
	}
fin:
	seq_printf(m,"\n");
	spin_unlock_irqrestore(&maplock[readport],maplockflag[readport]);
	return 0;
}

static int proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, proc_show, NULL);
}

static const struct file_operations proc_fops = {
  .owner = THIS_MODULE,
  .open = proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = single_release,
  .write = fetchdata,
};

int cpstracker_th(void *data){
int i,k;
	while(!kthread_should_stop()){
		schedule();
		msleep(1000);
		for(i=0;i<65536;i++){
			k=atomic_read(&pkt_numsyn[i]);
			atomic_set(&pkt_cps[i],k);
			atomic_set(&pkt_numsyn[i],0);
		}
	}
return 0;
}


enum nft_trace {
	NFT_TRACE_RULE,
	NFT_TRACE_RETURN,
	NFT_TRACE_POLICY,
};

static const char *const comments[] = {
	[NFT_TRACE_RULE]	= "rule",
	[NFT_TRACE_RETURN]	= "return",
	[NFT_TRACE_POLICY]	= "policy",
};

static struct nf_loginfo trace_loginfo = {
	.type = NF_LOG_TYPE_LOG,
	.u = {
		.log = {
			.level = LOGLEVEL_WARNING,
			.logflags = NF_LOG_MASK,
	        },
	},
};

static void __nft_trace_packet(const struct nft_pktinfo *pkt,
			       const struct nft_chain *chain,
			       int rulenum, enum nft_trace type)
{
	struct net *net = dev_net(pkt->in ? pkt->in : pkt->out);

	nf_log_trace(net, pkt->xt.family, pkt->ops->hooknum, pkt->skb, pkt->in,
		     pkt->out, &trace_loginfo, "TRACE: %s:%s:%s:%u ",
		     chain->table->name, chain->name, comments[type],
		     rulenum);
}

static inline void nft_trace_packet(const struct nft_pktinfo *pkt,
				    const struct nft_chain *chain,
				    int rulenum, enum nft_trace type)
{
	if (unlikely(pkt->skb->nf_trace))
		__nft_trace_packet(pkt, chain, rulenum, type);
}

static void nft_cmp_fast_eval(const struct nft_expr *expr,
			      struct nft_regs *regs)
{
	const struct nft_cmp_fast_expr *priv = nft_expr_priv(expr);
	u32 mask = nft_cmp_fast_mask(priv->len);

	if ((regs->data[priv->sreg] & mask) == priv->data)
		return;
	regs->verdict.code = NFT_BREAK;
}

static bool nft_payload_fast_eval(const struct nft_expr *expr,
				  struct nft_regs *regs,
				  const struct nft_pktinfo *pkt)
{
	const struct nft_payload *priv = nft_expr_priv(expr);
	const struct sk_buff *skb = pkt->skb;
	u32 *dest = &regs->data[priv->dreg];
	unsigned char *ptr;

	if (priv->base == NFT_PAYLOAD_NETWORK_HEADER)
		ptr = skb_network_header(skb);
	else
		ptr = skb_network_header(skb) + pkt->xt.thoff;

	ptr += priv->offset;

	if (unlikely(ptr + priv->len >= skb_tail_pointer(skb)))
		return false;

	*dest = 0;
	if (priv->len == 2)
		*(u16 *)dest = *(u16 *)ptr;
	else if (priv->len == 4)
		*(u32 *)dest = *(u32 *)ptr;
	else
		*(u8 *)dest = *(u8 *)ptr;
	return true;
}

struct nft_jumpstack {
	const struct nft_chain	*chain;
	const struct nft_rule	*rule;
	int			rulenum;
};

unsigned int
nft_do_chain(struct nft_pktinfo *pkt, const struct nf_hook_ops *ops)
{
	const struct nft_chain *chain = ops->priv, *basechain = chain;
	const struct net *net = dev_net(pkt->in ? pkt->in : pkt->out);
	const struct nft_rule *rule;
	const struct nft_expr *expr, *last;
	struct nft_regs regs;
	unsigned int stackptr = 0;
	struct nft_jumpstack jumpstack[NFT_JUMP_STACK_SIZE];
	struct nft_stats *stats;
	int rulenum;
	unsigned int gencursor = nft_genmask_cur(net);

do_chain:
	rulenum = 0;
	rule = list_entry(&chain->rules, struct nft_rule, list);
next_rule:
	regs.verdict.code = NFT_CONTINUE;
	list_for_each_entry_continue_rcu(rule, &chain->rules, list) {

		/* This rule is not active, skip. */
		if (unlikely(rule->genmask & (1 << gencursor)))
			continue;

		rulenum++;

		nft_rule_for_each_expr(expr, last, rule) {
			if (expr->ops == &nft_cmp_fast_ops)
				nft_cmp_fast_eval(expr, &regs);
			else if (expr->ops != &nft_payload_fast_ops ||
				 !nft_payload_fast_eval(expr, &regs, pkt))
				expr->ops->eval(expr, &regs, pkt);

			if (regs.verdict.code != NFT_CONTINUE)
				break;
		}

		switch (regs.verdict.code) {
		case NFT_BREAK:
			regs.verdict.code = NFT_CONTINUE;
			continue;
		case NFT_CONTINUE:
			nft_trace_packet(pkt, chain, rulenum, NFT_TRACE_RULE);
			continue;
		}
		break;
	}

	switch (regs.verdict.code & NF_VERDICT_MASK) {
	case NF_ACCEPT:
	case NF_DROP:
	case NF_QUEUE:
		nft_trace_packet(pkt, chain, rulenum, NFT_TRACE_RULE);
		return regs.verdict.code;
	}

	switch (regs.verdict.code) {
	case NFT_JUMP:
		BUG_ON(stackptr >= NFT_JUMP_STACK_SIZE);
		jumpstack[stackptr].chain = chain;
		jumpstack[stackptr].rule  = rule;
		jumpstack[stackptr].rulenum = rulenum;
		stackptr++;
		/* fall through */
	case NFT_GOTO:
		nft_trace_packet(pkt, chain, rulenum, NFT_TRACE_RULE);

		chain = regs.verdict.chain;
		goto do_chain;
	case NFT_CONTINUE:
		rulenum++;
		/* fall through */
	case NFT_RETURN:
		nft_trace_packet(pkt, chain, rulenum, NFT_TRACE_RETURN);
		break;
	default:
		WARN_ON(1);
	}

	if (stackptr > 0) {
		stackptr--;
		chain = jumpstack[stackptr].chain;
		rule  = jumpstack[stackptr].rule;
		rulenum = jumpstack[stackptr].rulenum;
		goto next_rule;
	}

	nft_trace_packet(pkt, basechain, -1, NFT_TRACE_POLICY);

	rcu_read_lock_bh();
	stats = this_cpu_ptr(rcu_dereference(nft_base_chain(basechain)->stats));
	u64_stats_update_begin(&stats->syncp);
	stats->pkts++;
	stats->bytes += pkt->skb->len;
	u64_stats_update_end(&stats->syncp);
	rcu_read_unlock_bh();

	return nft_base_chain(basechain)->policy;
}
EXPORT_SYMBOL_GPL(nft_do_chain);

int __init nf_tables_core_module_init(void)
{
	int err;

	int itr;
	for(itr=0;itr<65536;itr++){spin_lock_init(&maplock[itr]);pkt_activecon[itr].counter=0;maplockflag[itr]=0;pkt_numsyn[itr].counter=0;pkt_cps[itr].counter=0;}
	memset(kernbuf,0,KERNBUFSIZE);
	memset(maps,0,sizeof(mapdtype)*65536);
	proc_create(PROCFS_NAME, 0644, NULL, &proc_fops);
    for(itr=0;itr<33;itr++) maskset[itr] = 4294967295 >> (32-itr);
	cpstracker = kthread_run(&cpstracker_th,(void *)0,"cpstracker");
	
	err = nft_immediate_module_init();
	if (err < 0)
		goto err1;

	err = nft_cmp_module_init();
	if (err < 0)
		goto err2;

	err = nft_lookup_module_init();
	if (err < 0)
		goto err3;

	err = nft_bitwise_module_init();
	if (err < 0)
		goto err4;

	err = nft_byteorder_module_init();
	if (err < 0)
		goto err5;

	err = nft_payload_module_init();
	if (err < 0)
		goto err6;

	err = nft_dynset_module_init();
	if (err < 0)
		goto err7;

	return 0;

err7:
	nft_payload_module_exit();
err6:
	nft_byteorder_module_exit();
err5:
	nft_bitwise_module_exit();
err4:
	nft_lookup_module_exit();
err3:
	nft_cmp_module_exit();
err2:
	nft_immediate_module_exit();
err1:
	return err;
}

void nf_tables_core_module_exit(void)
{
	kthread_stop(cpstracker);
	remove_proc_entry(PROCFS_NAME, NULL);
	
	nft_dynset_module_exit();
	nft_payload_module_exit();
	nft_byteorder_module_exit();
	nft_bitwise_module_exit();
	nft_lookup_module_exit();
	nft_cmp_module_exit();
	nft_immediate_module_exit();
}
