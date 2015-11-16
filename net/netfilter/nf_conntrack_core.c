/* Connection state tracking for netfilter.  This is separated from,
   but required by, the NAT layer; it can also be used by an iptables
   extension. */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2003,2004 USAGI/WIDE Project <http://www.linux-ipv6.org>
 * (C) 2005-2012 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/mm.h>
#include <linux/nsproxy.h>
#include <linux/rculist_nulls.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_timestamp.h>
#include <net/netfilter/nf_conntrack_timeout.h>
#include <net/netfilter/nf_conntrack_labels.h>
#include <net/netfilter/nf_conntrack_synproxy.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_helper.h>

#define NF_CONNTRACK_VERSION	"0.5.0"

#include <linux/ip.h>
#include "../../pkt/settings.h"
#include "../../pkt/interface.h"
#define CONCAT(A,B)         A ## B
#define EXPAND_CONCAT(A,B)  CONCAT(A, B)
#define ARGN(N, LIST)       EXPAND_CONCAT(ARG_, N) LIST
#define ARG_0(A0, ...)      A0
#define ARG_1(A0, A1, ...)  A1
#define ARG_2(A0, A1, A2, ...)      A2
#define ARG_3(A0, A1, A2, A3, ...)  A3
#define S0 ARGN(0, MYIP)
#define S1 ARGN(1, MYIP)
#define S2 ARGN(2, MYIP)
#define S3 ARGN(3, MYIP)

extern atomic_t pkt_activecon[65536];
extern u32 pkt_serverip;

int (*nfnetlink_parse_nat_setup_hook)(struct nf_conn *ct,
				      enum nf_nat_manip_type manip,
				      const struct nlattr *attr) __read_mostly;
EXPORT_SYMBOL_GPL(nfnetlink_parse_nat_setup_hook);

__cacheline_aligned_in_smp spinlock_t nf_conntrack_locks[CONNTRACK_LOCKS];
EXPORT_SYMBOL_GPL(nf_conntrack_locks);

__cacheline_aligned_in_smp DEFINE_SPINLOCK(nf_conntrack_expect_lock);
EXPORT_SYMBOL_GPL(nf_conntrack_expect_lock);

static void nf_conntrack_double_unlock(unsigned int h1, unsigned int h2)
{
	h1 %= CONNTRACK_LOCKS;
	h2 %= CONNTRACK_LOCKS;
	spin_unlock(&nf_conntrack_locks[h1]);
	if (h1 != h2)
		spin_unlock(&nf_conntrack_locks[h2]);
}

/* return true if we need to recompute hashes (in case hash table was resized) */
static bool nf_conntrack_double_lock(struct net *net, unsigned int h1,
				     unsigned int h2, unsigned int sequence)
{
	h1 %= CONNTRACK_LOCKS;
	h2 %= CONNTRACK_LOCKS;
	if (h1 <= h2) {
		spin_lock(&nf_conntrack_locks[h1]);
		if (h1 != h2)
			spin_lock_nested(&nf_conntrack_locks[h2],
					 SINGLE_DEPTH_NESTING);
	} else {
		spin_lock(&nf_conntrack_locks[h2]);
		spin_lock_nested(&nf_conntrack_locks[h1],
				 SINGLE_DEPTH_NESTING);
	}
	if (read_seqcount_retry(&net->ct.generation, sequence)) {
		nf_conntrack_double_unlock(h1, h2);
		return true;
	}
	return false;
}

static void nf_conntrack_all_lock(void)
{
	int i;

	for (i = 0; i < CONNTRACK_LOCKS; i++)
		spin_lock_nested(&nf_conntrack_locks[i], i);
}

static void nf_conntrack_all_unlock(void)
{
	int i;

	for (i = 0; i < CONNTRACK_LOCKS; i++)
		spin_unlock(&nf_conntrack_locks[i]);
}

unsigned int nf_conntrack_htable_size __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_htable_size);

unsigned int nf_conntrack_max __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_max);

DEFINE_PER_CPU(struct nf_conn, nf_conntrack_untracked);
EXPORT_PER_CPU_SYMBOL(nf_conntrack_untracked);

unsigned int nf_conntrack_hash_rnd __read_mostly;
EXPORT_SYMBOL_GPL(nf_conntrack_hash_rnd);

static u32 hash_conntrack_raw(const struct nf_conntrack_tuple *tuple)
{
	unsigned int n;

	/* The direction must be ignored, so we hash everything up to the
	 * destination ports (which is a multiple of 4) and treat the last
	 * three bytes manually.
	 */
	n = (sizeof(tuple->src) + sizeof(tuple->dst.u3)) / sizeof(u32);
	return jhash2((u32 *)tuple, n, nf_conntrack_hash_rnd ^
		      (((__force __u16)tuple->dst.u.all << 16) |
		      tuple->dst.protonum));
}

static u32 __hash_bucket(u32 hash, unsigned int size)
{
	return reciprocal_scale(hash, size);
}

static u32 hash_bucket(u32 hash, const struct net *net)
{
	return __hash_bucket(hash, net->ct.htable_size);
}

static u_int32_t __hash_conntrack(const struct nf_conntrack_tuple *tuple,
				  unsigned int size)
{
	return __hash_bucket(hash_conntrack_raw(tuple), size);
}

static inline u_int32_t hash_conntrack(const struct net *net,
				       const struct nf_conntrack_tuple *tuple)
{
	return __hash_conntrack(tuple, net->ct.htable_size);
}

bool
nf_ct_get_tuple(const struct sk_buff *skb,
		unsigned int nhoff,
		unsigned int dataoff,
		u_int16_t l3num,
		u_int8_t protonum,
		struct nf_conntrack_tuple *tuple,
		const struct nf_conntrack_l3proto *l3proto,
		const struct nf_conntrack_l4proto *l4proto)
{
	memset(tuple, 0, sizeof(*tuple));

	tuple->src.l3num = l3num;
	if (l3proto->pkt_to_tuple(skb, nhoff, tuple) == 0)
		return false;

	tuple->dst.protonum = protonum;
	tuple->dst.dir = IP_CT_DIR_ORIGINAL;

	return l4proto->pkt_to_tuple(skb, dataoff, tuple);
}
EXPORT_SYMBOL_GPL(nf_ct_get_tuple);

bool nf_ct_get_tuplepr(const struct sk_buff *skb, unsigned int nhoff,
		       u_int16_t l3num, struct nf_conntrack_tuple *tuple)
{
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int protoff;
	u_int8_t protonum;
	int ret;

	rcu_read_lock();

	l3proto = __nf_ct_l3proto_find(l3num);
	ret = l3proto->get_l4proto(skb, nhoff, &protoff, &protonum);
	if (ret != NF_ACCEPT) {
		rcu_read_unlock();
		return false;
	}

	l4proto = __nf_ct_l4proto_find(l3num, protonum);

	ret = nf_ct_get_tuple(skb, nhoff, protoff, l3num, protonum, tuple,
			      l3proto, l4proto);

	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(nf_ct_get_tuplepr);

bool
nf_ct_invert_tuple(struct nf_conntrack_tuple *inverse,
		   const struct nf_conntrack_tuple *orig,
		   const struct nf_conntrack_l3proto *l3proto,
		   const struct nf_conntrack_l4proto *l4proto)
{
	memset(inverse, 0, sizeof(*inverse));

	inverse->src.l3num = orig->src.l3num;
	if (l3proto->invert_tuple(inverse, orig) == 0)
		return false;

	inverse->dst.dir = !orig->dst.dir;

	inverse->dst.protonum = orig->dst.protonum;
	return l4proto->invert_tuple(inverse, orig);
}
EXPORT_SYMBOL_GPL(nf_ct_invert_tuple);

static void
clean_from_lists(struct nf_conn *ct)
{
	pr_debug("clean_from_lists(%p)\n", ct);
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode);
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode);

	/* Destroy all pending expectations */
	nf_ct_remove_expectations(ct);
}

/* must be called with local_bh_disable */
static void nf_ct_add_to_dying_list(struct nf_conn *ct)
{
	struct ct_pcpu *pcpu;

	/* add this conntrack to the (per cpu) dying list */
	ct->cpu = smp_processor_id();
	pcpu = per_cpu_ptr(nf_ct_net(ct)->ct.pcpu_lists, ct->cpu);

	spin_lock(&pcpu->lock);
	hlist_nulls_add_head(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
			     &pcpu->dying);
	spin_unlock(&pcpu->lock);
}

/* must be called with local_bh_disable */
static void nf_ct_add_to_unconfirmed_list(struct nf_conn *ct)
{
	struct ct_pcpu *pcpu;

	/* add this conntrack to the (per cpu) unconfirmed list */
	ct->cpu = smp_processor_id();
	pcpu = per_cpu_ptr(nf_ct_net(ct)->ct.pcpu_lists, ct->cpu);

	spin_lock(&pcpu->lock);
	hlist_nulls_add_head(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
			     &pcpu->unconfirmed);
	spin_unlock(&pcpu->lock);
}

/* must be called with local_bh_disable */
static void nf_ct_del_from_dying_or_unconfirmed_list(struct nf_conn *ct)
{
	struct ct_pcpu *pcpu;

	/* We overload first tuple to link into unconfirmed or dying list.*/
	pcpu = per_cpu_ptr(nf_ct_net(ct)->ct.pcpu_lists, ct->cpu);

	spin_lock(&pcpu->lock);
	BUG_ON(hlist_nulls_unhashed(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode));
	hlist_nulls_del_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode);
	spin_unlock(&pcpu->lock);
}

/* Released via destroy_conntrack() */
struct nf_conn *nf_ct_tmpl_alloc(struct net *net,
				 const struct nf_conntrack_zone *zone,
				 gfp_t flags)
{
	struct nf_conn *tmpl;

	tmpl = kzalloc(sizeof(*tmpl), flags);
	if (tmpl == NULL)
		return NULL;

	tmpl->status = IPS_TEMPLATE;
	write_pnet(&tmpl->ct_net, net);

	if (nf_ct_zone_add(tmpl, flags, zone) < 0)
		goto out_free;

	atomic_set(&tmpl->ct_general.use, 0);

	return tmpl;
out_free:
	kfree(tmpl);
	return NULL;
}
EXPORT_SYMBOL_GPL(nf_ct_tmpl_alloc);

void nf_ct_tmpl_free(struct nf_conn *tmpl)
{
	nf_ct_ext_destroy(tmpl);
	nf_ct_ext_free(tmpl);
	kfree(tmpl);
}
EXPORT_SYMBOL_GPL(nf_ct_tmpl_free);

static void
destroy_conntrack(struct nf_conntrack *nfct)
{
	struct nf_conn *ct = (struct nf_conn *)nfct;
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_l4proto *l4proto;

	pr_debug("destroy_conntrack(%p)\n", ct);
	NF_CT_ASSERT(atomic_read(&nfct->use) == 0);
	NF_CT_ASSERT(!timer_pending(&ct->timeout));

	if (unlikely(nf_ct_is_template(ct))) {
		nf_ct_tmpl_free(ct);
		return;
	}
	rcu_read_lock();
	l4proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), nf_ct_protonum(ct));
	if (l4proto && l4proto->destroy)
		l4proto->destroy(ct);

	rcu_read_unlock();

	local_bh_disable();
	/* Expectations will have been removed in clean_from_lists,
	 * except TFTP can create an expectation on the first packet,
	 * before connection is in the list, so we need to clean here,
	 * too.
	 */
	nf_ct_remove_expectations(ct);

	nf_ct_del_from_dying_or_unconfirmed_list(ct);

	NF_CT_STAT_INC(net, delete);
	local_bh_enable();

	if (ct->master)
		nf_ct_put(ct->master);

	pr_debug("destroy_conntrack: returning ct=%p to slab\n", ct);
	nf_conntrack_free(ct);
}

static void nf_ct_delete_from_lists(struct nf_conn *ct)
{
	struct net *net = nf_ct_net(ct);
	unsigned int hash, reply_hash;
	unsigned int sequence;

	nf_ct_helper_destroy(ct);

	local_bh_disable();
	do {
		sequence = read_seqcount_begin(&net->ct.generation);
		hash = hash_conntrack(net,
				      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		reply_hash = hash_conntrack(net,
					   &ct->tuplehash[IP_CT_DIR_REPLY].tuple);
	} while (nf_conntrack_double_lock(net, hash, reply_hash, sequence));

	clean_from_lists(ct);
	nf_conntrack_double_unlock(hash, reply_hash);

	nf_ct_add_to_dying_list(ct);

	NF_CT_STAT_INC(net, delete_list);
	local_bh_enable();
}

bool nf_ct_delete(struct nf_conn *ct, u32 portid, int report)
{
	struct nf_conn_tstamp *tstamp;

	u32 origdip,origsip;
	u16 origdport,origsport;

	origdip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	origsip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	if (origdip == pkt_serverip){
		origdport = ntohs((u16) ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port);
		origsport = ntohs((u16) ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num);
		atomic_dec(&pkt_activecon[origdport]);
		//printk("--%d.%d.%d.%d:%d > %d.%d.%d.%d:%d[%d]\n",NIPQUAD(origsip),origsport,NIPQUAD(origdip),origdport,atomic_read(&pkt_activecon[origdport]));
	}
	
	tstamp = nf_conn_tstamp_find(ct);
	if (tstamp && tstamp->stop == 0)
		tstamp->stop = ktime_get_real_ns();

	if (nf_ct_is_dying(ct))
		goto delete;

	if (nf_conntrack_event_report(IPCT_DESTROY, ct,
				    portid, report) < 0) {
		/* destroy event was not delivered */
		nf_ct_delete_from_lists(ct);
		nf_conntrack_ecache_delayed_work(nf_ct_net(ct));
		return false;
	}

	nf_conntrack_ecache_work(nf_ct_net(ct));
	set_bit(IPS_DYING_BIT, &ct->status);
 delete:
	nf_ct_delete_from_lists(ct);
	nf_ct_put(ct);
	return true;
}
EXPORT_SYMBOL_GPL(nf_ct_delete);

static void death_by_timeout(unsigned long ul_conntrack)
{
	nf_ct_delete((struct nf_conn *)ul_conntrack, 0, 0);
}

static inline bool
nf_ct_key_equal(struct nf_conntrack_tuple_hash *h,
		const struct nf_conntrack_tuple *tuple,
		const struct nf_conntrack_zone *zone)
{
	struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);

	/* A conntrack can be recreated with the equal tuple,
	 * so we need to check that the conntrack is confirmed
	 */
	return nf_ct_tuple_equal(tuple, &h->tuple) &&
	       nf_ct_zone_equal(ct, zone, NF_CT_DIRECTION(h)) &&
	       nf_ct_is_confirmed(ct);
}

/*
 * Warning :
 * - Caller must take a reference on returned object
 *   and recheck nf_ct_tuple_equal(tuple, &h->tuple)
 */
static struct nf_conntrack_tuple_hash *
____nf_conntrack_find(struct net *net, const struct nf_conntrack_zone *zone,
		      const struct nf_conntrack_tuple *tuple, u32 hash)
{
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	unsigned int bucket = hash_bucket(hash, net);

	/* Disable BHs the entire time since we normally need to disable them
	 * at least once for the stats anyway.
	 */
	local_bh_disable();
begin:
	hlist_nulls_for_each_entry_rcu(h, n, &net->ct.hash[bucket], hnnode) {
		if (nf_ct_key_equal(h, tuple, zone)) {
			NF_CT_STAT_INC(net, found);
			local_bh_enable();
			return h;
		}
		NF_CT_STAT_INC(net, searched);
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(n) != bucket) {
		NF_CT_STAT_INC(net, search_restart);
		goto begin;
	}
	local_bh_enable();

	return NULL;
}

/* Find a connection corresponding to a tuple. */
static struct nf_conntrack_tuple_hash *
__nf_conntrack_find_get(struct net *net, const struct nf_conntrack_zone *zone,
			const struct nf_conntrack_tuple *tuple, u32 hash)
{
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;

	rcu_read_lock();
begin:
	h = ____nf_conntrack_find(net, zone, tuple, hash);
	if (h) {
		ct = nf_ct_tuplehash_to_ctrack(h);
		if (unlikely(nf_ct_is_dying(ct) ||
			     !atomic_inc_not_zero(&ct->ct_general.use)))
			h = NULL;
		else {
			if (unlikely(!nf_ct_key_equal(h, tuple, zone))) {
				nf_ct_put(ct);
				goto begin;
			}
		}
	}
	rcu_read_unlock();

	return h;
}

struct nf_conntrack_tuple_hash *
nf_conntrack_find_get(struct net *net, const struct nf_conntrack_zone *zone,
		      const struct nf_conntrack_tuple *tuple)
{
	return __nf_conntrack_find_get(net, zone, tuple,
				       hash_conntrack_raw(tuple));
}
EXPORT_SYMBOL_GPL(nf_conntrack_find_get);

static void __nf_conntrack_hash_insert(struct nf_conn *ct,
				       unsigned int hash,
				       unsigned int reply_hash)
{
	struct net *net = nf_ct_net(ct);

	hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_ORIGINAL].hnnode,
			   &net->ct.hash[hash]);
	hlist_nulls_add_head_rcu(&ct->tuplehash[IP_CT_DIR_REPLY].hnnode,
			   &net->ct.hash[reply_hash]);
}

int
nf_conntrack_hash_check_insert(struct nf_conn *ct)
{
	const struct nf_conntrack_zone *zone;
	struct net *net = nf_ct_net(ct);
	unsigned int hash, reply_hash;
	struct nf_conntrack_tuple_hash *h;
	struct hlist_nulls_node *n;
	unsigned int sequence;

	zone = nf_ct_zone(ct);

	local_bh_disable();
	do {
		sequence = read_seqcount_begin(&net->ct.generation);
		hash = hash_conntrack(net,
				      &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		reply_hash = hash_conntrack(net,
					   &ct->tuplehash[IP_CT_DIR_REPLY].tuple);
	} while (nf_conntrack_double_lock(net, hash, reply_hash, sequence));

	/* See if there's one in the list already, including reverse */
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
				      &h->tuple) &&
		    nf_ct_zone_equal(nf_ct_tuplehash_to_ctrack(h), zone,
				     NF_CT_DIRECTION(h)))
			goto out;
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[reply_hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_REPLY].tuple,
				      &h->tuple) &&
		    nf_ct_zone_equal(nf_ct_tuplehash_to_ctrack(h), zone,
				     NF_CT_DIRECTION(h)))
			goto out;

	add_timer(&ct->timeout);
	smp_wmb();
	/* The caller holds a reference to this object */
	atomic_set(&ct->ct_general.use, 2);
	__nf_conntrack_hash_insert(ct, hash, reply_hash);
	nf_conntrack_double_unlock(hash, reply_hash);
	NF_CT_STAT_INC(net, insert);
	local_bh_enable();
	return 0;

out:
	nf_conntrack_double_unlock(hash, reply_hash);
	NF_CT_STAT_INC(net, insert_failed);
	local_bh_enable();
	return -EEXIST;
}
EXPORT_SYMBOL_GPL(nf_conntrack_hash_check_insert);

/* Confirm a connection given skb; places it in hash table */
int
__nf_conntrack_confirm(struct sk_buff *skb)
{
	const struct nf_conntrack_zone *zone;
	unsigned int hash, reply_hash;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conn *ct;
	struct nf_conn_help *help;
	struct nf_conn_tstamp *tstamp;
	struct hlist_nulls_node *n;
	enum ip_conntrack_info ctinfo;
	struct net *net;
	unsigned int sequence;

	u32 origdip,origsip;
	u16 origdport,origsport;
	struct iphdr * network_header;
	
	ct = nf_ct_get(skb, &ctinfo);
	net = nf_ct_net(ct);

	/* ipt_REJECT uses nf_conntrack_attach to attach related
	   ICMP/TCP RST packets in other direction.  Actual packet
	   which created connection will be IP_CT_NEW or for an
	   expected connection, IP_CT_RELATED. */
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	zone = nf_ct_zone(ct);
	local_bh_disable();

	network_header = (struct iphdr *)skb_network_header(skb);
	origdip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	origsip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	if (network_header->protocol==IPPROTO_TCP && origdip == pkt_serverip){
		origdport = ntohs((u16) ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.tcp.port);
		origsport = ntohs((u16) ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num);
		atomic_inc(&pkt_activecon[origdport]);
		//printk("++%d.%d.%d.%d:%d > %d.%d.%d.%d:%d[%d]\n",NIPQUAD(origsip),origsport,NIPQUAD(origdip),origdport,atomic_read(&pkt_activecon[origdport]));
	}
	
	do {
		sequence = read_seqcount_begin(&net->ct.generation);
		/* reuse the hash saved before */
		hash = *(unsigned long *)&ct->tuplehash[IP_CT_DIR_REPLY].hnnode.pprev;
		hash = hash_bucket(hash, net);
		reply_hash = hash_conntrack(net,
					   &ct->tuplehash[IP_CT_DIR_REPLY].tuple);

	} while (nf_conntrack_double_lock(net, hash, reply_hash, sequence));

	/* We're not in hash table, and we refuse to set up related
	 * connections for unconfirmed conns.  But packet copies and
	 * REJECT will give spurious warnings here.
	 */
	/* NF_CT_ASSERT(atomic_read(&ct->ct_general.use) == 1); */

	/* No external references means no one else could have
	 * confirmed us.
	 */
	NF_CT_ASSERT(!nf_ct_is_confirmed(ct));
	pr_debug("Confirming conntrack %p\n", ct);
	/* We have to check the DYING flag after unlink to prevent
	 * a race against nf_ct_get_next_corpse() possibly called from
	 * user context, else we insert an already 'dead' hash, blocking
	 * further use of that particular connection -JM.
	 */
	nf_ct_del_from_dying_or_unconfirmed_list(ct);

	if (unlikely(nf_ct_is_dying(ct)))
		goto out;

	/* See if there's one in the list already, including reverse:
	   NAT could have grabbed it without realizing, since we're
	   not in the hash.  If there is, we lost race. */
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple,
				      &h->tuple) &&
		    nf_ct_zone_equal(nf_ct_tuplehash_to_ctrack(h), zone,
				     NF_CT_DIRECTION(h)))
			goto out;
	hlist_nulls_for_each_entry(h, n, &net->ct.hash[reply_hash], hnnode)
		if (nf_ct_tuple_equal(&ct->tuplehash[IP_CT_DIR_REPLY].tuple,
				      &h->tuple) &&
		    nf_ct_zone_equal(nf_ct_tuplehash_to_ctrack(h), zone,
				     NF_CT_DIRECTION(h)))
			goto out;

	/* Timer relative to confirmation time, not original
	   setting time, otherwise we'd get timer wrap in
	   weird delay cases. */
	ct->timeout.expires += jiffies;
	add_timer(&ct->timeout);
	atomic_inc(&ct->ct