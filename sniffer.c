/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include "sniffer_ioctl.h"
#include <linux/textsearch.h>
#include <linux/irqflags.h>

MODULE_AUTHOR("");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

unsigned long ruleInt;

//unsigned char SIG_STRING[] = {'g', 'o', 't'};
//unsigned char SIG_STRING[] = {'H', 'a', 'k', 'i', 'm'};
//unsigned int SIG_LENGTH = 5;
static const char SIG_STRING[] = "Hakim";
#define SIG_LENGTH (ARRAY_SIZE(SIG_STRING) - 1)

struct ts_config *conf;
struct ts_state state;

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;
atomic_t readers;

spinlock_t list_lock;
spinlock_t skb_lock;

unsigned long flags;

int rulesset=0;

static int hook_chain = NF_INET_LOCAL_IN;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;

struct sniffer_flow_entry *head;

struct rules_list{
    int mode;
    uint32_t src_ip;
    int src_port;
    uint32_t dest_ip;
    int dest_port;
    int action;
    struct list_head mylist;
};

struct rules_list rules;
struct list_head *rulepos;

// skb buffer between kernel and user space
struct skb_list skbs;
struct list_head *skbpos;

// skb wrapper for buffering
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};

//wait_queue_head_t queue;
static DECLARE_WAIT_QUEUE_HEAD(queue);

char flag = 'n';

static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}

/* From kernel to userspace */
static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    struct skb_list *packet, *q;
    long tosend = 0;

    if(atomic_read(&readers) > 0)
        return -666;

    atomic_inc(&readers);
    while(atomic_read(&refcnt) == 0){ /*no data*/
        if(wait_event_interruptible(queue, atomic_read(&refcnt) > 0)){
            atomic_dec(&readers);
            return -ERESTARTSYS;
        }
    }

    local_irq_save(ruleInt);
    list_for_each_safe(skbpos, q, &skbs.list){
        packet = list_entry(skbpos, struct skb_list, list);
        struct iphdr *iph1;
        iph1 = ip_hdr(packet->skb);
        tosend = packet->skb->len > 2000 ? 2000 : packet->skb->len;
        if(copy_to_user(buf, packet->skb->data, tosend) != 0){
            printk(KERN_DEBUG "Copy to user failed");
            return -EFAULT;
        }
        list_del(skbpos);
        kfree(packet);
        atomic_dec(&refcnt);            
        break;
    }
    local_irq_restore(ruleInt);
    
    atomic_dec(&readers);
    return tosend;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
    struct cdev *cdev = inode->i_cdev;
    int cindex = iminor(inode);

    if (!cdev) {
        printk(KERN_ERR "cdev error\n");
        return -ENODEV;
    }

    if (cindex != 0) {
        printk(KERN_ERR "Invalid cindex number %d\n", cindex);
        return -ENODEV;
    }

    return 0;
}

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
    return 0;
}

static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long err =0 ;
    struct sniffer_flow_entry *new_entry;
    struct rules_list *tmp, *checker;
    int found = 0;

    if (_IOC_TYPE(cmd) != SNIFFER_IOC_MAGIC)
        return -ENOTTY; 
    if (_IOC_NR(cmd) > SNIFFER_IOC_MAXNR)
        return -ENOTTY;
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err)
        return -EFAULT;
    switch(cmd) {
    case SNIFFER_FLOW_ENABLE:
    case SNIFFER_FLOW_DISABLE:
        rulesset = 1;
        new_entry = (struct sniffer_flow_entry *)arg;
        tmp = kmalloc(sizeof(struct rules_list), GFP_KERNEL);
        tmp->src_ip = new_entry->src_ip;
        tmp->dest_ip = new_entry->dest_ip;
        tmp->mode = new_entry->mode;
        tmp->src_port = new_entry->src_port;
        tmp->dest_port = new_entry->dest_port;
        tmp->action = new_entry->action;
        //spin_lock_irqsave(&list_lock, flags);
        //spin_lock(&list_lock);
        local_irq_save(ruleInt);
        list_for_each(rulepos, &rules.mylist){
            checker=list_entry(rulepos, struct rules_list, mylist);
            if(checker->src_port==tmp->src_port && checker->src_ip==tmp->src_ip && checker->dest_port==tmp->dest_port && checker->dest_ip==tmp->dest_ip){
                found = 1;
                checker->mode = new_entry->mode;
                checker->action = new_entry->action;
                break;
            }
        }
        if(found == 0)
            list_add(&(tmp->mylist), &(rules.mylist));
        list_for_each(rulepos, &rules.mylist){
            tmp=list_entry(rulepos, struct rules_list, mylist);
        }
        //spin_unlock_irqrestore(&list_lock, flags);
        //spin_unlock(&list_lock);
        local_irq_restore(ruleInt);
        break;
    default:
        err = -EINVAL;
    }
    return err;
}

static struct file_operations sniffer_fops = {
    .open = sniffer_fs_open,
    .release = sniffer_fs_release,
    .read = sniffer_fs_read,
    .unlocked_ioctl = sniffer_fs_ioctl,
    .owner = THIS_MODULE,
};

static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
        const struct net_device *indev, const struct net_device *outdev,
        int (*okfn) (struct sk_buff*))
{
    struct iphdr *iph = ip_hdr(skb);
    struct rules_list *parser;

    
    if(iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = ip_tcp_hdr(iph);
        if(ntohs(tcph->dest) == 22){
            return NF_ACCEPT;
        }
        if(ntohs(tcph->dest ) != 22){
            //spin_lock_irqsave(&list_lock, flags);
            local_irq_save(ruleInt);
            list_for_each(rulepos, &rules.mylist){
                parser=list_entry(rulepos, struct rules_list, mylist);
                if(/*parser->mode==SNIFFER_FLOW_ENABLE && */(parser->dest_port==-1 || ntohs(tcph->dest)==parser->dest_port) && (parser->src_port==-1 || ntohs(tcph->source)==parser->src_port) && (parser->src_ip==0 || ntohl(iph->saddr)==parser->src_ip) && (parser->dest_ip==0 || ntohl(iph->daddr)==parser->dest_ip || parser->dest_ip==2130706433)){
                    //spin_unlock_irqrestore(&list_lock, flags);
                    local_irq_restore(ruleInt);
                    if(parser->action==ACTION_NONE){
						kfree(skb);
                        if(parser->mode == SNIFFER_FLOW_ENABLE)
                            return NF_ACCEPT;
                        else
                            return NF_DROP;
                    }
                    if(parser->action==ACTION_CAPTURE){
                        struct skb_list *new;
                        new = (struct skb_list *)kmalloc(sizeof(struct skb_list), GFP_ATOMIC);
                        new->skb = skb_copy(skb, GFP_ATOMIC);
                        local_irq_save(ruleInt);
                        list_add(&(new->list), &(skbs.list));
                        atomic_inc(&refcnt);
                        local_irq_restore(ruleInt);
                        flag='\1';
                        wake_up_interruptible(&queue);
						kfree(skb);
                        if(parser->mode == SNIFFER_FLOW_ENABLE)
                            return NF_ACCEPT;
                        else
                            return NF_DROP;
                    }
                    if(parser->action==ACTION_DPI){
                        unsigned int pos = 0;
                        pos  = skb_find_text(skb, 0, skb->len, conf, &state);
                        if(pos == UINT_MAX){
							kfree(skb);
                            if(parser->mode == SNIFFER_FLOW_ENABLE)
                                return NF_ACCEPT;
                            else
                                return NF_DROP;
                        }
                        parser->mode=SNIFFER_FLOW_DISABLE;
						kfree(skb);
                        return NF_DROP;
                    }
                }
            }
            //spin_unlock_irqrestore(&list_lock, flags);
            local_irq_restore(ruleInt);
			kfree(skb);
            return NF_DROP;
        }
    }

	kfree(skb);
    return NF_ACCEPT;
}

static int __init sniffer_init(void)
{
    int status = 0;

    status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
    if (status <0) {
        printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
        goto out;
    }

    cdev_init(&sniffer_cdev, &sniffer_fops);
    status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
    if (status < 0) {
        printk(KERN_ERR "cdev_add failed %d\n", status);
        goto out_cdev;
        
    }

    atomic_set(&refcnt, 0);
    atomic_set(&readers, 0);
    spin_lock_init(&list_lock);
    spin_lock_init(&skb_lock);

    INIT_LIST_HEAD(&skbs.list);

    /* register netfilter hook */
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    nf_hook_ops.hook = sniffer_nf_hook;
    nf_hook_ops.pf = PF_INET;
    nf_hook_ops.hooknum = hook_chain;
    nf_hook_ops.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }

    INIT_LIST_HEAD(&rules.mylist);
    //2130706433
    struct rules_list *tmp;
    tmp = kmalloc(sizeof(struct rules_list), GFP_KERNEL);
    tmp->src_ip = 2130706433;
    tmp->dest_ip = 2130706433;
    tmp->mode = SNIFFER_FLOW_ENABLE;
    tmp->src_port = -1;
    tmp->dest_port = -1;
    tmp->action = ACTION_NONE;
    list_add(&(tmp->mylist), &(rules.mylist));

    conf = textsearch_prepare("kmp", SIG_STRING, SIG_LENGTH, GFP_KERNEL, TS_AUTOLOAD);

    return 0;

out_add:
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{
    //textsearch_destroy(conf);
    struct rules_list *qrule, *RULE;
    list_for_each_safe(rulepos, qrule, &rules.mylist){
        RULE = list_entry(rulepos, struct rules_list, mylist);
        list_del(rulepos);
        kfree(RULE);
    }

    struct skb_list *packet, *q;
    list_for_each_safe(skbpos, q, &skbs.list){
        packet = list_entry(skbpos, struct skb_list, list);
        list_del(skbpos);
        kfree(packet);
    }

    if (nf_hook_ops.hook) {
        nf_unregister_hook(&nf_hook_ops);
        memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    }
    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
}

module_init(sniffer_init);
module_exit(sniffer_exit);
