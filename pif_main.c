//
// pif_main.c - driver for FX host packet interface
//
// Based on:
// drivers/net/mv643xx_eth.c - Driver for MV643XX ethernet ports
// Copyright (C) 2002 Matthew Dharm <mdharm@momenco.com>
//
// Based on the 64360 driver from:
// Copyright (C) 2002 rabeeh@galileo.co.il
//
// Copyright (C) 2003 PMC-Sierra, Inc.,
//  written by Manish Lachwani (lachwani@pmc-sierra.com)
//
// Copyright (C) 2003 Ralf Baechle <ralf@linux-mips.org>
//
// Copyright (C) 2004-2005 MontaVista Software, Inc.
//         Dale Farnsworth <dale@farnsworth.org>
//
// Copyright (C) 2004 Steven J. Hill <sjhill1@rockwellcollins.com>
//             <sjhill@realitydiluted.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//

#include "common.h"

#include <uapi/linux/pkt_cls.h>
#include <linux/init.h>
#include <linux/dma-mapping.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/ip.h>
#include <linux/pci.h>
#include <asm/io.h>
#include <asm/types.h>
#include <asm/pgtable.h>
#include <asm/delay.h>

#include "pif.h"

MODULE_AUTHOR("Bay Microsystems");
MODULE_DESCRIPTION("Host Packet Interface Driver");
MODULE_LICENSE("GPL");

// module parameter
static uint slot_cnt = (uint)-1;
module_param(slot_cnt, uint, S_IRUGO);
MODULE_PARM_DESC(slot_cnt, "number of slots this module should support");

// Constants

#undef PIF_BUF_SZ_CHK
#undef UNUSED_FOR_NOW

// #define NO_RX_DMA
// #define NO_TX_DMA

#define RX_SKB_SIZE                    2048

// how many packets to process per poll
#define PIF_HYSTERESIS                 (PIF_RX_RING_SIZE / 4)

// how many dirty SKBs to leave in the rx descriptor ring
#define PIF_RX_RING_GAP                0

#define PIF_NUM_STATS                  0
#define PIF_MIN_PACKET_SIZE            40 // Assumes raw IP

#ifdef PIF_BUF_SZ_CHK
unsigned char skb_signature[] = {0xaa, 0xbb, 0xcc, 0xdd};
#endif

extern int  pif_proc_init(struct pif_private *hp);
extern void pif_proc_remove(int slot);
extern int  pif_proc_module_init(int slot_cnt);
extern void pif_proc_module_exit(void);

//
// net_device data structure pointer array
//
static struct net_device **pif_dev = NULL;

//
// filter for ASCII printable characters
//
static char z(char p)
{
    return ((p < ' ') || (p > '~')) ? '.' : p;
}

//
// send a packet to stdout
//
static void dump_pkt(struct sk_buff *skb, dma_addr_t dma,
                     unsigned char dump_all)
{
    static u_int32_t rx_cnt = 0;

    unsigned char *p = skb->data;
    unsigned int cnt = skb_tail_pointer(skb) - skb->data;
    unsigned int i, j, num_lines;

    if (!skb || !dma)
    {
        pr_err(PIF_DEV_STR ": %s:%d null skb or dmad pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    printk("\n"
           "skb.head = %p\n"
           "   .data = %p (+%d)\n"
           "   .tail = %p (+%d)\n"
           "   .end  = %p (+%d)\n"
           " total   = %ld\n",
           skb->head,
           skb->data,              skb_headroom(skb),
           skb_tail_pointer(skb),  cnt,
           skb_end_pointer(skb),   skb_tailroom(skb),
           (skb_end_pointer(skb) - skb->head));

    printk("\n"
           "buf_ptr  = %llu\n", dma);

    printk("\n"
           "packet %d:\n"
           "        00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F\n"
           "      +----------------------------------------------------\n",
           ++rx_cnt);

    num_lines = skb_end_pointer(skb) - skb->data;
    num_lines += 15;
    num_lines /= 16;

    for (i = 0; i < num_lines; i++)
    {
        j = i * 16;

        if (!dump_all)
        {
            // show two extra lines
            if (j >= (cnt + 32))
                break;
        }

        printk(" %04X | %02X %02X %02X %02X  %02X %02X %02X %02X  ", j,
               p[j +  0], p[j +  1], p[j +  2], p[j +  3],
               p[j +  4], p[j +  5], p[j +  6], p[j +  7]);
        printk("%02X %02X %02X %02X  %02X %02X %02X %02X : ",
               p[j +  8], p[j +  9], p[j + 10], p[j + 11],
               p[j + 12], p[j + 13], p[j + 14], p[j + 15]);
        printk("%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
               z(p[j +  0]), z(p[j +  1]), z(p[j +  2]), z(p[j +  3]),
               z(p[j +  4]), z(p[j +  5]), z(p[j +  6]), z(p[j +  7]),
               z(p[j +  8]), z(p[j +  9]), z(p[j + 10]), z(p[j + 11]),
               z(p[j + 12]), z(p[j + 13]), z(p[j + 14]), z(p[j + 15]));
    }
    printk(" last data byte @ %X\n\n", cnt - 1);
}

//
// RX complete ISR
//
static irqreturn_t pif_isr_RX_done(int irq, void *ptr)
{
    struct pif_private *hp = (struct pif_private*)ptr;
    unsigned long flags;

    if (hp && (hp->rxDebugLevel >= 10))
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

    spin_lock_irqsave(&hp->lock, flags);
    bic_kern_mask_interrupt(BIC_INTR_DMA_RX, hp->slot);
    bic_kern_inc_intr_cntr(BIC_INTR_DMA_RX, hp->slot);
    napi_schedule(&hp->napi);          // NAPI - start polling
    spin_unlock_irqrestore(&hp->lock, flags);

    if (hp && (hp->rxDebugLevel >= 4))
    {
        pr_notice("%s: EXIT %s\n", hp->ndev->name, __FUNCTION__);
    }
    return IRQ_HANDLED;
}

//
// Tx complete ISR
//
static irqreturn_t pif_isr_TX_done(int irq, void *ptr)
{
    struct pif_private *hp = (struct pif_private*)ptr;

    if (hp && (hp->txDebugLevel >= 10))
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

    bic_kern_inc_intr_cntr(BIC_INTR_DMA_TX, hp->slot);
    schedule_work(&hp->tx_complete_task);

    if (hp && (hp->txDebugLevel >= 4))
    {
        pr_notice("%s: EXIT %s\n", hp->ndev->name, __FUNCTION__);
    }
    return IRQ_HANDLED;
}

//
// attach interrupts
//
static void bic_register_isrs(struct pif_private *hp)
{
    int slot = (hp ? hp->slot : 0);
    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    bic_kern_reg_isr("PIF rx", BIC_INTR_DMA_RX, slot, pif_isr_RX_done, hp);
    bic_kern_reg_isr("PIF tx", BIC_INTR_DMA_TX, slot, pif_isr_TX_done, hp);
    bic_kern_unmask_interrupt(BIC_INTR_DMA_RX, slot);
    bic_kern_unmask_interrupt(BIC_INTR_DMA_TX, slot);
}

//
// detach interrupts
//
static void bic_unregister_isrs(struct pif_private *hp)
{
    int slot = (hp ? hp->slot : 0);
    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    bic_kern_mask_interrupt(BIC_INTR_DMA_RX, slot);
    bic_kern_mask_interrupt(BIC_INTR_DMA_TX, slot);
    bic_kern_unreg_isr(BIC_INTR_DMA_TX, slot, hp);
    bic_kern_unreg_isr(BIC_INTR_DMA_RX, slot, hp);
}

//
// clear all counters
//
static void pif_clear_counters(struct pif_private *hp)
{
    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    memset(&hp->stats, 0, sizeof(hp->stats));
}

//
// read a 64 bit stats counter
//
static u_int64_t readCounter(volatile u_int32_t *cntr)
{
    REG_64_TYPE data;

    if (!cntr)
    {
        pr_err(PIF_DEV_STR ": %s:%d null cntr pointer\n",__FUNCTION__,__LINE__);
        return 0;
    }

    data.u32.lo = *cntr;               // read the lower half
    data.u32.hi = *cntr;               // read the upper half

    return data.u64;
}

//
// transfer data from hardware counters to stats structure
//
static void pif_update_counters(struct pif_private *hp)
{
    unsigned int i;
    volatile u_int32_t *hw = (u_int32_t*)0; // &hp->hw->stats;
    u_int64_t          *sw = (u_int64_t*)0; // &hp->cntrs;

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    mutex_lock(&hp->stats_mutex);
    for (i = 0; i < PIF_NUM_STATS; i++)
    {
        *sw++ = readCounter(hw++);
    }
    mutex_unlock(&hp->stats_mutex);
}

//
// Disable the port and clear the counters.
// The Rx and Tx units are in idle state after this command
//
static void pif_reset(struct pif_private *hp)
{
    unsigned int cntl = (hp ? hp->hw->cntl : 0);

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    // disable the FPGA
    SET_PIF_TX_ENABLE(cntl, 0);
    SET_PIF_RX_ENABLE(cntl, 0);
    SET_PIF_TX_DMA_ENABLE(cntl, 0);
    SET_PIF_RX_DMA_ENABLE(cntl, 0);
    SET_PIF_RX_PAUSE(cntl, 0);
    SET_PIF_INTR_LATCH_ENABLE(cntl, 0);

    hp->hw->cntl = cntl;

    // clear counters
    pif_clear_counters(hp);
}

//
// Send the given packet to hardware
//
static PIF_FUNC_RET_STATUS pif_send(struct pif_private *hp,
                                    struct pkt_info *p_pkt_info)
{
    int used = (hp ? hp->tx.used_desc : 0);
    int curr = (hp ? hp->tx.curr_desc : 0);

    if (!hp || !p_pkt_info)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp or p_pkg_info pointer\n",__FUNCTION__,__LINE__);
        return PIF_ERROR;
    }

    if (hp->txDebugLevel >= 3)
    {
        printk("\n\t *** %s TRANSMIT ***\n", hp->ndev->name);
    }

    if (hp->txDebugLevel >= 5)
    {
        dump_pkt(p_pkt_info->skb_ptr, p_pkt_info->buf_ptr, hp->dumpAll);
    }

    hp->tx.desc_array[curr].buf_ptr  = p_pkt_info->buf_ptr;
    hp->tx.desc_array[curr].byte_cnt = p_pkt_info->byte_cnt;
    hp->tx.skb[curr]                 = p_pkt_info->skb_ptr;

    SET_PIF_BUF_AVL(p_pkt_info->status, 1);

    // Inform the hardware about the buffer
    wmb();
    hp->tx.desc_array[curr].status = p_pkt_info->status;
    wmb();

    hp->tx.ring_skbs++;

    // Finish Tx packet. Update first desc in case of Tx resource error
    curr = (curr + 1) % hp->tx.ring_size;

    // Update the current descriptor
    hp->tx.curr_desc = curr;

    // Check for ring index overlap in the Tx desc ring
    if (curr == used)
    {
        hp->tx.resource_err = PIF_HYSTERESIS;
        return PIF_QUEUE_LAST_RESOURCE;
    }

    return PIF_OK;
}

//
// Receive a packet from hardware.
// If the routine exhausts Rx ring resources the resource error flag is set.
//
static PIF_FUNC_RET_STATUS pif_receive(struct pif_private *hp,
                                       struct pkt_info *p_pkt_info)
{
    unsigned int command_status;
    int curr, used;

    if (!hp || !p_pkt_info)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp or p_pkg_info pointer\n",__FUNCTION__,__LINE__);
        return PIF_ERROR;
    }

    // Do not process Rx ring in case of Rx ring resource error
    if (hp->rx.resource_err)
    {
        if (net_ratelimit())
            pr_info("%s: %s - PIF_QUEUE_FULL\n", hp->ndev->name, __FUNCTION__);
        return PIF_QUEUE_FULL;
    }

    // Get the Rx Desc ring 'curr and 'used' indexes
    curr = hp->rx.curr_desc;
    used = hp->rx.used_desc;

    // The following parameters are used to save readings from memory
    command_status = hp->rx.desc_array[curr].status;
    rmb();

    // Nothing to receive...
    if (1 == GET_PIF_BUF_AVL(command_status))
    {
        if (hp->rxDebugLevel >= 3)
        {
            pr_info("%s: %s - PIF_END_OF_JOB\n", hp->ndev->name, __FUNCTION__);
        }
        return PIF_END_OF_JOB;
    }

#ifdef NO_RX_DMA
    // copy data from hardware buffer into the SKB
    {
        int i, cnt;
        u_int32_t srcVal;
        u_char *dst;

        dst = hp->rx.skb[curr]->data;
        cnt = (hp->rx.desc_array[curr].byte_cnt + 3) >> 2; // use whole words
        for (i = 0; i < cnt; i++)
        {
            srcVal = hp->rx.buff_array[curr].wrd[i];

            *dst++ = (srcVal >> 24) & 0xFF;
            *dst++ = (srcVal >> 16) & 0xFF;
            *dst++ = (srcVal >>  8) & 0xFF;
            *dst++ = (srcVal >>  0) & 0xFF;
        }
    }
#endif

    p_pkt_info->status   = command_status;
    p_pkt_info->byte_cnt = hp->rx.desc_array[curr].byte_cnt;
    p_pkt_info->buf_ptr  = hp->rx.desc_array[curr].buf_ptr;
    p_pkt_info->skb_ptr  = hp->rx.skb[curr];

    // Clean the return info field to indicate that the packet has been
    // moved to the upper layers
    hp->rx.skb[curr] = NULL;

    // Update current index in data structure
    curr = (curr + 1) % hp->rx.ring_size;
    hp->rx.curr_desc = curr;

    // Rx descriptors exhausted. Set the Rx ring resource error flag
    if (curr == used)
        hp->rx.resource_err = 1;

    return PIF_OK;
}

//
// Loads the Rx ring with a fresh buffer
// If set, it clears the "resource error" condition
//
static PIF_FUNC_RET_STATUS pif_rx_load_buff(struct pif_private *hp,
                                            struct pkt_info *p_pkt_info)
{
    int used = (hp ? hp->rx.used_desc : 0);

    if (!hp || !p_pkt_info)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp or p_pkg_info pointer\n",__FUNCTION__,__LINE__);
        return PIF_ERROR;
    }

    hp->rx.desc_array[used].buf_ptr  = p_pkt_info->buf_ptr;
    hp->rx.desc_array[used].byte_cnt = 0;
    hp->rx.skb[used]                 = p_pkt_info->skb_ptr;

    SET_PIF_BUF_AVL(p_pkt_info->status, 1);

    // Return the descriptor to hardware
    wmb();
    hp->rx.desc_array[used].status = p_pkt_info->status;
    wmb();

    // Move the used descriptor pointer to the next descriptor
    hp->rx.used_desc = (used + 1) % hp->rx.ring_size;

    // Any Rx return cancels the Rx resource error status
    hp->rx.resource_err = 0;

    return PIF_OK;
}

//
// Fills / refills the Rx ring
//
static void pif_rx_task(struct pif_private *hp)
{
    struct pkt_info pkt_info = {0};
    struct sk_buff *skb = 0;
#ifdef PIF_BUF_SZ_CHK
    int index = RX_SKB_SIZE - sizeof(unsigned long),  count = 0;
#endif

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    if (test_and_set_bit(0, &hp->rx_task_busy))
    {
        panic("%s: %s - Error in test_set_bit / clear_bit",
              hp->ndev->name, __FUNCTION__);
    }

    while (hp->rx.ring_skbs < (hp->rx.ring_size - PIF_RX_RING_GAP))
    {
        // *** get SKBUF ***
        skb = __dev_alloc_skb(RX_SKB_SIZE, GFP_ATOMIC | GFP_DMA);
        if (!skb)
        {
            pr_err("%s: Error allocating RX skb\n", hp->ndev->name);
            break;
        }
        memset(skb->data, 0xff, RX_SKB_SIZE);

#ifdef PIF_BUF_SZ_CHK
        for (count = 0; count < 4; count++)
            skb->data[index + count] = skb_signature[count];
#endif

        pkt_info.status   = 0;
        pkt_info.byte_cnt = 0;
        pkt_info.skb_ptr  = skb;
#ifdef NO_RX_DMA
        // store data in hardware buffer in FPGA
        {
            int used = hp->rx.used_desc;
            pkt_info.buf_ptr = (dma_addr_t)&hp->rx.buff_array[used];
        }
#else
        // store data directly into SKB
        if (hp->ndev && hp->ndev->dev.parent)
        {
            pkt_info.buf_ptr = dma_map_single(hp->ndev->dev.parent, skb->data,
                                              RX_SKB_SIZE, DMA_FROM_DEVICE);
        }
        if (dma_mapping_error(hp->ndev->dev.parent, pkt_info.buf_ptr)) 
        {
            pr_err("%s: Error DMA mapping skb data %llu\n", hp->ndev->name,pkt_info.buf_ptr);
            break;
        }
#endif
        hp->rx.ring_skbs++;

        if (pif_rx_load_buff(hp, &pkt_info) != PIF_OK)
        {
            pr_err("%s: Error allocating RX Ring\n", hp->ndev->name);
            break;
        }
    }

    clear_bit(0, &hp->rx_task_busy);

    // If RX ring is empty, set a timer to try allocating at a later time .
    if ((hp->rx.ring_skbs == 0) && (hp->rx_timer_flag == 0))
    {
        pr_info("%s: Rx ring is empty\n", hp->ndev->name);

        hp->timeout.expires = jiffies + (HZ / 10); // after 100mSec
        add_timer(&hp->timeout);
        hp->rx_timer_flag = 1;
    }
}

//
// Timer routine to wake up RX queue filling task.
// It is only called in case the RX queue is empty,
// and alloc_skb failed (due to out of memory event).
//
static void pif_rx_task_timer_wrapper(unsigned long data)
{
    struct pif_private *hp = (struct pif_private*)data;

    hp->rx_timer_flag = 0;
    pif_rx_task(hp);
}

//
// CALLED BY KERNEL
//
// Set promiscuous mode according to flags
//
static void pif_set_multicast_list(struct net_device *ndev)
{
    struct pif_private *hp = netdev_priv(ndev);

    if (!ndev || !hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null ndev or hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }


    if ((hp->txDebugLevel >= 10) || (hp->rxDebugLevel >= 10))
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }
}

//
// release the used SKBs
//
static int pif_free_tx_queue(struct pif_private *hp)
{
    struct sk_buff *skb;

    int released = 0;
    int retry    = 0;

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return released;
    }

#define RETRY 50000

    for (;;)
    {
        int used = hp->tx.used_desc;
        int curr = hp->tx.curr_desc;

        unsigned int command_status;

        // Stop - about to overlap the current available Tx descriptor
        if ((used == curr) && !hp->tx.resource_err)
        {
            if (hp->txDebugLevel >= 3)
            {
                pr_info("%s: %s - PIF_END_OF_JOB\n", hp->ndev->name, __FUNCTION__);
            }
            break;                     // EXIT for(;;)
        }

        command_status = hp->tx.desc_array[used].status;

        // Still transmitting...
        if (0 == GET_PIF_BUF_RDY(command_status))
        {
            if (hp->txDebugLevel >= 2)
            {
                pr_info("%s: %s - retry\n", hp->ndev->name, __FUNCTION__);
            }

            if (++retry > RETRY)
            {
                panic("%s: %s - exceeded return descriptor retry count (%d)",
                      hp->ndev->name, __FUNCTION__, RETRY);
                break;
            }
            continue;                  // RE-ENTER for(;;)
        }
        retry = 0;

        // Report any errors
        if (1 == GET_PIF_BUF_ERR(command_status))
        {
            pr_info("%s: %s - TX error (status=%08X)\n",
                   hp->ndev->name, __FUNCTION__, command_status);
            hp->stats.tx_errors++;
        }

        // Clean up
        skb = hp->tx.skb[used];
        if (skb == NULL)
        {
            pr_info("%s: %s - SKB lost\n", hp->ndev->name, __FUNCTION__);
        }
        else
        {
            // Release the SKB
            dma_unmap_single(hp->ndev->dev.parent, (dma_addr_t)skb->data,
                             skb->len, DMA_TO_DEVICE);
            dev_kfree_skb_any(skb);    // *** release SKBUF ***
            released++;

            // Decrement the number of outstanding SKBs counter on the TX queue.
            if (hp->tx.ring_skbs == 0)
            {
                panic("%s: %s - outstanding Tx SKBs counter is corrupted",
                      hp->ndev->name, __FUNCTION__);
            }
            hp->tx.ring_skbs--;

            // re-init this descriptor
            hp->tx.skb[used] = NULL;
            hp->tx.desc_array[used].status   = 0;
            // hp->tx.desc_array[used].byte_cnt = 0;
            // hp->tx.desc_array[used].buf_ptr  = NULL;

            // Update the next descriptor to release.
            hp->tx.used_desc = (used + 1) % hp->tx.ring_size;

            // reduce the Tx resource error hysteresis
            if (hp->tx.resource_err > 0)
            {
                hp->tx.resource_err--;
            }
        }
    }

    return released;
}

long checksum(unsigned short *addr, int count)
{
    // Compute Internet Checksum for "count" bytes beginning at location "addr"
    register long sum = 0;

    if (!addr)
    {
        pr_err(PIF_DEV_STR ": %s:%d null addr pointer\n",__FUNCTION__,__LINE__);
        return sum;
    }

    while (count > 1)
    {
        //  This is the inner loop
        sum += *addr++;
        count -= 2;
    }

    // Add left-over byte, if any
    if (count > 0)
        sum += *(unsigned char*)addr;

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

unsigned short iphdr_cksum(unsigned short *ip, int len)
{
    long sum = 0;                      // assume 32 bit long, 16 bit short

    if (!ip)
    {
        pr_err(PIF_DEV_STR ": %s:%d null ip pointer\n",__FUNCTION__,__LINE__);
        return sum;
    }

    while (len > 1)
    {
        sum += *((unsigned short*)ip);
        ip++;
        if (sum & 0x80000000)          // if high order bit set, fold
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if (len)                           // take care of left over byte
        sum += (unsigned short)*(unsigned char*)ip;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

//
// to use ping to test hardware:
//
// 1) enable ping loopback:
//      echo -n 2 > /proc/pif/0/pif_loopback
//
// 2) loopback pif packets at the BIC data FPGA:
//      setmem 81100000 1
//
// 3) assign an IP address to PIF
//      ip addr add 192.168.55.100/24 brd + dev pif0
//
// 4) run ping:
//      ping -c 1 192.168.55.10
//
// to turn on debug tracing:
//
//  echo 10 > /proc/pif/0/pif_tx_dbg_lvl
//  echo 10 > /proc/pif/0/pif_rx_dbg_lvl
//
static void edit_for_ping_looping(struct sk_buff *skb)
{
    struct iphdr *iphdr;
    struct icmphdr *icmphdr;
    u_int32_t src;
    u_int32_t dst;
    u_short csum;
    u_char ihl;
    int icmp_len;

    if (!skb)
    {
        pr_err(PIF_DEV_STR ": %s:%d null skb pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    // get the ip header len & datagram total length
    //
    iphdr = (struct iphdr*)((u_char*)skb->data);
    ihl = iphdr->ihl << 2;             // save ip header len in bytes

    // swap the src/dst addresses
    //
    src = iphdr->saddr;
    dst = iphdr->daddr;
    iphdr->saddr = dst;
    iphdr->daddr = src;

    // recalc ip header checksum
    //
    iphdr->check = 0;
    csum = iphdr_cksum((unsigned short*)iphdr, ihl);
    iphdr->check = csum;

    // point to ping message
    //
    icmphdr = (struct icmphdr*)(iphdr + 1);
    icmphdr->type = 0;                 // mark as reply

    // recalc icmp checksum
    //
    icmp_len = iphdr->tot_len - sizeof(*iphdr);
    icmphdr->checksum = 0;
    csum = checksum((u_short*)icmphdr, icmp_len);
    icmphdr->checksum = csum;
}

//
// release the transmit ring resources
//
static void pif_free_tx_rings(struct pif_private *hp)
{
    unsigned int curr;

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    // Free outstanding SKBs on TX rings
    for (curr = 0; ((hp->tx.ring_skbs > 0) &&
                    (curr < hp->tx.ring_size)); curr++)
    {
        if (hp->tx.skb[curr])
        {
            dev_kfree_skb_any(hp->tx.skb[curr]); // *** release SKBUF ***
            hp->tx.skb[curr] = NULL;
            hp->tx.ring_skbs--;
        }
    }
    if (hp->tx.ring_skbs)
    {
        pr_err("%s: Error in freeing Tx ring\n"
               " %d SKBs still stuck - ignoring them\n",
               hp->ndev->name, hp->tx.ring_skbs);
    }
}

//
// release the receive ring resources
//
static void pif_free_rx_rings(struct pif_private *hp)
{
    int curr;

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    // Free preallocated SKBs on RX rings
    for (curr = 0; hp->rx.ring_skbs && curr < hp->rx.ring_size; curr++)
    {
        if (hp->rx.skb[curr])
        {
            dev_kfree_skb_any(hp->rx.skb[curr]); // *** release SKBUF ***
            hp->rx.skb[curr] = NULL;
            hp->rx.ring_skbs--;
        }
    }

    if (hp->rx.ring_skbs)
    {
        pr_err("%s: Error in freeing Rx ring\n"
               " %d SKBs still stuck - ignoring them\n",
               hp->ndev->name, hp->rx.ring_skbs);
    }
}

//
// This routine prepares the PIF for Rx and Tx activity:
//
static void pif_start(struct pif_private *hp)
{
    unsigned int cntl = (hp ? hp->hw->cntl : 0);

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    // enable the FPGA
    SET_PIF_TX_ENABLE(cntl, 1);
    SET_PIF_RX_ENABLE(cntl, 1);
    SET_PIF_TX_DMA_ENABLE(cntl, 1);
    SET_PIF_RX_DMA_ENABLE(cntl, 1);
    SET_PIF_INTR_LATCH_ENABLE(cntl, 1);

    hp->hw->cntl = cntl;
}

//
// Helper function for pif_stop (no spin-locks)
//
static int pif_real_stop(struct pif_private *hp)
{
    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return -EFAULT;
    }

    netif_stop_queue(hp->ndev);        // kernel - suspend tx

    pif_reset(hp);

    napi_disable(&hp->napi);
    bic_unregister_isrs(hp);

    pif_free_tx_rings(hp);
    pif_free_rx_rings(hp);

    // printk("%s: disabled\n", hp->ndev->name);

    return 0;
}

//
// CALLED BY KERNEL
//
// Stop the network device and release buffers
//
static int pif_stop(struct net_device *ndev)
{
    struct pif_private *hp = netdev_priv(ndev);
    unsigned long flags;

    if (!ndev || !hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null ndev or hp pointer\n",__FUNCTION__,__LINE__);
        return -EFAULT;
    }

    if ((hp->txDebugLevel >= 10) || (hp->rxDebugLevel >= 10))
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

    spin_lock_irqsave(&hp->lock, flags);

    pif_real_stop(hp);

    spin_unlock_irqrestore(&hp->lock, flags);

    return 0;
}

//
// Helper function for pif_open (no spin-locks)
//
static int pif_real_open(struct pif_private *hp)
{
    int i;

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return -1;
    }

    pif_reset(hp);

    memset(&hp->timeout, 0, sizeof(struct timer_list));
    hp->timeout.function = pif_rx_task_timer_wrapper;
    hp->timeout.data = (unsigned long)hp;

    hp->txFull          = 0;

    hp->rx_task_busy    = 0;
    hp->rx_timer_flag   = 0;

    // build RX ring
    hp->rx.curr_desc    = 0;
    hp->rx.used_desc    = 0;
    hp->rx.ring_skbs    = 0;
    hp->rx.resource_err = 0;

    for (i = 0; i < hp->rx.ring_size; i++)
    {
        hp->rx.desc_array[i].status   = 0;
        hp->rx.desc_array[i].byte_cnt = 0;
        hp->rx.desc_array[i].buf_ptr  = 0;
    }

    // build TX ring
    hp->tx.curr_desc    = 0;
    hp->tx.used_desc    = 0;
    hp->tx.ring_skbs    = 0;
    hp->tx.resource_err = 0;

    for (i = 0; i < hp->tx.ring_size; i++)
    {
        hp->tx.desc_array[i].status   = 0;
        hp->tx.desc_array[i].byte_cnt = 0;
        hp->tx.desc_array[i].buf_ptr  = 0;
    }

    // Initialize the skb_ptr's to 0
    for (i = 0; i < hp->tx.ring_size; i++)
    {
        hp->tx.skb[i] = NULL;
    }

    pif_rx_task(hp);                   // Fill RX ring with SKBs

    pif_start(hp);

    napi_enable(&hp->napi);
    bic_register_isrs(hp);

    netif_start_queue(hp->ndev);       // kernel - start tx

    // printk("%s: enabled\n", hp->ndev->name);

    return 0;
}

//
// CALLED BY KERNEL
//
// Start the network device and initialize Rx & Tx rings
//
static int pif_open(struct net_device *ndev)
{
    struct pif_private *hp = netdev_priv(ndev);
    int err = 0;
    unsigned long flags;

    if (!ndev || !hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null ndev or hp pointer\n",__FUNCTION__,__LINE__);
        return -EFAULT;
    }

    if ((hp->txDebugLevel >= 10) || (hp->rxDebugLevel >= 10))
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

    spin_lock_irqsave(&hp->lock, flags);

    if (pif_real_open(hp))
    {
        pr_info("%s: Error opening %s interface\n",
               hp->ndev->name, ndev->name);
        err = -EBUSY;
    }

    spin_unlock_irqrestore(&hp->lock, flags);
    return err;
}

#define FW_SAR_MIN_LEN 48 // to handle one cell packet limitation
//
// CALLED BY KERNEL
//
// Enqueue the given buffer in the Tx ring
//
static int pif_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
    struct pif_private *hp = netdev_priv(ndev);
    struct pkt_info pkt_info;

    unsigned int byte_cnt, numBytesPad = 0;
    unsigned long flags;
    int bytes2Align;

    if (!skb || !ndev || !hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null skb, ndev or hp pointer\n",__FUNCTION__,__LINE__);
        return 1;
    }

    if (hp->txDebugLevel >= 10)
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

    if (netif_queue_stopped(ndev))     // kernel - query
    {
        pr_err("%s: Transmit attempt when interface is stopped\n",
               hp->ndev->name);
        return 1;
    }

    // This is a hard error, log it.
    if (hp->tx.resource_err > 0)
    {
        netif_stop_queue(ndev);        // kernel - suspend tx
        pr_err("%s: Transmit attempt when queue full !\n", hp->ndev->name);
        return 1;
    }

    // Paranoid check - this shouldn't happen
    if (skb == NULL)
    {
        hp->stats.tx_dropped++;
        pr_err("%s: Transmit attempt with no SKB\n", hp->ndev->name);
        return 1;
    }

    // length check - HW buffer is 2K max
    if (skb->len > (1024 * 2))
    {
        hp->stats.tx_dropped++;
        dev_kfree_skb_any(skb);    // *** release SKBUF ***
        pr_err("%s: Oversized packet\n", hp->ndev->name);
        return 1;
    }

    spin_lock_irqsave(&hp->lock, flags);

    // Since TX DMA in the FPGA requires 8 byte alignment, adjust the
    // skb->data pointer by expanding the head
    bytes2Align = (int)((u64)skb->data & 0x7);
    if (bytes2Align > 0)
    {
        // printk("pif: skb->data = %llx\n", (u64)skb->data);
        if (pskb_expand_head(skb, (8 - bytes2Align), 0, GFP_ATOMIC | GFP_DMA) != 0)
        {
            hp->stats.tx_dropped++;
            if (printk_ratelimit())
                printk("%s: skb expand_head failed, dropping...\n", hp->ndev->name);
            return 1;
        }
        // printk("pif: after alignment, skb->data = %llx\n", (u64)skb->data);
    }

    if (skb->len < FW_SAR_MIN_LEN)
    {
        if (skb_padto(skb, FW_SAR_MIN_LEN) != 0)
        {
            hp->stats.tx_dropped++;
            if (printk_ratelimit())
                printk("%s: skb_padto failed, dropping...\n", hp->ndev->name);
            return 1;
        }

        numBytesPad = FW_SAR_MIN_LEN - skb->len;
    }

    // Update packet info data structure -- DMA owned, first last
    pkt_info.status   = 0;
    pkt_info.byte_cnt = byte_cnt = skb->len + numBytesPad;

#ifdef NO_TX_DMA
    // copy data to hardware buffer in FPGA
    {
        int i, j, cnt;
        int curr = hp->tx.curr_desc;

        struct pif_buff *p_hw = (struct pif_buff*)&hp->tx.buff_array[curr];

        cnt = (byte_cnt + 3) >> 2;     // use whole words

        for (i = 0; i < cnt; i++)
        {
            j = i * 4;
            p_hw->wrd[i] = (((skb->data[j + 0] & 0xFF) << 24) |
                                ((skb->data[j + 1] & 0xFF) << 16) |
                                ((skb->data[j + 2] & 0xFF) <<  8) |
                                ((skb->data[j + 3] & 0xFF) <<  0));
        }
        pkt_info.buf_ptr = (dma_addr_t)p_hw;
    }
#else
    // pull data directly from SKB
    pkt_info.buf_ptr = dma_map_single(ndev->dev.parent, skb->data,
                                             byte_cnt, DMA_TO_DEVICE);
    if (dma_mapping_error(ndev->dev.parent, pkt_info.buf_ptr)) 
    {
        pr_err("%s: Error DMA mapping skb data %llu\n", hp->ndev->name, pkt_info.buf_ptr);
        return 1;
    }
#endif
    pkt_info.skb_ptr = skb;

    if (pif_send(hp, &pkt_info) == PIF_QUEUE_LAST_RESOURCE)
    {
        if (3 == hp->loopback)         // rx pause
        {
            hp->txFull = 1;            // set the txFull flag
        }
        else
        {
            // Stop getting SKBs from upper layers.
            // Getting SKBs from upper layers will be enabled again after
            // packets are released.
            netif_stop_queue(ndev);    // kernel - suspend tx
        }

        if (hp->txDebugLevel >= 2)
        {
            pr_err("%s: Tx queue full, stopped\n", hp->ndev->name);
        }
    }

    // Update statistics and start of transmittion time
    hp->stats.tx_bytes += byte_cnt;
    hp->stats.tx_packets++;
    ndev->trans_start = jiffies;

    spin_unlock_irqrestore(&hp->lock, flags);

    if (hp->txDebugLevel >= 4)
    {
        pr_notice("%s: EXIT %s\n", hp->ndev->name, __FUNCTION__);
    }

    return 0;
}

//
// forward received packets to the kernel core
//
static int pif_receive_queue(struct pif_private *hp, int budget)
{
    struct pkt_info pkt_info;
    struct sk_buff *skb;

    unsigned int received_packets = 0;
    unsigned int byte_cnt;
    unsigned int dump_threshold = 5;
#ifdef PIF_BUF_SZ_CHK
    int index = RX_SKB_SIZE - sizeof(unsigned long),  count = 0;
#endif

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return -EFAULT;
    }

    // if txFull -- only occurs if (3 == hp->loopback) --
    // do not process the rx side

    while (!(hp->txFull) &&
           (budget > 0) && (pif_receive(hp, &pkt_info) == PIF_OK))
    {
        hp->rx.ring_skbs--;
        received_packets++;

        budget--;

        // Update statistics
        byte_cnt = pkt_info.byte_cnt;
        hp->stats.rx_packets++;
        hp->stats.rx_bytes += byte_cnt;

        skb = pkt_info.skb_ptr;

        // If the error summary bit is on the packet needs to be dropped.
        if (1 == GET_PIF_BUF_ERR(pkt_info.status))
        {
            printk("%s: RX error (status=%08X)\n",
                   hp->ndev->name, pkt_info.status);
            hp->stats.rx_dropped++;
            hp->stats.rx_errors++;
            dev_kfree_skb_any(skb);    // *** release SKBUF ***
        }
        else
        {
            skb_put(skb, byte_cnt);
            skb->dev      = hp->ndev;
            skb->protocol = htons(ETH_P_VIFMUX);
            skb->pkt_type = PACKET_HOST;
            skb->cb[0] = hp->slot;     // pass slot number to vifmux

            switch(hp->loopback)
            {
            case  0 :                  // do nothing
            case  1 :                  // not currently used (was vif looping)
                break;
            case  2 :
                edit_for_ping_looping(skb);
                skb->protocol = htons(ETH_P_IP);
                break;
            case  3 :                  // return to sender - handled below
                break;
            default :
                printk("\n%s: loopback %d is undefined\n",
                       hp->ndev->name, hp->loopback);
                break;
            }

            if (hp->rxDebugLevel >= 3)
            {
                printk("\n\t *** %s RECEIVE ***\n", hp->ndev->name);
            }

            if (byte_cnt < PIF_MIN_PACKET_SIZE)
            {
                if (net_ratelimit())
                    printk("\n\t *** Received Small Packet - size %d ***\n", byte_cnt);
                dump_threshold = 3;
            }

            if (hp->rxDebugLevel >= dump_threshold)
            {
                printk("\nDescriptor Status: 0x%08x\n", pkt_info.status);
                dump_pkt(pkt_info.skb_ptr, pkt_info.buf_ptr, hp->dumpAll);
            }

            if (4 <= hp->loopback)     // drop the packet
            {
                hp->stats.rx_dropped++;
                dev_kfree_skb_any(skb); // *** release SKBUF ***

            }
            else if (3 == hp->loopback) // return SKBUF to sender
            {
                if (pif_start_xmit(skb, hp->ndev))
                {
                    printk("user loopback failed\n\n");
                    dev_kfree_skb_any(skb); // *** release SKBUF ***
                }
            }
            else                       // send SKBUF to kernel
            {
                netif_receive_skb(skb);
            }
        }

#ifdef PIF_BUF_SZ_CHK
        for (count = 0; count < 4; count++)
        {
            if (skb->data[index + count] != skb_signature[count])
            {
                printk("\n\t *** %s INVALID PACKET REC. ***\n", hp->ndev->name);
                printk("Descriptor Status: 0x%08x\n", pkt_info.status);
                printk("Rx_Bytes = %d\n", byte_cnt);
                if (hp->rxDebugLevel >= 3)
                {
                    dump_pkt(pkt_info.skb_ptr, pkt_info.buf_ptr, hp->dumpAll);
                }
                // BUG();
                hp->stats.rx_errors++;
                break;
            }
        }
#endif
    }
    return received_packets;
}

//
// CALLED BY KERNEL
//
// Polled version - for NAPI support
//
static int pif_poll(struct napi_struct *napi, int budget)
{
    struct pif_private *hp = container_of(napi, struct pif_private, napi);

    int work_done = 0;
    unsigned long flags;

    if (!napi || !hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null napi or hp pointer\n",__FUNCTION__,__LINE__);
        return -EFAULT;
    }

    // if txFull -- only occurs if (3 == hp->loopback)
    // -- skip this poll but keep trying
    if (hp->txFull)
        return work_done;

    // process buffers received from hardware
    work_done = pif_receive_queue(hp, budget);
    pif_rx_task(hp);                   // refill buffer ring

    // if txFull has become active -- only occurs if (3 == hp->loopback)
    // -- finish this poll and keep trying
    if (!(hp->txFull) &&
        (work_done < budget))          // we're under budget so we're finished
    {
        // quit polling & re-enable interrupts
        spin_lock_irqsave(&hp->lock, flags);
        napi_complete(napi);           // NAPI - stop polling
        bic_kern_unmask_interrupt(BIC_INTR_DMA_RX, hp->slot);
        spin_unlock_irqrestore(&hp->lock, flags);
    }
    return work_done;
}

//
// CALLED BY KERNEL
//
// Tx timeout handler
//
static void pif_tx_timeout(struct net_device *ndev)
{
    struct pif_private *hp = netdev_priv(ndev);

    if (!ndev || !hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null ndev or hp pointer\n",__FUNCTION__,__LINE__);
        return;
    }

    if (hp->txDebugLevel >= 10)
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

#ifdef UNUSED_FOR_NOW
    // Do the reset outside of interrupt context
    schedule_work(&hp->tx_timeout_task);
#endif

    if (hp->txDebugLevel >= 4)
    {
        pr_notice("%s: EXIT %s\n", hp->ndev->name, __FUNCTION__);
    }
}

//
// Actual routine to reset the adapter when a Tx timeout has occurred
//
static void pif_tx_timeout_task(struct work_struct *data)
{
    struct pif_private *hp = container_of(data, struct pif_private, tx_timeout_task);
    int rc = 0;

    if (hp->txDebugLevel >= 10)
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

#ifdef UNUSED_FOR_NOW
    netif_device_detach(hp->ndev);     // kernel - stop tx if running
    pif_reset(hp);
    pif_start(hp);
    netif_device_attach(hp->ndev);     // kernel - start tx if running
#else
    if ((rc = pif_real_stop(hp)) != 0)
    {
        pr_err("%s: Fatal error on stopping device\n", hp->ndev->name);
    }
    else if ((rc = pif_real_open(hp)) != 0)
    {
        pr_err("%s: Fatal error on opening device\n", hp->ndev->name);
    }
#endif
}

//
// CALLED BY KERNEL
//
// Returns a pointer to the interface statistics
//
static struct net_device_stats* pif_get_stats(struct net_device *ndev)
{
    struct pif_private *hp = netdev_priv(ndev);

    if ((hp->txDebugLevel >= 20) || (hp->rxDebugLevel >= 20))
    {
        if (net_ratelimit())
        {
            pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
        }
    }

    pif_update_counters(hp);

    return &hp->stats;
}

//
// CALLED BY KERNEL
//
// Changes MTU (maximum transfer unit) of the host packet interface
//
static int pif_change_mtu(struct net_device *ndev, int new_mtu)
{
    struct pif_private *hp = netdev_priv(ndev);
    int                old_mtu = ndev->mtu;
    int                rc      = 0;
    unsigned long      flags;

    if ((hp->txDebugLevel >= 10) || (hp->rxDebugLevel >= 10))
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

    if ((new_mtu > 9500) || (new_mtu < 64))
    {
        pr_err(PIF_DEV_STR ": %s:%d %s: Invalid mtu value %d\n",__FUNCTION__,__LINE__, hp->ndev->name,new_mtu);
        return -EINVAL;
    }

    spin_lock_irqsave(&hp->lock, flags);

    ndev->mtu = new_mtu;

    // Stop & re-open the interface to allocate RX SKBs with the new MTU
    // The re-open may fail if there are no SKBs available

    if (netif_running(ndev))           // kernel - query
    {
        pr_notice("%s: Changing MTU from %d to %d\n", hp->ndev->name,
               old_mtu, new_mtu);

        if ((rc = pif_real_stop(hp)) != 0)
        {
            pr_err("%s: Fatal error on stopping device\n", hp->ndev->name);
        }
        else if ((rc = pif_real_open(hp)) != 0)
        {
            pr_err("%s: Fatal error on opening device\n", hp->ndev->name);
        }
    }
    spin_unlock_irqrestore(&hp->lock, flags);
    return rc;
}

//
// Actual routine to TX complete
//
static void pif_tx_complete_task(struct work_struct *data)
{
    struct pif_private *hp = container_of(data, struct pif_private, tx_complete_task);
    u_int32_t tx_resource_err;
    u_int32_t returned;
    unsigned long flags;
    int hyst_clr;

    if (hp->txDebugLevel >= 10)
    {
        pr_notice("%s: ENTER %s\n", hp->ndev->name, __FUNCTION__);
    }

    spin_lock_irqsave(&hp->lock, flags);

    tx_resource_err = hp->tx.resource_err;
    returned        = pif_free_tx_queue(hp);

    // has tx hysteresis been cleared?
    hyst_clr = ((tx_resource_err > 0) && (hp->tx.resource_err <= 0));

    spin_unlock_irqrestore(&hp->lock, flags);

    if (hyst_clr)
    {
        // Start getting SKBs from upper layers again.
        if (hp->txDebugLevel >= 2)
        {
            pr_err("%s: Tx queue available, restarting\n", hp->ndev->name);
        }

        if (3 == hp->loopback)         // rx resume
        {
            hp->txFull = 0;            // clear the txFull flag
        }
        else
        {
            netif_wake_queue(hp->ndev); // kernel - restart tx
        }
    }
    else
    {
        if ((tx_resource_err && (returned == 0)) || (returned > hp->tx.ring_size))
        {
            pr_err("\n\n%s: err = %d, cnt = %d\n\n", hp->ndev->name,
                   tx_resource_err, returned);
        }
    }

    if (hp->txDebugLevel >= 4)
    {
        pr_notice("%s: EXIT %s\n", hp->ndev->name, __FUNCTION__);
    }
}

static const struct net_device_ops pif_netdev_ops =
{
    .ndo_open               = pif_open,
    .ndo_stop               = pif_stop,
    .ndo_start_xmit         = pif_start_xmit,
    .ndo_set_rx_mode        = pif_set_multicast_list,
    .ndo_set_mac_address    = NULL,    // eth_mac_addr,
    .ndo_change_mtu         = pif_change_mtu,
    .ndo_tx_timeout         = pif_tx_timeout,
    .ndo_get_stats          = pif_get_stats,
};

static void pif_dev_setup(struct net_device *ndev)
{
    ndev->type                = ARPHRD_NONE; // ARPHRD_ETHER;
    ndev->hard_header_len     = 0;     // ETH_HLEN;
    ndev->mtu                 = 1500;  // eth_mtu
    ndev->addr_len            = 0;     // ETH_ALEN;
    ndev->tx_queue_len        = 1000;  // Ethernet wants good queues
    ndev->flags               = IFF_NOARP;

    // driver specific initialization

    ndev->netdev_ops          = &pif_netdev_ops;
    ndev->watchdog_timeo      = 2 * HZ;
    ndev->features            = 0;
}

//
// insertion event
//
int pif_insert(void *arg)
{
    struct net_device    *ndev;
    struct pif_private   *hp;
    struct common_notice *note = (struct common_notice*)arg;

    int slot   = (note ? note->bic->slot : 0);
    int err    = 0;
    int weight = PIF_HYSTERESIS;

    char devName[32];

    if (!arg)
    {
        pr_err(PIF_DEV_STR ": %s:%d null arg pointer\n",__FUNCTION__,__LINE__);
        return -EFAULT;
    }

    pr_info(PIF_DEV_STR "%d : insert chain event\n",slot);

    sprintf(devName, PIF_DEV_STR "%d", slot);

    // setup the network device structure
    ndev = alloc_netdev(sizeof(struct pif_private), devName,
                        NET_NAME_USER, pif_dev_setup);
    if (ndev == NULL)
    {
        pr_err("%s: cannot allocate network device\n", devName);
        return -ENOMEM;
    }

    // tell the kernel we're part of the data FPGA
    SET_NETDEV_DEV(ndev, &note->bic->pci->dev);

    // get private structure pointer
    hp = netdev_priv(ndev);

    if (!hp)
    {
        pr_err(PIF_DEV_STR ": %s:%d null hp pointer\n",__FUNCTION__,__LINE__);
        return -EFAULT;
    }

    // setup the private structure
    hp->ndev = ndev;
    hp->hw   = &note->bic->fpga->hbr.pif;
    hp->slot = slot;

    // TICKET 2197 - disable SOP timeout
    hp->hw->sop_to = 0;

    mutex_init(&hp->stats_mutex);
    spin_lock_init(&hp->lock);

    hp->rx.desc_array = (struct pif_desc*)&hp->hw->rxDesc;
#ifdef NO_RX_DMA
    hp->rx.buff_array = (struct pif_buff*)&hp->hw->rxBuff;
#else
    hp->rx.buff_array = NULL;
#endif
    hp->rx.ring_size  = PIF_RX_RING_SIZE;
    hp->rx.skb = kmalloc(sizeof(*hp->rx.skb) * hp->rx.ring_size, GFP_KERNEL);
    if (!hp->rx.skb)
    {
        pr_err("%s: cannot allocate Rx SKB ring\n", devName);
        free_netdev(ndev);
        return -ENOMEM;
    }

    hp->tx.desc_array = (struct pif_desc*)&hp->hw->txDesc;
#ifdef NO_TX_DMA
    hp->tx.buff_array = (struct pif_buff*)&hp->hw->txBuff;
#else
    hp->tx.buff_array = NULL;
#endif
    hp->tx.ring_size  = PIF_TX_RING_SIZE;
    hp->tx.skb = kmalloc(sizeof(*hp->tx.skb) * hp->tx.ring_size, GFP_KERNEL);
    if (!hp->tx.skb)
    {
        pr_err("%s: cannot allocate Tx SKB ring\n", devName);
        kfree(hp->rx.skb);
        free_netdev(ndev);
        return -ENOMEM;
    }

    // Configure the transmission complete task
    INIT_WORK(&hp->tx_complete_task, pif_tx_complete_task);

    // Configure the kernel timeout task
    INIT_WORK(&hp->tx_timeout_task, pif_tx_timeout_task);

    // setup NAPI
    netif_napi_add(ndev, &hp->napi, pif_poll, weight);

    // register the network device with the OS
    err = register_netdev(ndev);
    if (err)
    {
        pr_err("%s: cannot register device\n", devName);
        kfree(hp->tx.skb);
        kfree(hp->rx.skb);
        free_netdev(ndev);
        return err;
    }

    // store device pointer
    pif_dev[slot] = ndev;

    // setup the proc files
    pif_proc_init(hp);

    return 0;
}

//
// extraction event
//
int pif_remove(void *arg)
{
    struct common_notice *note = (struct common_notice*)arg;
    int slot = note->bic->slot;
    struct net_device *ndev = pif_dev[slot];

    if (!arg)
    {
        pr_err(PIF_DEV_STR ": %s:%d arg nullptr\n",__FUNCTION__,__LINE__);
        return -EFAULT;
    }

    if (ndev != NULL)
    {
        // get private structure pointer
        struct pif_private *hp = netdev_priv(ndev);

        pr_info(PIF_DEV_STR "%d : extract chain event %p\n",slot,ndev);
        pif_proc_remove(slot);
        unregister_netdev(ndev);
        kfree(hp->rx.skb);
        kfree(hp->tx.skb);
        flush_scheduled_work();
        free_netdev(ndev);
        pif_dev[slot] = NULL;
    }
    return 0;
}

//
// notification callback
//
static int pif_notify(struct notifier_block *nb, unsigned long action, void *arg)
{
    pr_info(PIF_DEV_STR ": notify action=%ld arg=%p\n",action,arg);

    if (!arg)
    {
        pr_err(PIF_DEV_STR ": %s:%d null arg pointer\n",__FUNCTION__,__LINE__);
        return NOTIFY_OK;
    }

    switch(action)
    {
    case BIC_INSERTION :
        pif_insert(arg);
        break;
    case BIC_EXTRACTION :
        pif_remove(arg);
        break;
    case BIC_INSERTION_FAILSAFE :
    case BIC_EXTRACTION_FAILSAFE :
        // ignore failsafe mode
        break;
    default :
        break;
    }

    return NOTIFY_OK;
}

static struct notifier_block pif_insert_nb =
{
    .notifier_call = pif_notify,
    .priority      = INSERT_PRIORITY_PIF,
};

static struct notifier_block pif_extract_nb =
{
    .notifier_call = pif_notify,
    .priority      = EXTRACT_PRIORITY_PIF,
};

//
// Register for notifications from the BIC
//
static int __init pif_module_init(void)
{
    void *ptr;

    // Get slot_cnt from common module?
    if (slot_cnt == (uint)-1) slot_cnt = common_get_slot_cnt();

    // range check
    if ((slot_cnt < 1) || (slot_cnt > SYS_MAX_SLOTS))
    {
        pr_err(PIF_DEV_STR " : slot count of '%d' is out of range\n", slot_cnt);
        return -EINVAL;
    }

    // announce our intentions
    pr_notice(PIF_DEV_STR " : install driver for %d slots\n", slot_cnt);

    // allocate net_device data structure pointers
    ptr = kcalloc(slot_cnt, sizeof(struct net_device*), GFP_KERNEL);
    if (ptr == NULL)
    {
        pr_err(PIF_DEV_STR " : unable to allocate device memory\n");
        return -ENOMEM;
    }

    // we now have an array of pointers to net_devices
    pif_dev = (struct net_device**)ptr;

    // set up the procfs
    pif_proc_module_init(slot_cnt);

    common_register_insert_notifier(&pif_insert_nb);
    common_register_extract_notifier(&pif_extract_nb);

    pr_notice(PIF_DEV_STR " : module loaded\n");
    return 0;
}

//
// Unregister for notifications from the BIC
//
static void __exit pif_module_exit(void)
{
    common_register_extract_notifier(&pif_extract_nb);
    common_unregister_insert_notifier(&pif_insert_nb);

    kfree(pif_dev);
    pif_proc_module_exit();
}

module_init(pif_module_init);
module_exit(pif_module_exit);
