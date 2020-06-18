/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * bridge.c - send all packets from one port out the other.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ip_frag.h>

#include "logger.h"
#include "config.h"
#include "logger.h"
#include "pktbuf.h"
#include "netstack/arp.h"
#include "netstack/ether.h"

#include "node.h"
#include "stats.h"
#include "gtp_process.h"


#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "bridge"

/* DEFINES */
#define MAX_RX_BURST_COUNT 8
#define PREFETCH_OFFSET 4

/* GLOBALS */
volatile uint8_t keep_running = 1;

/* EXTERN */
extern app_confg_t app_config;
extern numa_info_t numa_node_info[GTP_MAX_NUMANODE];
extern pkt_stats_t port_pkt_stats[GTP_CFG_MAX_PORTS];

static void sigint_handler(__attribute__((unused)) int signo);
static int add_interfaces(void);
static int add_static_arp(void);
static __rte_always_inline void process_pkt_mbuf(struct rte_mbuf *m, uint8_t port);

uint32_t print_delay = 10000;

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;
        if (counter++ == print_delay) {
		// Show stats
		printf("\n DISP_STATS=%s\n", app_config.disp_stats ? "ON" : "OFF");

		while (keep_running) {
			if (app_config.disp_stats) {
				show_static_display();
			}
		}
		counter = 0;
        }

        if (pkt->port == 0) {
                meta->destination = 1;
        } else {
                meta->destination = 0;
        }
        meta->action = ONVM_NF_ACTION_OUT;
        return 0;
}

int
main(int argc, char *argv[]) {
	printf("yaha \n");
	logger_init();
	printf("yaha \n");

	int32_t i;
	int32_t ret;

    
        int arg_offset;
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;

	printf("yaha \n");
        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

    // Check Huge pages for memory buffers
    ret = rte_eal_has_hugepages();
    if (ret < 0) {
        rte_panic("\n ERROR: no Huge Page\n");
        exit(EXIT_FAILURE);
    }
	// Load ini config file
	ret = load_config();
	if (ret < 0) {
		printf("\n ERROR: failed to load config\n");
		return -1;
	}


	ret = populate_node_info();
	if (ret < 0) {
		rte_panic("\n ERROR: in populating NUMA node Info\n");
		exit(EXIT_FAILURE);
	}
	printf("\n");

	// Init ARP table
	ret = arp_init(0);
	assert(ret == 0);

	// Add interface info to interface and arp table
	ret = add_interfaces();
	assert(ret == 0);


	// Add static arp
	ret = add_static_arp();
	assert(ret == 0);

#if 0
	// Set interface options and queues
	if (node_interface_setup() < 0) {
		rte_panic("ERROR: interface setup Failed\n");
		exit(EXIT_FAILURE);
	}
#endif

	// Register signals
	signal(SIGINT, sigint_handler);
	signal(SIGUSR1, sig_extra_stats);
	signal(SIGUSR2, sig_config);

        argc -= arg_offset;
        argv += arg_offset;

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
	// Free resources
	printf("\n\nCleaning...\n");
#if 0
	arp_terminate();
#endif
	printf("Done.\n");
	return 0;
}

static void
sigint_handler(__attribute__((unused)) int signo)
{
    keep_running = 0;
}

static int
add_interfaces(void)
{
    int32_t i;
    uint16_t avail_dev_count = rte_eth_dev_count_avail();
    struct rte_ether_addr addr;

    // Check interfaces in app configs
    if (app_config.gtp_port_count == 0 || app_config.gtp_port_count % 2 != 0) {
        logger(LOG_APP, L_CRITICAL,
            "Number of interface in config (%d) should be even and larger than zero\n",
            app_config.gtp_port_count, avail_dev_count);
        return -1;
    } else if (app_config.gtp_port_count > avail_dev_count) {
        logger(LOG_APP, L_CRITICAL,
            "Number of interface in config (%d) > avail dpdk eth devices (%d), abort.\n",
            app_config.gtp_port_count, avail_dev_count);
        return -1;
    }

    for (i = 0; i < app_config.gtp_port_count; i++) {
        if (app_config.gtp_ports[i].port_num >= avail_dev_count) {
            logger(LOG_APP, L_CRITICAL,
                "Interface index #%d in config >= avail dpdk eth devices (%d), abort.\n",
                app_config.gtp_ports[i].port_num, avail_dev_count);
            return -1;
        }
    }

    if (app_config.gtp_port_count != avail_dev_count) {
        logger(LOG_APP, L_WARN,
            "Notice: number of interface in config (%d) != avail dpdk eth devices (%d)\n",
            app_config.gtp_port_count, avail_dev_count);
    }

    // Add interface
    for (i = 0; i < app_config.gtp_port_count; i++) {
        confg_gtp_port_t *port_config = &app_config.gtp_ports[i];
        interface_t iface;

        rte_eth_macaddr_get(port_config->port_num, &addr);

        iface.port = port_config->port_num;
        iface.ipv4_addr = port_config->ipv4;
        memcpy(iface.hw_addr, addr.addr_bytes, sizeof(iface.hw_addr));

        add_interface(&iface);
    }

    return 0;
}

static int
add_static_arp(void)
{
    int32_t i, ret;
    arp_entry_t *arp_entry;

    for (i = 0; i < app_config.static_arp_count; i++) {
        arp_entry = &app_config.static_arps[i];
        ret = arp_add_mac(arp_entry->ipv4_addr, arp_entry->mac_addr, 1);
        if (ret != 0)
            return -1;
    }

    return 0;
}

static __rte_always_inline void
process_pkt_mbuf(struct rte_mbuf *m, uint8_t port)
{
    struct rte_ether_hdr *eth_hdr = NULL;
    struct rte_ipv4_hdr *ip_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;
    gtpv1_t *gtp1_hdr = NULL;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    printf_dbg("\n [RX] Port#%u ", m->port);
    printf_dbg("Ether(type:0x%x dmac: %x:%x:%x:%x:%x:%x) ",
        eth_hdr->ether_type,
        eth_hdr->d_addr.addr_bytes[0], eth_hdr->d_addr.addr_bytes[1],
        eth_hdr->d_addr.addr_bytes[2], eth_hdr->d_addr.addr_bytes[3],
        eth_hdr->d_addr.addr_bytes[4], eth_hdr->d_addr.addr_bytes[5]);

    // printf_dbg("smac: %x:%x:%x:%x:%x:%x) ",
    //     eth_hdr->s_addr.addr_bytes[0], eth_hdr->s_addr.addr_bytes[1],
    //     eth_hdr->s_addr.addr_bytes[2], eth_hdr->s_addr.addr_bytes[3],
    //     eth_hdr->s_addr.addr_bytes[4], eth_hdr->s_addr.addr_bytes[5]);

    // Test: forward all non-gtpu packets
    // int fwd_port = 1;
    // int ret = rte_eth_tx_burst(fwd_port, 0, &m, 1);
    // printf(" fwd to port#%d ret=%d\n", fwd_port, ret);
    // assert(likely(ret == 1));
    // return;

    // Ether type: IPv4 (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) = 0x8)
    if (likely(eth_hdr->ether_type == 0x8)) {
        ip_hdr = (struct rte_ipv4_hdr *)((char *)(eth_hdr + 1));
        printf_dbg(" IPv4(");
        print_rte_ipv4_dbg(ip_hdr->src_addr);
        printf_dbg(" -> ");
        print_rte_ipv4_dbg(ip_hdr->dst_addr);
        printf_dbg(") ");

        // Check IP is fragmented
        if (unlikely(rte_ipv4_frag_pkt_is_fragmented(ip_hdr))) {
            port_pkt_stats[port].ipFrag += 1;
            goto out_flush;
        }

        // Check for UDP
        // printf(" protocol: %x ", ip_hdr->next_proto_id);
        if (likely(ip_hdr->next_proto_id == 0x11)) {
            udp_hdr = (struct rte_udp_hdr *)((char *)(ip_hdr + 1));
            printf_dbg(" UDP(port src:%d dst:%d) ",
                rte_cpu_to_be_16(udp_hdr->src_port),
                rte_cpu_to_be_16(udp_hdr->dst_port));

            /* GTPU LTE carries V1 only 2152 (htons(2152) = 0x6808) */
            if (likely(udp_hdr->src_port == 0x6808 ||
                       udp_hdr->dst_port == 0x6808)) {
                gtp1_hdr = (gtpv1_t *)((char *)(udp_hdr + 1));
                printf_dbg(" GTP-U(type:0x%x, teid:%d) ", gtp1_hdr->type, ntohl(gtp1_hdr->teid));

                // Check if gtp version is 1
                if (unlikely(gtp1_hdr->flags >> 5 != 1)) {
                    printf(" NonGTPVer(gtp1_hdr->ver:%d)\n", gtp1_hdr->flags >> 5);
                    port_pkt_stats[port].non_gtpVer += 1;
                    goto out_flush;
                }

                // Check if msg type is PDU
                if (unlikely(gtp1_hdr->type != 0xff)) {
                    printf(" DROP(gtp1_hdr->type:%d)\n", gtp1_hdr->type);
                    port_pkt_stats[port].dropped += 1;
                    goto out_flush;
                }

                // GTP decap
                if (likely(process_gtpv1(m, port, gtp1_hdr) > 0)) {
                    return;
                } else {
                    printf_dbg(" ERR(decap failed)\n");
                    port_pkt_stats[port].decap_err += 1;
                    goto out_flush;
                }
            } else {
                port_pkt_stats[port].non_gtp += 1;
            } /* (unlikely(udp_hdr->src|dst_port != 2123)) */
        } else {
            port_pkt_stats[port].non_udp += 1;
        } /* (unlikely(ip_hdr->next_proto_id != 0x11)) */

        // GTP encap
        if (likely(process_ipv4(m, port, ip_hdr) > 0)) {
            return;
        } else {
            printf_dbg(" ERR(encap failed)\n");
            port_pkt_stats[port].encap_err += 1;
            goto out_flush;
        }

    } else {
        port_pkt_stats[port].non_ipv4 += 1;

        // Ether type: ARP
        if (unlikely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))) {
            arp_in(m);
            goto out_flush;
        }
    } /* (likely(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) */

out_flush:
    fflush(stdout);
    rte_pktmbuf_free(m);
}
