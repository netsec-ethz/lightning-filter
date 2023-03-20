
#include <rte_eal.h>
#include <rte_ethdev.h>

#include "lib/log/log.h"
#include "setup.h"
#include "worker_ct.h"

#define LF_WORKER_CT_LOG(level, ...)                                        \
	LF_LOG(level,                                                           \
			RTE_FMT("Worker Control Traffic: " RTE_FMT_HEAD(__VA_ARGS__, ), \
					RTE_FMT_TAIL(__VA_ARGS__, )))

int
lf_worker_ct_run(struct lf_worker_ct *ctx)
{
	struct lf_setup_ct_port_queue signal_port_queue = ctx->signal_port_queue;
	uint16_t port_id;
	uint16_t vport_id;
	uint16_t rx_queue_id;
	uint16_t tx_queue_id;

	struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST];
	uint16_t nb_rx;

	LF_WORKER_CT_LOG(DEBUG, "run\n");
	RTE_ETH_FOREACH_DEV(port_id) {
		if ((signal_port_queue.portmask & (1 << port_id)) == 0) {
			continue;
		}
		LF_WORKER_CT_LOG(DEBUG,
				"port %d (rx: %d, tx: %d), vport %d (rx: %d, tx: %d)\n",
				port_id, signal_port_queue.rx_queue_id[port_id],
				signal_port_queue.tx_queue_id[port_id],
				signal_port_queue.vport_id[port_id], 0, 0);
	}


	while (likely(!lf_force_quit)) {
		RTE_ETH_FOREACH_DEV(port_id) {
			if ((signal_port_queue.portmask & (1 << port_id)) == 0) {
				continue;
			}

			rx_queue_id = signal_port_queue.rx_queue_id[port_id];
			tx_queue_id = signal_port_queue.tx_queue_id[port_id];
			vport_id = signal_port_queue.vport_id[port_id];

			/* Incoming signal packets */
			nb_rx = rte_eth_rx_burst(port_id, rx_queue_id, rx_pkts,
					LF_MAX_PKT_BURST);
			if (nb_rx > 0) {
				LF_WORKER_CT_LOG(DEBUG, "Received incoming signal packet!\n");
			}
			rte_eth_tx_burst(vport_id, 0, rx_pkts, nb_rx);

			/* Outgoing signal packets */
			nb_rx = rte_eth_rx_burst(vport_id, 0, rx_pkts, LF_MAX_PKT_BURST);
			if (nb_rx > 0) {
				LF_WORKER_CT_LOG(DEBUG, "Received outgoing signal packet!\n");
			}
			rte_eth_tx_burst(port_id, tx_queue_id, rx_pkts, nb_rx);
		}
	}

	return 0;
}