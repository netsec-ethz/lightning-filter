use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::{Metric, Registry};

pub struct PrometheusMetrics {
    pub collector_count_total: PrometheusMetric<Family<CollectorCountLabel, Gauge>>,
    pub ethdev_stats: PrometheusMetric<Family<EthdevStatsLabels, Gauge>>,
    pub lf_worker_stats: PrometheusMetric<Family<LFWorkerStatsLabels, Gauge>>,
    pub lf_keymanager_stats: PrometheusMetric<Family<LFKeymanagerStatsLabels, Gauge>>,
    pub lf_keymanager_dict: PrometheusMetric<Family<LFKeymanagerDictLabels, Gauge>>,
}

impl PrometheusMetrics {
    pub fn new() -> Self {
        PrometheusMetrics {
            collector_count_total: PrometheusMetric {
                name: "lf_monitor_collecting_total".to_string(),
                help: "Number of times the lf-monitor has collected stats".to_string(),
                metric: Family::default(),
            },
            ethdev_stats: PrometheusMetric {
                name: "dpdk_ethdev_stats".to_string(),
                help: "DPDK ethdev statistics".to_string(),
                metric: Family::default(),
            },
            lf_worker_stats: PrometheusMetric {
                name: "dpdk_lf_worker_stats".to_string(),
                help: "DPDK LF worker statistics".to_string(),
                metric: Family::default(),
            },
            lf_keymanager_stats: PrometheusMetric {
                name: "dpdk_lf_keymanager_stats".to_string(),
                help: "DPDK LF keymanager statistics".to_string(),
                metric: Family::default(),
            },
            lf_keymanager_dict: PrometheusMetric {
                name: "dpdk_lf_keymanager_dict".to_string(),
                help: "DPDK LF keymanager dictionary statistics".to_string(),
                metric: Family::default(),
            },
        }
    }
}

pub struct PrometheusMetric<T> {
    pub name: String,
    pub help: String,
    pub metric: T,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct CollectorCountLabel {
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EthdevStatsLabels {
    pub port_id: i16,
    pub port_name: String,
    pub metric: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LFWorkerStatsLabels {
    pub worker_id: i16,
    pub metric: String,
}



#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LFKeymanagerStatsLabels {
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct LFKeymanagerDictLabels {
    pub key: String,
}

pub fn new_registry(metrics : &PrometheusMetrics) -> Registry {
    let mut registry = Registry::default();
    register_metrics(&mut registry, metrics);
    registry
}

fn register_metrics(registry: &mut Registry, metrics : &PrometheusMetrics) {
    register_metric(registry, &metrics.collector_count_total);
    register_metric(registry, &metrics.ethdev_stats);
    register_metric(registry, &metrics.lf_worker_stats);
    register_metric(registry, &metrics.lf_keymanager_stats);
    register_metric(registry, &metrics.lf_keymanager_dict);
}

fn register_metric<T: Metric + Clone>(registry: &mut Registry, metric: &PrometheusMetric<T>) {
    registry.register(
        metric.name.to_string(),
        metric.help.to_string(),
        metric.metric.clone(),
    );
}