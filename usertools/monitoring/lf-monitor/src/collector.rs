use std::thread;
use serde_json::{Result, Value};

use crate::prometheus::{EthdevStatsLabels, LFKeymanagerStatsLabels, LFKeymanagerDictLabels, PrometheusMetric, PrometheusMetrics};
use crate::dpdk::DpdkTelemetry;

pub struct Collector {
    dpdk_telemetry: DpdkTelemetry,
    prometheus_metrics: PrometheusMetrics,
    period: std::time::Duration,
}

impl Collector {

    pub fn new(dpdk_telemetry: DpdkTelemetry, prometheus_metrics: PrometheusMetrics) -> Self {
        Collector {
            dpdk_telemetry: dpdk_telemetry,
            prometheus_metrics: prometheus_metrics,
            // Default
            period: std::time::Duration::from_secs(1),
        }
    }

    pub fn run(&self) {
        loop {
            self.collect();
            thread::sleep(self.period);
        }
    }

    fn collect(&self) {
        println!("Collecting metrics");
        self.collect_ethdev();
        self.collect_lf();
    }

    fn collect_ethdev(&self) {
        // parameter list for ethdev metrics
        let list: Value = self.dpdk_telemetry.query("/ethdev/list");
        let intfs = list["/ethdev/list"].as_array().unwrap();

        for intf in intfs {
            // Get interface name from info
            let info_path = ["/ethdev/info", &intf.to_string()].join(",");
            let info_result = self.dpdk_telemetry.query(&info_path);
            let info = info_result["/ethdev/info"].as_object().unwrap();
            let intf_name = info["name"].as_str().unwrap();

            // Get stats
            let stats_path = ["/ethdev/stats", &intf.to_string()].join(",");
            let result = self.dpdk_telemetry.query(&stats_path);
            let stats = result["/ethdev/stats"].as_object().unwrap();
            for (key, value) in stats {
                if !value.is_number(){
                    continue;
                }
                let value = value.as_i64().unwrap();
                let labels = EthdevStatsLabels {
                    port_id: intf.as_i64().unwrap(),
                    port_name: intf_name.to_string(),
                    key: key.to_string(),
                };
                let counter = self.prometheus_metrics.ethdev_stats.metric.get_or_create(&labels);
                counter.set(value);
            }
        }
    }

    fn collect_lf(&self) {
        self.collect_lf_keymanager();
    }

    fn collect_lf_keymanager(&self) {
        let result = self.dpdk_telemetry.query("/lf/keymanager/stats");
        let stats = result["/lf/keymanager/stats"].as_object().unwrap();
        for (key, value) in stats {
            if !value.is_number(){
                continue;
            }
            let value = value.as_i64().unwrap();
            let labels = LFKeymanagerStatsLabels {
                result: key.to_string(),
            };
            let counter = self.prometheus_metrics.lf_keymanager_stats.metric.get_or_create(&labels);
            counter.set(value);
        }

        let result = self.dpdk_telemetry.query("/lf/keymanager/dict");
        let dict = result["/lf/keymanager/dict"].as_object().unwrap();
        for (key, value) in dict {
            if !value.is_number(){
                continue;
            }
            let value = value.as_i64().unwrap();
            let labels = LFKeymanagerDictLabels {
                key: key.to_string(),
            };
            let counter = self.prometheus_metrics.lf_keymanager_dict.metric.get_or_create(&labels);
            counter.set(value);
        }
    }
}
