use std::{
    collections::{HashMap, VecDeque},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Instant,
};
use chrono::{DateTime, Local};
use crate::constants::{MAX_SAMPLES, TICK_RATE_MS};

// From capture thread to UI thread
pub struct SharedStats {
    pub traffic_delta: HashMap<Ipv4Addr, u64>,
    pub rx_delta: u64,
    pub tx_delta: u64,
}

// Single IP history record
pub struct IpHistory {
    pub samples: VecDeque<u64>,
    pub total_sum: u64,
    pub peak_rate: f64,
    pub peak_time: DateTime<Local>,
}

impl IpHistory {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES),
            total_sum: 0,
            peak_rate: 0.0,
            peak_time: Local::now(),
        }
    }

    pub fn update(&mut self, bytes: u64) -> f64 {
        let instant_rate = (bytes as f64) * (1000.0 / TICK_RATE_MS as f64);

        if instant_rate > self.peak_rate {
            self.peak_rate = instant_rate;
            self.peak_time = Local::now();
        }

        self.samples.push_back(bytes);
        self.total_sum += bytes;
        if self.samples.len() > MAX_SAMPLES {
            if let Some(removed) = self.samples.pop_front() {
                self.total_sum -= removed;
            }
        }

        let duration_secs = self.samples.len() as f64 * (TICK_RATE_MS as f64 / 1000.0);
        if duration_secs == 0.0 {
            0.0
        } else {
            self.total_sum as f64 / duration_secs
        }
    }
}

// Main application state
pub struct App {
    pub rx_history: Vec<f64>,
    pub tx_history: Vec<f64>,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
    pub peak_rx_record: (f64, DateTime<Local>),
    pub peak_tx_record: (f64, DateTime<Local>),
    
    ip_histories: HashMap<Ipv4Addr, IpHistory>,
    
    // UI display of top talkers
    pub top_talkers: Vec<(Ipv4Addr, f64, f64, DateTime<Local>)>,
    pub last_tick: Instant,
}

impl App {
    pub fn new() -> App {
        let now = Local::now();
        App {
            rx_history: vec![0.0; MAX_SAMPLES],
            tx_history: vec![0.0; MAX_SAMPLES],
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            peak_rx_record: (0.0, now),
            peak_tx_record: (0.0, now),
            ip_histories: HashMap::new(),
            top_talkers: vec![],
            last_tick: Instant::now(),
        }
    }

    pub fn on_tick(&mut self, shared_stats: &Arc<Mutex<SharedStats>>) {
        let mut stats = shared_stats.lock().unwrap();

        // Update overall RX/TX history
        self.rx_history.remove(0);
        self.rx_history.push(stats.rx_delta as f64);
        self.tx_history.remove(0);
        self.tx_history.push(stats.tx_delta as f64);

        self.total_rx_bytes += stats.rx_delta;
        self.total_tx_bytes += stats.tx_delta;

        let current_rx_rate = (stats.rx_delta as f64) * (1000.0 / TICK_RATE_MS as f64);
        let current_tx_rate = (stats.tx_delta as f64) * (1000.0 / TICK_RATE_MS as f64);

        if current_rx_rate > self.peak_rx_record.0 {
            self.peak_rx_record = (current_rx_rate, Local::now());
        }
        if current_tx_rate > self.peak_tx_record.0 {
            self.peak_tx_record = (current_tx_rate, Local::now());
        }

        // Update per-IP histories and top talkers
        let mut all_ips: Vec<Ipv4Addr> = self.ip_histories.keys().cloned().collect();
        for k in stats.traffic_delta.keys() {
            if !self.ip_histories.contains_key(k) {
                all_ips.push(*k);
            }
        }

        let mut current_snapshot = Vec::new();
        for ip in all_ips {
            let bytes_in = *stats.traffic_delta.get(&ip).unwrap_or(&0);
            let history = self.ip_histories.entry(ip).or_insert_with(IpHistory::new);

            let avg_bps = history.update(bytes_in);

            if history.total_sum > 0 || history.peak_rate > 0.0 {
                current_snapshot.push((ip, avg_bps, history.peak_rate, history.peak_time));
            } else {
                self.ip_histories.remove(&ip);
            }
        }

        current_snapshot.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        self.top_talkers = current_snapshot;

        stats.traffic_delta.clear();
        stats.rx_delta = 0;
        stats.tx_delta = 0;
    }
}
