mod app;
mod constants;
mod network;
mod ui;
mod util;

use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
};
use app::SharedStats;

fn main() -> Result<(), Box<dyn Error>> {
    // network module to get default device and local IP
    let (device, local_ip) = network::get_default_device()?;
    let device_name = device.name.clone();

    // shared stats between capture thread and UI thread
    let stats = Arc::new(Mutex::new(SharedStats {
        traffic_delta: HashMap::new(),
        rx_delta: 0,
        tx_delta: 0,
    }));

    network::start_capture_thread(device, local_ip, Arc::clone(&stats))?;
    ui::run(stats, &device_name)?;

    Ok(())
}
