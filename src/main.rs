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
use pnet::ipnetwork::Ipv4Network;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let cidr_arg = args.get(1);

    let filter_cidr: Option<Ipv4Network> = match cidr_arg {
        Some(s) => {
            match s.parse() {
                Ok(net) => {
                    println!("Filter mode: Targeting subnet {}", net);
                    Some(net)
                },
                Err(_) => {
                    eprintln!("Invalid CIDR provided '{}', falling back to default private ranges.", s);
                    None
                }
            }
        },
        None => {
            println!("No subnet provided. Targeting all standard private networks (RFC1918).");
            None
        }
    };
    // network module to get default device and local IP
    let (device, local_ip) = network::get_default_device()?;
    let device_name = device.name.clone();

    // shared stats between capture thread and UI thread
    let stats = Arc::new(Mutex::new(SharedStats {
        traffic_delta: HashMap::new(),
        rx_delta: 0,
        tx_delta: 0,
    }));

    network::start_capture_thread(device, local_ip, Arc::clone(&stats), filter_cidr)?;
    ui::run(stats, &device_name)?;

    Ok(())
}
