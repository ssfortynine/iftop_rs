mod app;
mod constants;
mod network;
mod ui;
mod util;
mod spoof;

use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex},
    env,
};
use app::SharedStats;
use pnet::ipnetwork::Ipv4Network;
use spoof::ArpSpoofer;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    let mut interface_arg: Option<String> = None;
    let mut filter_cidr: Option<Ipv4Network> = None;
    let mut spoof_target: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            // --spoof 192.168.5.1
            "--spoof" => {
                if i + 1 < args.len() {
                    spoof_target = Some(args[i+1].clone());
                    i += 1;
                }
            }
            // --dev eth0 (select network interface)
            "--dev" => {
                if i + 1 < args.len() {
                    interface_arg = Some(args[i+1].clone());
                    i += 1;
                }
            }
            val => {
                if let Ok(net) = val.parse::<Ipv4Network>() {
                    filter_cidr = Some(net);
                    println!("Filter mode: Targeting subnet {}", net);
                }
            }
        }
        i += 1;
    }

    // network module to get default device and local IP
    let (device, local_ip) = network::get_default_device()?;
    let device_name = device.name.clone();
    println!("Starting capture on device: {} ({})", device_name, local_ip);

    let mut _spoofer = ArpSpoofer::new();
    if let Some(target) = spoof_target {
        match _spoofer.start(&device_name, &target) {
            Ok(_) => println!(" [!] ARP Spoofing active against {}", target),
            Err(e) => eprintln!(" [X] Failed to start arpspoof: {}. Is 'dsniff' installed?", e),
        }
    }

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
