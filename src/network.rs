use std::{
    error::Error,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread,
};
use pcap::{Capture, Device};
use pnet::datalink;
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    Packet,
};
use crate::app::SharedStats;
use pnet::ipnetwork::Ipv4Network; 

pub fn get_local_ip(device_name: &str) -> Option<Ipv4Addr> {
    let interfaces = datalink::interfaces();
    let iface = interfaces.into_iter().find(|i| i.name == device_name)?;
    iface.ips.iter().find_map(|ip| {
        if let pnet::ipnetwork::IpNetwork::V4(net) = ip {
            Some(net.ip())
        } else {
            None
        }
    })
}

pub fn is_rfc1918_private(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    (octets[0] == 192 && octets[1] == 168) ||
    (octets[0] == 10) ||
    (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
}

pub fn get_default_device() -> Result<(Device, Ipv4Addr), Box<dyn Error>> {
    let device = Device::lookup()?.ok_or("No default device found")?;
    let device_name = device.name.clone();
    let local_ip = get_local_ip(&device_name).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
    Ok((device, local_ip))
}

fn should_track_ip(ip: &Ipv4Addr, filter_cidr: Option<Ipv4Network>) -> bool {
    match filter_cidr {
        // If a CIDR is provided (e.g.,
        Some(network) => network.contains(*ip),
        None => is_rfc1918_private(ip),
    }
}

// Start a background packet capture thread
pub fn start_capture_thread(
    device: Device, 
    local_ip: Ipv4Addr, 
    stats: Arc<Mutex<SharedStats>>
    , filter_cidr: Option<Ipv4Network>
) -> Result<(), Box<dyn Error>> {
    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(10)
        .open()?;

    thread::spawn(move || loop {
        if let Ok(packet) = cap.next_packet() {
            if let Some(ethernet) = EthernetPacket::new(packet.data) {
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        let len = packet.header.len as u64;
                        let src = ipv4.get_source();
                        let dst = ipv4.get_destination();

                        let mut s = stats.lock().unwrap();

                        // Track total transmitted and received bytes
                        if src == local_ip {
                            s.tx_delta += len;
                        } else {
                            s.rx_delta += len;
                        }

                        // Track per-IP traffic for LAN IPs
                        if should_track_ip(&src, filter_cidr) {
                            *s.traffic_delta.entry(src).or_insert(0) += len;
                        }
                        if should_track_ip(&dst, filter_cidr) {
                            *s.traffic_delta.entry(dst).or_insert(0) += len;
                        }
                    }
                }
            }
        }
    });
    
    Ok(())
}
