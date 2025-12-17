use pcap::{Device, Capture};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use crossterm::{execute, terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen}, cursor};
use std::io::stdout;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 获取网卡
    let device = Device::lookup()?.ok_or("No default device found")?;
    println!("Listening on device: {}", device.name);

    // 2. 开启混杂模式抓包
    let mut cap = Capture::from_device(device)?
        .promisc(true) 
        .snaplen(65535)
        .timeout(100)
        .open()?;

    // 统计：IP地址 -> 字节数
    let stats = Arc::new(Mutex::new(HashMap::<Ipv4Addr, u64>::new()));
    let stats_ui = Arc::clone(&stats);

    // 3. UI 线程
    thread::spawn(move || {
        let _ = execute!(stdout(), EnterAlternateScreen);
        loop {
            thread::sleep(Duration::from_secs(1));
            let mut map = stats_ui.lock().unwrap();

            let _ = execute!(stdout(), Clear(ClearType::All), cursor::MoveTo(0, 0));
            println!("{:<20} | {:<15}", "LAN Device IP", "Bandwidth Usage");
            println!("{}", "-".repeat(40));

            // 排序
            let mut sorted: Vec<(&Ipv4Addr, &u64)> = map.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));

            // 显示 Top 10
            for (ip, bytes) in sorted.iter().take(10) {
                println!("{:<20} | {}", ip, format_bytes(**bytes));
            }

            map.clear();
        }
    });

    ctrlc::set_handler(|| {
        let _ = execute!(stdout(), LeaveAlternateScreen);
        std::process::exit(0);
    })?;

    // 4. 抓包循环
    loop {
        if let Ok(packet) = cap.next_packet() {
            if let Some(ethernet) = EthernetPacket::new(packet.data) {
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        let src = ipv4.get_source();
                        let dst = ipv4.get_destination();
                        let len = packet.header.len as u64;

                        let mut map = stats.lock().unwrap();

                        // 简单的启发式逻辑：
                        // 如果源IP是局域网IP (192.168.x.x)，则记为该IP使用了流量
                        // 如果目标IP是局域网IP，也记为该IP使用了流量
                        // 注意：你需要根据你实际的网段修改这里的判断逻辑
                        if is_lan_ip(&src) {
                            *map.entry(src).or_insert(0) += len;
                        }
                        if is_lan_ip(&dst) {
                            *map.entry(dst).or_insert(0) += len;
                        }
                    }
                }
            }
        }
    }
}

// 辅助函数：判断是否是局域网IP (你需要根据实际情况修改，比如 10.x.x.x 或 172.16.x.x)
fn is_lan_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 假设局域网是 192.168.x.x
    octets[0] == 192 && octets[1] == 168 && octets[2] == 5
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    if bytes >= MB { format!("{:.2} MB/s", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.2} KB/s", bytes as f64 / KB as f64) }
    else { format!("{} B/s", bytes) }
}
