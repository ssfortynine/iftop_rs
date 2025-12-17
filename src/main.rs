use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::io::stdout;
use std::thread;
use std::time::{Duration, Instant};
use std::net::Ipv4Addr;

use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

use pcap::{Capture, Device};

use crossterm::{execute, terminal::{Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen}, cursor};


// 定义一个结构体来存储流量方向
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct Connection {
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取默认网卡
    let device = Device::lookup()?.ok_or("No device available")?;
    println!("Listening on device: {}", device.name);

    // 打开网卡进行数据包捕获
    let mut cap = Capture::from_device(device)?
        .promisc(true) // 混杂模式，捕获所有流经网卡的数据包
        .snaplen(65535)
        .timeout(100)
        .open()?;

    // 共享状态：存储连接和对应字节数
    // Key: Connnection, Valut: Bytes
    let stats = Arc::new(Mutex::new(HashMap::<Connection, u64>::new()));

    // 克隆引用方便在UI线程中使用
    let stats_ui = Arc::clone(&stats);

    // 启动UI线程
    thread::spawn(move || {
        let _ = execute!(stdout(), EnterAlternateScreen); // 进入备用屏幕
        loop {
            thread::sleep(Duration::from_secs(1));
            let mut map = stats_ui.lock().unwrap();

            // 清屏
            let _ = execute!(stdout(), Clear(ClearType::All), cursor::MoveTo(0,0));
            
            println!("{:<20} -> {:<20} {:>10}", "Source", "Destination", "Bytes/s");
            println!("{}", "-".repeat(60));

            // 将HashMap转为Vec以便排序
            let mut sorted_conns: Vec<(&Connection, &u64)> = map.iter().collect();
            // 按流量从小到大排序
            sorted_conns.sort_by(|a,b| b.1.cmp(a.1));

            // 显示 Top 20
            for (conn, bytes) in sorted_conns.iter().take(20) {
                println!("{:<20} -> {:<20} | {}", conn.src, conn.dst, format_bytes(**bytes));
            }


            map.clear(); // 清空统计数据以便下一个周期重新统计
        }
    });

    // 处理Ctrl+C信号以优雅退出
    ctrlc::set_handler(move || {
        let _ = execute!(stdout(), LeaveAlternateScreen); // 离开备用屏幕
        std::process::exit(0);
    })?;

    // 主线程循环捕获数据包
    loop {
        // 获取下一个包（可能会因为timout而返回None）
        match cap.next_packet() {
            Ok(packet) => {
                // 解析以太网包
                if let Some(ethernet) =  EthernetPacket::new(packet.data){
                    // 只处理IPv4包，简化处理
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()){
                            let src = ipv4.get_source();
                            let dst = ipv4.get_destination();
                            let len = ipv4.get_total_length() as u64;
                            // 更新统计数据
                            let mut map = stats.lock().unwrap();
                            let conn = Connection { src, dst };
                            *map.entry(conn).or_insert(0) += len;
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // 超时，继续等待下一个包
                continue;
            }
            Err(e) => {
                println!("Error capturing packet: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

// 辅助函数： 格式化字节数为人类可读形式
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

