use chrono::Local; // 用于获取当前时间
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dns_lookup::lookup_addr; // DNS 反向解析
use pcap::{Capture, Device};
use pnet::datalink;
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    Packet,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    symbols::Marker,
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Line as CanvasLine},
        Block, Borders, Cell, Paragraph, Row, Table,
    },
    Terminal,
};
use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

// ----------------------
// 常量定义
// ----------------------
const TICK_RATE_MS: u64 = 500;
const HISTORY_WINDOW_SECS: u64 = 60;
const MAX_SAMPLES: usize = (HISTORY_WINDOW_SECS * 1000 / TICK_RATE_MS) as usize;

// ----------------------
// 数据结构
// ----------------------

struct SharedStats {
    traffic_delta: HashMap<Ipv4Addr, u64>,
    rx_delta: u64,
    tx_delta: u64,
}

// 单个 IP 的详细数据
struct IpMetrics {
    samples: VecDeque<u64>,
    total_sum: u64,
    
    // 新增：峰值记录
    peak_bps: f64,
    peak_time: String,
}

impl IpMetrics {
    fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES),
            total_sum: 0,
            peak_bps: 0.0,
            peak_time: "-".to_string(),
        }
    }

    fn update(&mut self, bytes: u64) -> f64 {
        self.samples.push_back(bytes);
        self.total_sum += bytes;
        if self.samples.len() > MAX_SAMPLES {
            if let Some(removed) = self.samples.pop_front() {
                self.total_sum -= removed;
            }
        }
        let duration_secs = self.samples.len() as f64 * (TICK_RATE_MS as f64 / 1000.0);
        let current_bps = if duration_secs == 0.0 { 0.0 } else { self.total_sum as f64 / duration_secs };

        // 记录峰值
        if current_bps > self.peak_bps {
            self.peak_bps = current_bps;
            self.peak_time = Local::now().format("%H:%M:%S").to_string();
        }

        current_bps
    }
}

struct App {
    rx_history: Vec<f64>,
    tx_history: Vec<f64>,
    total_rx_bytes: u64,
    total_tx_bytes: u64,
    peak_rx_rate: u64,
    peak_tx_rate: u64,

    // IP 统计数据
    ip_stats: HashMap<Ipv4Addr, IpMetrics>,
    
    // DNS 缓存：IP -> Hostname (Arc<Mutex<>> 用于跨线程共享)
    dns_cache: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
    // 记录已经发起过查询的 IP，避免重复查询
    dns_query_sent: Vec<Ipv4Addr>,

    // 用于显示的排序列表
    top_talkers: Vec<(Ipv4Addr, f64, String, f64, String)>, // IP, Current, Hostname, Peak, PeakTime
    
    last_tick: Instant,
}

impl App {
    fn new() -> App {
        App {
            rx_history: vec![0.0; MAX_SAMPLES],
            tx_history: vec![0.0; MAX_SAMPLES],
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            peak_rx_rate: 0,
            peak_tx_rate: 0,
            ip_stats: HashMap::new(),
            dns_cache: Arc::new(Mutex::new(HashMap::new())),
            dns_query_sent: Vec::new(),
            top_talkers: vec![],
            last_tick: Instant::now(),
        }
    }

    fn on_tick(&mut self, shared_stats: &Arc<Mutex<SharedStats>>) {
        let mut stats = shared_stats.lock().unwrap();

        // 1. 全局图表
        self.rx_history.remove(0);
        self.rx_history.push(stats.rx_delta as f64);
        self.tx_history.remove(0);
        self.tx_history.push(stats.tx_delta as f64);
        self.total_rx_bytes += stats.rx_delta;
        self.total_tx_bytes += stats.tx_delta;

        if stats.rx_delta > self.peak_rx_rate { self.peak_rx_rate = stats.rx_delta; }
        if stats.tx_delta > self.peak_tx_rate { self.peak_tx_rate = stats.tx_delta; }

        // 2. IP 统计
        let mut all_ips: Vec<Ipv4Addr> = self.ip_stats.keys().cloned().collect();
        for k in stats.traffic_delta.keys() {
            if !self.ip_stats.contains_key(k) { all_ips.push(*k); }
        }

        // 3. DNS 触发逻辑
        let dns_cache_clone = Arc::clone(&self.dns_cache);
        for ip in &all_ips {
            // 如果这个IP还没查过 DNS
            if !self.dns_query_sent.contains(ip) {
                self.dns_query_sent.push(*ip);
                let target_ip = *ip;
                let cache_ref = Arc::clone(&dns_cache_clone);
                
                // 启动后台线程查询 DNS，避免阻塞 UI
                thread::spawn(move || {
                    // 使用 dns_lookup 库进行反向解析
                    let hostname = lookup_addr(&IpAddr::V4(target_ip)).unwrap_or_else(|_| target_ip.to_string());
                    let mut cache = cache_ref.lock().unwrap();
                    cache.insert(target_ip, hostname);
                });
            }
        }

        // 4. 更新数据快照
        let mut current_snapshot = Vec::new();
        let cache_lock = self.dns_cache.lock().unwrap(); // 锁住读取 DNS 结果

        for ip in all_ips {
            let bytes_in = *stats.traffic_delta.get(&ip).unwrap_or(&0);
            let metrics = self.ip_stats.entry(ip).or_insert_with(IpMetrics::new);
            let avg_bps = metrics.update(bytes_in);

            if metrics.total_sum > 0 {
                let hostname = cache_lock.get(&ip).cloned().unwrap_or_else(|| "Resolving...".to_string());
                current_snapshot.push((
                    ip, 
                    avg_bps, 
                    hostname, 
                    metrics.peak_bps, 
                    metrics.peak_time.clone()
                ));
            } else {
                self.ip_stats.remove(&ip);
            }
        }
        
        // 排序
        current_snapshot.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        self.top_talkers = current_snapshot;

        // 清理
        stats.traffic_delta.clear();
        stats.rx_delta = 0;
        stats.tx_delta = 0;
    }
}

fn get_local_ip(device_name: &str) -> Option<Ipv4Addr> {
    let interfaces = datalink::interfaces();
    let iface = interfaces.into_iter().find(|i| i.name == device_name)?;
    iface.ips.iter().find_map(|ip| {
        if let pnet::ipnetwork::IpNetwork::V4(net) = ip { Some(net.ip()) } else { None }
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let device = Device::lookup()?.ok_or("No default device found")?;
    let device_name = device.name.clone();
    let local_ip = get_local_ip(&device_name).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(10)
        .open()?;

    let stats = Arc::new(Mutex::new(SharedStats {
        traffic_delta: HashMap::new(),
        rx_delta: 0,
        tx_delta: 0,
    }));
    let stats_clone = Arc::clone(&stats);

    thread::spawn(move || loop {
        if let Ok(packet) = cap.next_packet() {
            if let Some(ethernet) = EthernetPacket::new(packet.data) {
                if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                        let len = packet.header.len as u64;
                        let src = ipv4.get_source();
                        let dst = ipv4.get_destination();

                        let mut s = stats_clone.lock().unwrap();
                        if src == local_ip { s.tx_delta += len; } else { s.rx_delta += len; }
                        if is_lan_ip(&src) { *s.traffic_delta.entry(src).or_insert(0) += len; }
                        if is_lan_ip(&dst) { *s.traffic_delta.entry(dst).or_insert(0) += len; }
                    }
                }
            }
        }
    });

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new();
    let res = run_app(&mut terminal, app, stats, &device_name);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res { println!("{:?}", err) }
    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
    stats: Arc<Mutex<SharedStats>>,
    device_name: &str,
) -> io::Result<()> {
    let tick_rate = Duration::from_millis(TICK_RATE_MS);

    loop {
        terminal.draw(|f| {
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(0)
                .constraints([Constraint::Length(16), Constraint::Min(10)].as_ref())
                .split(f.size());

            // --- Net Box (Canvas) ---
            let net_block = Block::default()
                .borders(Borders::ALL)
                .title(format!(" net [{}] ", device_name))
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(Color::White));
            f.render_widget(net_block.clone(), main_chunks[0]);

            let inner_area = net_block.inner(main_chunks[0]);
            let graph_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
                .split(inner_area);

            let chart_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(graph_chunks[0]);

            let max_rx = app.rx_history.iter().cloned().fold(1.0, f64::max);
            let max_tx = app.tx_history.iter().cloned().fold(1.0, f64::max);
            let x_limit = app.rx_history.len() as f64;

            let download_canvas = Canvas::default()
                .block(Block::default().title("Download").title_style(Style::default().fg(Color::Red)))
                .marker(Marker::Braille)
                .x_bounds([0.0, x_limit])
                .y_bounds([0.0, max_rx])
                .paint(|ctx| {
                    for (i, &val) in app.rx_history.iter().enumerate() {
                        ctx.draw(&CanvasLine { x1: i as f64, y1: 0.0, x2: i as f64, y2: val, color: Color::Red });
                    }
                });
            f.render_widget(download_canvas, chart_chunks[0]);

            let upload_canvas = Canvas::default()
                .block(Block::default().title("Upload").title_style(Style::default().fg(Color::Blue)))
                .marker(Marker::Braille)
                .x_bounds([0.0, x_limit])
                .y_bounds([0.0, max_tx])
                .paint(|ctx| {
                    for (i, &val) in app.tx_history.iter().enumerate() {
                        ctx.draw(&CanvasLine { x1: i as f64, y1: 0.0, x2: i as f64, y2: val, color: Color::Blue });
                    }
                });
            f.render_widget(upload_canvas, chart_chunks[1]);

            let text_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(graph_chunks[1]);

            let current_rx_bps = (*app.rx_history.last().unwrap_or(&0.0)) * (1000.0 / TICK_RATE_MS as f64);
            let current_tx_bps = (*app.tx_history.last().unwrap_or(&0.0)) * (1000.0 / TICK_RATE_MS as f64);
            let peak_rx_bps = (app.peak_rx_rate as f64) * (1000.0 / TICK_RATE_MS as f64);
            let peak_tx_bps = (app.peak_tx_rate as f64) * (1000.0 / TICK_RATE_MS as f64);

            let rx_text = vec![
                Line::from(vec![Span::raw("▼ "), Span::styled(format_bps(current_rx_bps), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::styled("  Top: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bps(peak_rx_bps))]),
                Line::from(vec![Span::styled("  Tot: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bytes_total(app.total_rx_bytes))]),
            ];
            f.render_widget(Paragraph::new(rx_text).block(Block::default().style(Style::default().fg(Color::Red))), text_chunks[0]);

            let tx_text = vec![
                Line::from(vec![Span::raw("▲ "), Span::styled(format_bps(current_tx_bps), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::styled("  Top: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bps(peak_tx_bps))]),
                Line::from(vec![Span::styled("  Tot: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bytes_total(app.total_tx_bytes))]),
            ];
            f.render_widget(Paragraph::new(tx_text).block(Block::default().style(Style::default().fg(Color::Blue))), text_chunks[1]);

            // --- 底部表格 (含 Hostname 和 峰值信息) ---
            let header_cells = ["IP Address", "Hostname", "Current Speed", "Peak Speed", "Peak Time"]
                .iter()
                .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
            let header = Row::new(header_cells).style(Style::default().bg(Color::Rgb(50, 50, 50))).height(1).bottom_margin(1);
            
            let rows = app.top_talkers.iter().take(20).map(|(ip, bps, hostname, peak_bps, peak_time)| {
                let color = if *bps > 1_000_000.0 { Color::Red } else if *bps > 10_000.0 { Color::LightYellow } else { Color::Green };
                
                Row::new(vec![
                    Cell::from(ip.to_string()),
                    Cell::from(hostname.clone()).style(Style::default().fg(Color::Cyan)), // Hostname 颜色
                    Cell::from(format_bps(*bps)).style(Style::default().fg(color)),
                    Cell::from(format_bps(*peak_bps)).style(Style::default().fg(Color::Gray)), // 峰值颜色
                    Cell::from(peak_time.clone()).style(Style::default().fg(Color::DarkGray)), // 时间颜色
                ]).height(1)
            });

            // 调整列宽以容纳新数据
            let table = Table::new(rows, [
                    Constraint::Percentage(20), // IP
                    Constraint::Percentage(30), // Hostname (长一点)
                    Constraint::Percentage(15), // Current
                    Constraint::Percentage(15), // Peak
                    Constraint::Percentage(20), // Time
                ])
                .header(header)
                .block(Block::default().title(" Network Users ").borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded));
            f.render_widget(table, main_chunks[1]);
        })?;

        let timeout = tick_rate.checked_sub(app.last_tick.elapsed()).unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('c') { return Ok(()); }
            }
        }
        if app.last_tick.elapsed() >= tick_rate {
            app.on_tick(&stats);
            app.last_tick = Instant::now();
        }
    }
}

fn is_lan_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 192 && octets[1] == 168 && octets[2] == 5
}

fn format_bps(bps: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    if bps >= MB { format!("{:.2} Mb/s", bps * 8.0 / MB) }
    else if bps >= KB { format!("{:.2} Kb/s", bps * 8.0 / KB) }
    else { format!("{:.0} b/s", bps * 8.0) }
}

fn format_bytes_total(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB { format!("{:.2} GiB", bytes as f64 / GB as f64) }
    else if bytes >= MB { format!("{:.2} MiB", bytes as f64 / MB as f64) }
    else if bytes >= KB { format!("{:.2} KiB", bytes as f64 / KB as f64) }
    else { format!("{} B", bytes) }
}
