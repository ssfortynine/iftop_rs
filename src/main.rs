use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    Packet,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Sparkline, Table},
    Terminal,
};
use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    io,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

// ----------------------
// 常量定义
// ----------------------
const TICK_RATE_MS: u64 = 500; // 刷新频率 500ms
const HISTORY_WINDOW_SECS: u64 = 60; // 统计窗口 60秒
const MAX_SAMPLES: usize = (HISTORY_WINDOW_SECS * 1000 / TICK_RATE_MS) as usize; // 窗口对应的样本数 (120个)

// ----------------------
// 数据结构
// ----------------------

// 抓包线程向UI线程传递的数据（增量）
struct SharedStats {
    traffic_delta: HashMap<Ipv4Addr, u64>, // 本周期内的流量
    total_delta: u64,                      // 本周期总流量
}

// 单个 IP 的历史记录，用于计算滑动平均
struct IpHistory {
    samples: VecDeque<u64>, // 最近 N 次的流量样本
    total_sum: u64,         // 样本总和（缓存优化，避免每次遍历求和）
}

impl IpHistory {
    fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES),
            total_sum: 0,
        }
    }

    // 添加一个新的样本，并返回当前的平均速率 (Bytes/s)
    fn update(&mut self, bytes: u64) -> f64 {
        self.samples.push_back(bytes);
        self.total_sum += bytes;

        // 保持窗口大小
        if self.samples.len() > MAX_SAMPLES {
            if let Some(removed) = self.samples.pop_front() {
                self.total_sum -= removed;
            }
        }

        // 计算平均值：总字节 / (样本数 * 单次时长)
        let duration_secs = self.samples.len() as f64 * (TICK_RATE_MS as f64 / 1000.0);
        if duration_secs == 0.0 {
            0.0
        } else {
            self.total_sum as f64 / duration_secs
        }
    }
}

// UI 状态 App
struct App {
    // 总流量历史 (用于顶部 Sparkline)
    sparkline_data: Vec<u64>,
    // 所有 IP 的历史记录
    ip_histories: HashMap<Ipv4Addr, IpHistory>,
    // 排行榜快照 (IP, 平均速率 B/s)
    top_talkers: Vec<(Ipv4Addr, f64)>,
    // 上一次更新时间
    last_tick: Instant,
}

impl App {
    fn new() -> App {
        App {
            sparkline_data: vec![0; 100],
            ip_histories: HashMap::new(),
            top_talkers: vec![],
            last_tick: Instant::now(),
        }
    }

    fn on_tick(&mut self, shared_stats: &Arc<Mutex<SharedStats>>) {
        let mut stats = shared_stats.lock().unwrap();

        // 1. 更新顶部总流量图表
        self.sparkline_data.remove(0);
        self.sparkline_data.push(stats.total_delta);

        // 2. 更新每个 IP 的历史数据 (滑动窗口)
        // 注意：即使 shared_stats 里没有这个 IP (本周期没流量)，也要填入 0
        // 否则平均值不会下降。
        
        // 先收集所有涉及到的 IP (历史记录里的 + 新抓到的)
        let mut all_ips: Vec<Ipv4Addr> = self.ip_histories.keys().cloned().collect();
        for k in stats.traffic_delta.keys() {
            if !self.ip_histories.contains_key(k) {
                all_ips.push(*k);
            }
        }

        let mut current_snapshot = Vec::new();

        // 遍历所有已知 IP 进行更新
        for ip in all_ips {
            let bytes_in = *stats.traffic_delta.get(&ip).unwrap_or(&0);
            
            let history = self.ip_histories.entry(ip).or_insert_with(IpHistory::new);
            let avg_bps = history.update(bytes_in);

            // 只有当平均流量 > 0 时才显示，且长期不活跃的清理掉
            if history.total_sum > 0 {
                current_snapshot.push((ip, avg_bps));
            } else {
                // 如果整个窗口(1分钟)内总和为0，说明很久没动静了，移除以节省内存
                self.ip_histories.remove(&ip);
            }
        }

        // 3. 排序并更新排行榜
        current_snapshot.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        self.top_talkers = current_snapshot;

        // 4. 清空共享区的计数器
        stats.traffic_delta.clear();
        stats.total_delta = 0;
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // 1. 设置网络抓包
    let device = Device::lookup()?.ok_or("No default device found")?;
    let device_name = device.name.clone();

    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(10)
        .open()?;

    let stats = Arc::new(Mutex::new(SharedStats {
        traffic_delta: HashMap::new(),
        total_delta: 0,
    }));
    let stats_clone = Arc::clone(&stats);

    // 2. 启动抓包线程
    thread::spawn(move || {
        loop {
            if let Ok(packet) = cap.next_packet() {
                if let Some(ethernet) = EthernetPacket::new(packet.data) {
                    if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            let len = packet.header.len as u64;
                            let src = ipv4.get_source();
                            let dst = ipv4.get_destination();

                            let mut s = stats_clone.lock().unwrap();
                            s.total_delta += len;

                            if is_lan_ip(&src) {
                                *s.traffic_delta.entry(src).or_insert(0) += len;
                            }
                            if is_lan_ip(&dst) {
                                *s.traffic_delta.entry(dst).or_insert(0) += len;
                            }
                        }
                    }
                }
            }
        }
    });

    // 3. 设置 TUI
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 4. 运行 UI 循环
    let app = App::new();
    let res = run_app(&mut terminal, app, stats, &device_name);

    // 5. 恢复终端
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

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
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Length(12),
                        Constraint::Min(10),
                    ]
                    .as_ref(),
                )
                .split(f.size());

            // --- 顶部图表 ---
            let sparkline = Sparkline::default()
                .block(
                    Block::default()
                        .title(format!(" Total Traffic (Live) on {} ", device_name))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)),
                )
                .data(&app.sparkline_data)
                .style(Style::default().fg(Color::Magenta));
            f.render_widget(sparkline, chunks[0]);

            // --- 底部表格 ---
            let header_cells = ["IP Address", "Avg Bandwidth (1 min)", "Status"]
                .iter()
                .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
            let header = Row::new(header_cells)
                .style(Style::default().bg(Color::Rgb(50, 50, 50)))
                .height(1)
                .bottom_margin(1);

            let rows = app.top_talkers.iter().take(20).map(|(ip, bps)| {
                // 颜色阈值：> 1MB/s 红, > 10KB/s 黄, 其他绿
                let color = if *bps > 1_000_000.0 {
                    Color::Red
                } else if *bps > 10_000.0 {
                    Color::LightYellow
                } else {
                    Color::Green
                };
                
                let cells = vec![
                    Cell::from(ip.to_string()),
                    Cell::from(format_bps(*bps)).style(Style::default().fg(color)),
                    Cell::from("Active"),
                ];
                Row::new(cells).height(1)
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(40),
                    Constraint::Percentage(40),
                    Constraint::Percentage(20),
                ]
            )
            .header(header)
            .block(
                Block::default()
                    .title(" Top Bandwidth Users (1 Minute Average) ")
                    .borders(Borders::ALL)
                    .border_type(ratatui::widgets::BorderType::Rounded)
                    .border_style(Style::default().fg(Color::White)),
            );
            f.render_widget(table, chunks[1]);
        })?;

        // --- 事件与定时 ---
        let timeout = tick_rate
            .checked_sub(app.last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code || key.code == KeyCode::Char('c') {
                    return Ok(());
                }
            }
        }

        if app.last_tick.elapsed() >= tick_rate {
            app.on_tick(&stats);
            app.last_tick = Instant::now();
        }
    }
}

// 辅助：判断局域网 IP
fn is_lan_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    (octets[0] == 192 && octets[1] == 168) || (octets[0] == 10)
}

// 辅助：格式化 Bytes Per Second (f64)
fn format_bps(bps: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;

    if bps >= MB {
        format!("{:.2} MB/s", bps / MB)
    } else if bps >= KB {
        format!("{:.2} KB/s", bps / KB)
    } else {
        format!("{:.0} B/s", bps)
    }
}
