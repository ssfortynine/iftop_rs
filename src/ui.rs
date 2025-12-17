use std::{io, sync::{Arc, Mutex}, time::{Duration, Instant}};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
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

use crate::app::{App, SharedStats};
use crate::constants::TICK_RATE_MS;
use crate::util::{format_bps, format_bytes_total};

pub fn run(stats: Arc<Mutex<SharedStats>>, device_name: &str) -> io::Result<()> {
    // Initialize terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new();
    let res = run_app_loop(&mut terminal, app, stats, device_name);

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("Error: {:?}", err)
    }
    Ok(())
}

fn run_app_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
    stats: Arc<Mutex<SharedStats>>,
    device_name: &str,
) -> io::Result<()> {
    let tick_rate = Duration::from_millis(TICK_RATE_MS);

    loop {
        terminal.draw(|f| {
            // ============= whole screen layout ============
            let main_chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(0)
                .constraints([
                    Constraint::Length(16), // Upside Net Box
                    Constraint::Min(10),    // Middle Table
                    Constraint::Length(1),  // Bottom Status Bar
                ].as_ref())
                .split(f.size());

            // ============= Top Net Monitor Box ============
            let net_block = Block::default()
                .borders(Borders::ALL)
                .title(format!(" Net Monitor [{}] ", device_name))
                .border_type(ratatui::widgets::BorderType::Rounded)
                .border_style(Style::default().fg(Color::Cyan));
            f.render_widget(net_block.clone(), main_chunks[0]);

            let inner_area = net_block.inner(main_chunks[0]);
            let graph_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(75), Constraint::Percentage(25)].as_ref())
                .split(inner_area);

            // ======== Left Graphs (Download/Upload) ========
            let chart_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(graph_chunks[0]);

            let max_rx = app.rx_history.iter().cloned().fold(100.0, f64::max);
            let max_tx = app.tx_history.iter().cloned().fold(100.0, f64::max);
            let x_limit = app.rx_history.len() as f64;

            // Download Canvas
            let download_canvas = Canvas::default()
                .block(Block::default().title(" Download ").title_style(Style::default().fg(Color::Red)))
                .marker(Marker::Braille)
                .x_bounds([0.0, x_limit])
                .y_bounds([0.0, max_rx])
                .paint(|ctx| {
                    for (i, &val) in app.rx_history.iter().enumerate() {
                        ctx.draw(&CanvasLine {
                            x1: i as f64,
                            y1: 0.0,
                            x2: i as f64,
                            y2: val,
                            color: Color::Red,
                        });
                    }
                });
            f.render_widget(download_canvas, chart_chunks[0]);

            // Upload Canvas
            let upload_canvas = Canvas::default()
                .block(Block::default().title(" Upload ").title_style(Style::default().fg(Color::Blue)))
                .marker(Marker::Braille)
                .x_bounds([0.0, x_limit])
                .y_bounds([0.0, max_tx])
                .paint(|ctx| {
                    for (i, &val) in app.tx_history.iter().enumerate() {
                        ctx.draw(&CanvasLine {
                            x1: i as f64,
                            y1: 0.0,
                            x2: i as f64,
                            y2: val,
                            color: Color::Blue,
                        });
                    }
                });
            f.render_widget(upload_canvas, chart_chunks[1]);

            // textual stats on the right
            let text_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(graph_chunks[1]);

            let current_rx_bps = (*app.rx_history.last().unwrap_or(&0.0)) * (1000.0 / TICK_RATE_MS as f64);
            let current_tx_bps = (*app.tx_history.last().unwrap_or(&0.0)) * (1000.0 / TICK_RATE_MS as f64);
            
            let peak_rx_bps = app.peak_rx_record.0;
            let peak_tx_bps = app.peak_tx_record.0;

            let rx_text = vec![
                Line::from(vec![Span::raw("▼ "), Span::styled(format_bps(current_rx_bps), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::styled("  Peak: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bps(peak_rx_bps))]),
                Line::from(vec![Span::styled("  Tot:  ", Style::default().fg(Color::DarkGray)), Span::raw(format_bytes_total(app.total_rx_bytes))]),
            ];
            f.render_widget(Paragraph::new(rx_text).block(Block::default().style(Style::default().fg(Color::Red))), text_chunks[0]);

            let tx_text = vec![
                Line::from(vec![Span::raw("▲ "), Span::styled(format_bps(current_tx_bps), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
                Line::from(vec![Span::styled("  Peak: ", Style::default().fg(Color::DarkGray)), Span::raw(format_bps(peak_tx_bps))]),
                Line::from(vec![Span::styled("  Tot:  ", Style::default().fg(Color::DarkGray)), Span::raw(format_bytes_total(app.total_tx_bytes))]),
            ];
            f.render_widget(Paragraph::new(tx_text).block(Block::default().style(Style::default().fg(Color::Blue))), text_chunks[1]);

            // ============= Middle Top Talkers Table ============
            let header_cells = ["IP Address", "Avg Bandwidth", "Peak Rate", "Peak Time", "Status"]
                .iter()
                .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
            let header = Row::new(header_cells)
                .style(Style::default().bg(Color::Rgb(40, 40, 40)))
                .height(1)
                .bottom_margin(0);

            let rows = app.top_talkers.iter().take(25).map(|(ip, avg_bps, peak_bps, peak_time)| {
                let avg_color = if *avg_bps > 1_000_000.0 { Color::Red } else if *avg_bps > 100_000.0 { Color::LightYellow } else { Color::Green };
                let peak_color = if *peak_bps > 1_000_000.0 { Color::Magenta } else { Color::Cyan };

                Row::new(vec![
                    Cell::from(ip.to_string()),
                    Cell::from(format_bps(*avg_bps)).style(Style::default().fg(avg_color)),
                    Cell::from(format_bps(*peak_bps)).style(Style::default().fg(peak_color)),
                    Cell::from(peak_time.format("%H:%M:%S").to_string()).style(Style::default().fg(Color::DarkGray)),
                    Cell::from("Active"),
                ]).height(1)
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                ]
            )
            .header(header)
            .block(Block::default().title(" Local Network Traffic ").borders(Borders::ALL).border_type(ratatui::widgets::BorderType::Rounded));
            f.render_widget(table, main_chunks[1]);

            // ============ Bottom Status Bar ============
            let global_rx_time = app.peak_rx_record.1.format("%H:%M:%S").to_string();
            let global_tx_time = app.peak_tx_record.1.format("%H:%M:%S").to_string();

            let status_content = Line::from(vec![
                Span::styled(" GLOBAL RECORDS ", Style::default().bg(Color::White).fg(Color::Black).add_modifier(Modifier::BOLD)),
                Span::raw(" | "),
                Span::styled("MAX RX: ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::raw(format!("{} ", format_bps(app.peak_rx_record.0))),
                Span::styled(format!("(@{})", global_rx_time), Style::default().fg(Color::DarkGray)),
                Span::raw(" | "),
                Span::styled("MAX TX: ", Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
                Span::raw(format!("{} ", format_bps(app.peak_tx_record.0))),
                Span::styled(format!("(@{})", global_tx_time), Style::default().fg(Color::DarkGray)),
                Span::raw(" | Press 'q' to quit"),
            ]);

            let status_bar = Paragraph::new(status_content)
                .style(Style::default().bg(Color::Rgb(20, 20, 20)));
            f.render_widget(status_bar, main_chunks[2]);
        })?;

        // Handle input
        let timeout = tick_rate.checked_sub(app.last_tick.elapsed()).unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('c') {
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
