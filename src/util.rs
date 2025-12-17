// Format function: Convert Bytes/s to bits/s for display
pub fn format_bps(bytes_per_sec: f64) -> String {
    let bps = bytes_per_sec * 8.0; //convert to bits per second
    const KB: f64 = 1000.0;
    const MB: f64 = 1000.0 * KB;
    const GB: f64 = 1000.0 * MB;

    if bps >= GB {
        format!("{:.2} Gb/s", bps / GB)
    } else if bps >= MB {
        format!("{:.2} Mb/s", bps / MB)
    } else if bps >= KB {
        format!("{:.2} Kb/s", bps / KB)
    } else {
        format!("{:.0} b/s", bps)
    }
}

pub fn format_bytes_total(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
