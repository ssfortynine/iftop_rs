pub const TICK_RATE_MS: u64 = 500; //
pub const HISTORY_WINDOW_SECS: u64 = 60;  
const MAX_SAMPLES: usize = (HISTORY_WINDOW_SECS * 1000 / TICK_RATE_MS) as usize;
