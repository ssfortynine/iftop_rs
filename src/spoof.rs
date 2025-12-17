use std::process::{Child, Command, Stdio};
use std::io;

pub struct ArpSpoofer {
    process: Option<Child>,
}

impl ArpSpoofer {
    pub fn new() -> Self {
        Self { process: None }
    }

    /// arpspoof -i <interface> <target_ip>
    pub fn start(&mut self, interface: &str, target_ip: &str) -> io::Result<()> {
        println!("Starting ARP spoofing on {} targeting {}...", interface, target_ip);
        
        let child = Command::new("arpspoof")
            .arg("-i")
            .arg(interface)
            .arg(target_ip)
            .stdout(Stdio::null())
            .stderr(Stdio::null()) 
            .spawn()?;

        self.process = Some(child);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill(); 
            let _ = child.wait(); 
            println!("ARP spoofing stopped.");
        }
    }
}

impl Drop for ArpSpoofer {
    fn drop(&mut self) {
        self.stop();
    }
}
