use pcap::{Capture, Device};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    let is_running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&is_running);
    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    let dev_list: Vec<Device> = pcap::Device::list().unwrap();
    // printed list beforehand to know index
    let dev = &dev_list[1];
    println!("Capturing on {:#?}", dev);
    let cap = Capture::from_device(dev.clone()).unwrap().open().unwrap();
    let mut cap = cap.setnonblock().unwrap();

    let mut cnt = 0;
    let mut tot = 0;
    if cap.filter("ip host 10.0.0.1 and tcp port 80", true).is_ok() {
        while is_running.load(Ordering::Relaxed) {
            if let Ok(packet) = cap.next() {
                cnt += 1;
            }
        }
    }
    println!("Count: {}", cnt);
}
