// use std::io::{self, Write};
use std::process::{Command, Stdio};

use slint::ToSharedString;

slint::include_modules!();

fn main() {
    let app = AppWindow::new().unwrap();
    let app_ref = app.as_weak();

    app.on_scan_ports(move |net_addr: slint::SharedString| {
        run_network_scanner(&app_ref.unwrap(), &net_addr);
    });

    app.run().unwrap();
}

fn run_network_scanner(app: &AppWindow, net_addr: &str) {
    let output = Command::new("pkexec")
        .arg("./target/debug/scanner") // Separate binary for raw socket logic
        .arg("-n")
        .arg(net_addr)
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn scanner")
        .wait_with_output()
        .expect("failed to scan");

    let results = String::from_utf8_lossy(&output.stdout).to_shared_string();
    app.set_scan_results(results);
}
