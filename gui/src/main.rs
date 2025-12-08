slint::include_modules!();

fn main() {
    let ui = AppWindow::new().unwrap();

    ui.on_scan_ports(move |net_addr: slint::SharedString| {
        // run_network_scan(&net_access, &net_addr);
    });

    ui.run().unwrap();
}