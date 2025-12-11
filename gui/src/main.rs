use std::{
    process::{Command, Stdio},
    rc::Rc,
    thread,
};

use slint::{ToSharedString, VecModel, Weak};

slint::include_modules!();

fn main() {
    let app = AppWindow::new().unwrap();
    let app_ref = app.as_weak();

    app.on_scan_ports(move |net_addr: slint::SharedString| {
        run_network_scanner(app_ref.clone(), &net_addr);
    });

    app.run().unwrap();
}

fn run_network_scanner(app: Weak<AppWindow>, net_addr: &str) {
    if let Some(app) = app.upgrade() {
        app.set_is_scanning(true);
    }

    let net_addr = net_addr.to_string();

    thread::spawn(move || {
        let output = Command::new("pkexec")
            .arg("./target/debug/scanner")
            .arg("-n")
            .arg(net_addr)
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn scanner")
            .wait_with_output()
            .expect("failed to scan");

        let results = String::from_utf8_lossy(&output.stdout);
        let devices: Vec<scan_core::models::NetDevice> =
            serde_json::from_str(&results).expect("could not deserialize net devices list.");

        // make UI updates in main thread.
        slint::invoke_from_event_loop(move || {
            println!("GOT DEVICES {}", devices.len());

            let devices_model = Rc::new(VecModel::from(
                devices
                    .into_iter()
                    .map(|d| d.into())
                    .collect::<Vec<slint_NetDevice>>(),
            ));

            if let Some(app) = app.upgrade() {
                app.set_devices(devices_model.into());
                app.set_is_scanning(false);
            }
        })
        .unwrap();
    });
}

impl From<scan_core::models::NetDevice> for slint_NetDevice {
    fn from(val: scan_core::models::NetDevice) -> Self {
        slint_NetDevice {
            ip_addr: val.ip_addr.to_shared_string(),
            mac_addr: val.mac_addr.to_shared_string(),
            manufacturer: val
                .manufacturer
                .unwrap_or("UNKNOWN".into())
                .to_shared_string(),
        }
    }
}
