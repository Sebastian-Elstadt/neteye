use clap::Parser;
use scanner_lib;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "192.168.0.0/24")]
    network: String,
}

fn main() {
    let args = Args::parse();

    let net_access = scanner_lib::get_net_access().expect("could not establish net access.");
    let devices =
        scanner_lib::scan_network(&net_access, &args.network).expect("could not scan network.");

    print_devices(&devices);
}

fn print_devices(devices: &Vec<scanner_lib::NetDevice>) {
    println!("\nfound {} devices on network:", devices.len());
    for (i, device) in devices.iter().enumerate() {
        let man_name = device
            .manufacturer
            .as_ref()
            .map_or("UNKNOWN", |s| s.as_str());
        println!(
            "{}. ip:{}, mac:{}, man:{}",
            i + 1,
            device.ip_addr,
            device.mac_addr,
            man_name
        );
    }
}
