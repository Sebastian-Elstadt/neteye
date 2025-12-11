use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "192.168.0.0/24")]
    network: String,
}

fn main() {
    let args = Args::parse();

    let net_access = scan_core::get_net_access().expect("could not establish net access.");
    let devices =
        scan_core::scan_network(&net_access, &args.network).expect("could not scan network.");

    print_devices(&devices);
}

fn print_devices(devices: &Vec<scan_core::models::NetDevice>) {
    // println!("\nfound {} devices on network:", devices.len());
    // for (i, device) in devices.iter().enumerate() {
    //     let man_name = device
    //         .manufacturer
    //         .as_ref()
    //         .map_or("UNKNOWN", |s| s.as_str());
    //     println!(
    //         "{}. ip:{}, mac:{}, man:{}",
    //         i + 1,
    //         device.ip_addr,
    //         device.mac_addr,
    //         man_name
    //     );
    // }

    let devices_json = serde_json::to_string(devices).expect("could not serialize devices vector");
    println!("{}", devices_json);
}
