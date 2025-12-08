use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use mac_oui::Oui;
use pnet::{
    datalink,
    packet::{
        Packet,
        arp::{ArpOperations, ArpPacket},
        ethernet::{
            EtherTypes::{self},
            EthernetPacket,
        },
        tcp::TcpFlags,
    },
    transport,
    util::MacAddr,
};

mod models;
mod utils;

use models::{NetAccess, NetDevice};
use utils::{
    get_datalink_channels, get_transport_channels, parse_cidr, send_arp_request,
    send_port_ip_packet,
};

pub fn get_net_access() -> Result<NetAccess, Box<dyn std::error::Error>> {
    let all = datalink::interfaces();

    let ipv4_iface = all
        .into_iter()
        .find(|i| i.is_up() && !i.is_loopback() && i.ips.iter().any(|ip| ip.is_ipv4()))
        .ok_or("no ipv4 interface found!")?;

    let local_ip = match ipv4_iface.ips.iter().find(|ip| ip.is_ipv4()).unwrap().ip() {
        IpAddr::V4(ipv4) => ipv4,
        _ => return Err("local ip is somehow not v4".into()),
    };

    let local_mac = ipv4_iface.mac.unwrap_or(MacAddr::zero());

    Ok(NetAccess {
        interface: ipv4_iface,
        local_ip,
        local_mac,
    })
}

pub fn scan_network(
    net_access: &NetAccess,
    network_addr: &str,
) -> Result<Vec<NetDevice>, Box<dyn std::error::Error>> {
    let (network, subnet_mask) = parse_cidr(network_addr)?;
    let (mut tx, mut rx) = get_datalink_channels(&net_access.interface)?;

    let oui_db = Oui::default()?;

    let num_hosts = (1u32 << (32 - subnet_mask)) - 2; // exclude network/broadcast
    println!("scanning {} hosts...", num_hosts);
    let network_u32 = u32::from(network);

    for i in 1..=num_hosts {
        let target_ip_u32 = network_u32 + i;
        let target_ip = Ipv4Addr::from(target_ip_u32);

        if target_ip == net_access.local_ip {
            continue;
        }

        send_arp_request(net_access, target_ip, &mut tx);
        std::thread::sleep(Duration::from_millis(10)); // increasing from 500 nanoseconds to 10ms made a massive difference.
    }

    let mut devices: Vec<NetDevice> = vec![];
    let start_time = Instant::now();
    while start_time.elapsed() < Duration::from_secs(10) {
        if let Ok(packet) = rx.next() {
            let packet_eth = EthernetPacket::new(packet)
                .expect("could not create ethernet packet from incoming rx packet.");
            if packet_eth.get_ethertype() != EtherTypes::Arp {
                continue;
            }

            let packet_arp = ArpPacket::new(packet_eth.payload())
                .expect("could not create arp packet from incoming rx packet.");
            if packet_arp.get_operation() != ArpOperations::Reply {
                continue;
            }

            let target_ip = packet_arp.get_sender_proto_addr();
            if target_ip == net_access.local_ip {
                continue;
            }

            println!("+> device {} detected.", target_ip); // for some reason, making this line "print!" instead of "println!" causes me to detect almost no devices.

            let target_mac = packet_arp.get_sender_hw_addr();
            let target_man = oui_db
                .lookup_by_mac(&target_mac.to_string())
                .ok()
                .flatten()
                .map(|entry| entry.company_name.to_string());

            devices.push(NetDevice {
                ip_addr: target_ip,
                mac_addr: target_mac,
                manufacturer: target_man,
            });
        }
    }

    Ok(devices)
}

pub fn scan_device_ports(
    net_access: &NetAccess,
    device: &NetDevice,
    port_range: Vec<u16>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut tx, mut rx) = get_transport_channels(65536)?;

    let (ports_tx, ports_rx) = std::sync::mpsc::channel::<u16>();
    let sent_all_packets = Arc::new(AtomicBool::new(false));
    let sent_all_packets_clone = sent_all_packets.clone();

    thread::spawn(move || {
        let mut iter = transport::tcp_packet_iter(&mut rx);
        let mut ports = HashSet::new();

        let timeout = Duration::from_secs(10);
        let mut start_time: Option<Instant> = None;

        loop {
            let sent_all_packets = sent_all_packets_clone.load(Ordering::Relaxed);
            if sent_all_packets && start_time.is_none() {
                start_time.replace(Instant::now());
            }

            if sent_all_packets && start_time.unwrap().elapsed() >= timeout {
                break;
            }

            if let Ok((tcp_packet, _)) = iter.next() {
                let src_port = tcp_packet.get_source();
                let flags = tcp_packet.get_flags();

                if flags == (TcpFlags::SYN | TcpFlags::ACK) && ports.insert(src_port) {
                    println!("+> port {} is open.", src_port);
                    let _ = ports_tx.send(src_port);
                }

                continue;
            }

            break;
        }

        println!("stopped listening for port responses.");
    });

    if port_range.len() > 0 {
        println!(
            "scanning for ports (given range: {} ports)...",
            port_range.len()
        );
        for port in port_range {
            let _ = send_port_ip_packet(net_access, &mut tx, device.ip_addr, port);
            thread::sleep(Duration::from_micros(500));
        }
    } else {
        println!("scanning for all ports...");
        for port in 1..65535 {
            let _ = send_port_ip_packet(net_access, &mut tx, device.ip_addr, port);
            thread::sleep(Duration::from_micros(500));
        }

        println!("packets sent to all ports.");
    }

    sent_all_packets.store(true, Ordering::Relaxed);
    thread::sleep(Duration::from_secs(10));

    println!("port scan complete.");
    println!(
        "\nopen ports: {:?}",
        ports_rx.try_iter().collect::<Vec<_>>()
    );

    Ok(())
}

// fn run_network_scan(net_access: &NetAccess, net_addr: &str) {
//     let devices = scan_network(net_access, net_addr).expect("could not scan network.");

//     loop {
//         print_devices(&devices);
//         println!("\nEnter a device number to scan its ports:");
//         let mut input = String::new();
//         std::io::stdin().read_line(&mut input).unwrap_or_else(|e| {
//             eprintln!("failed to parse input: {}", e);
//             0
//         });

//         let input = input.trim();
//         if input.is_empty() {
//             continue;
//         }

//         if input == "q" {
//             break;
//         }

//         if let Ok(index) = input.parse::<usize>() {
//             scan_device_ports(&net_access, &devices[index - 1], vec![]).unwrap_or_else(|e| {
//                 eprint!("failed to scan device ports: {}", e);
//             });
//         }
//     }
// }
