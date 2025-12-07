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

use clap::Parser;
use mac_oui::Oui;
use pnet::{
    datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        Packet,
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{
            EtherTypes::{self},
            EthernetPacket, MutableEthernetPacket,
        },
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        tcp::{MutableTcpPacket, TcpFlags, TcpOption, ipv4_checksum},
    },
    transport::{
        self, TransportChannelType::Layer3, TransportReceiver, TransportSender, transport_channel,
    },
    util::MacAddr,
};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "192.168.0.0/24")]
    network: String,
}

struct NetAccess {
    interface: NetworkInterface,
    local_ip: Ipv4Addr,
    local_mac: MacAddr,
}

struct NetDevice {
    ip_addr: Ipv4Addr,
    mac_addr: MacAddr,
    manufacturer: Option<String>,
}

fn main() {
    let args = Args::parse();

    let net_access = get_net_access().expect("could not establish net access.");
    println!(
        "will scan network on interface \"{}\" [ip: {}]",
        net_access.interface.name, net_access.local_ip
    );

    let devices = scan_network(&net_access, &args.network).expect("could not scan network.");

    loop {
        print_devices(&devices);
        println!("\nEnter a device number to scan its ports:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap_or_else(|e| {
            eprintln!("failed to parse input: {}", e);
            0
        });

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        if input == "q" {
            break;
        }

        if let Ok(index) = input.parse::<usize>() {
            scan_device_ports(&net_access, &devices[index - 1], vec![]).unwrap_or_else(|e| {
                eprint!("failed to scan device ports: {}", e);
            });
        }
    }
}

fn get_net_access() -> Result<NetAccess, Box<dyn std::error::Error>> {
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

fn parse_cidr(addr: &str) -> Result<(Ipv4Addr, u32), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() != 2 {
        return Err("cannot parse provided network address.".into());
    }

    let ip: Ipv4Addr = parts[0].parse()?;
    let mask: u32 = parts[1].parse()?;

    Ok((ip, mask))
}

fn scan_network(
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
            // println!("got a packet. investigating...");
            let packet_eth = EthernetPacket::new(packet)
                .expect("could not create ethernet packet from incoming rx packet.");
            if packet_eth.get_ethertype() != EtherTypes::Arp {
                // println!("packet is not ARP. skipping...");
                continue;
            }

            // println!("got an ARP packet! checking if it's a reply...");
            let packet_arp = ArpPacket::new(packet_eth.payload())
                .expect("could not create arp packet from incoming rx packet.");
            if packet_arp.get_operation() != ArpOperations::Reply {
                // println!("it's not a reply :( skipping...");
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

fn get_datalink_channels(
    interface: &NetworkInterface,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>), Box<dyn std::error::Error>> {
    // let def_channel = datalink::channel(interface, Default::default())?;
    let def_channel = datalink::channel(
        interface,
        datalink::Config {
            promiscuous: true,
            ..Default::default()
        },
    )?;

    match def_channel {
        datalink::Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => Err("unsupported transmission channel type.".into()),
    }
}

fn send_arp_request(net_access: &NetAccess, target_ip: Ipv4Addr, tx: &mut Box<dyn DataLinkSender>) {
    let mut ethernet_buffer = [0u8; 42];
    let mut eth_packet_builder = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    eth_packet_builder.set_destination(MacAddr::broadcast());
    eth_packet_builder.set_source(net_access.local_mac);
    eth_packet_builder.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet_builder = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet_builder.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet_builder.set_protocol_type(EtherTypes::Ipv4);
    arp_packet_builder.set_hw_addr_len(6);
    arp_packet_builder.set_proto_addr_len(4);
    arp_packet_builder.set_operation(ArpOperations::Request);
    arp_packet_builder.set_sender_hw_addr(net_access.local_mac);
    arp_packet_builder.set_sender_proto_addr(net_access.local_ip);
    arp_packet_builder.set_target_hw_addr(MacAddr::zero());
    arp_packet_builder.set_target_proto_addr(target_ip);

    eth_packet_builder.set_payload(arp_packet_builder.packet());
    tx.send_to(eth_packet_builder.packet(), None);
}

fn print_devices(devices: &Vec<NetDevice>) {
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

fn get_transport_channels(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver), Box<dyn std::error::Error>> {
    transport_channel(buffer_size, Layer3(IpNextHeaderProtocols::Tcp)).map_err(|e| e.into())
}

fn scan_device_ports(
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

fn send_port_ip_packet(
    net_access: &NetAccess,
    tx: &mut TransportSender,
    target_ip: Ipv4Addr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tcp_buffer = [0u8; 40];
    let mut tcp_packet_builder = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    tcp_packet_builder.set_source(40000 + (port % 1000));
    tcp_packet_builder.set_destination(port);
    tcp_packet_builder.set_sequence(12345);
    tcp_packet_builder.set_acknowledgement(0);
    tcp_packet_builder.set_data_offset(10); // 40 bytes
    tcp_packet_builder.set_flags(TcpFlags::SYN);
    tcp_packet_builder.set_window(64240);
    tcp_packet_builder.set_urgent_ptr(0);
    tcp_packet_builder.set_options(&[
        TcpOption::mss(1460),  // 2, 4, 5, 180 -> kind=2, len=4, value=1460
        TcpOption::nop(),      // 1
        TcpOption::wscale(10), // 3, 3, 10 -> kind=3, len=3, shift=10
    ]);

    let mut ip_buffer = [0u8; 60];
    let mut ip_packet_builder = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    ip_packet_builder.set_version(4);
    ip_packet_builder.set_header_length(5);
    ip_packet_builder.set_total_length(60);
    ip_packet_builder.set_ttl(64);
    ip_packet_builder.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet_builder.set_source(net_access.local_ip);
    ip_packet_builder.set_destination(target_ip);
    ip_packet_builder.set_payload(tcp_packet_builder.packet());

    let checksum = ipv4_checksum(
        &tcp_packet_builder.to_immutable(),
        &net_access.local_ip,
        &target_ip,
    );
    tcp_packet_builder.set_checksum(checksum);
    ip_packet_builder.set_payload(tcp_packet_builder.packet());

    match tx.send_to(ip_packet_builder, IpAddr::V4(target_ip)) {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
    }
}
