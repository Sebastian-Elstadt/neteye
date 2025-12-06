use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

use clap::Parser;
use mac_oui::Oui;
use pnet::{
    datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        Packet,
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
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
    print_devices(&devices);
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
    let (mut tx, mut rx) = get_transmission_channels(&net_access.interface)?;

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
        std::thread::sleep(Duration::from_micros(500));
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

            println!("got an ARP packet! checking if it's a reply...");
            let packet_arp = ArpPacket::new(packet_eth.payload())
                .expect("could not create arp packet from incoming rx packet.");
            if packet_arp.get_operation() != ArpOperations::Reply {
                println!("it's not a reply :( skipping...");
                continue;
            }

            println!("it's a reply :D adding device...");
            let target_ip = packet_arp.get_sender_proto_addr();
            if target_ip == net_access.local_ip {
                continue;
            }

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

fn get_transmission_channels(
    interface: &NetworkInterface,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>), Box<dyn std::error::Error>> {
    let def_channel = datalink::channel(interface, Default::default())?;

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
    println!("found {} devices on network:", devices.len());
    for (i, device) in devices.iter().enumerate() {
        let man_name = device
            .manufacturer
            .as_ref()
            .map_or("UNKNOWN", |s| s.as_str());
        println!(
            "{}. ip:{}, mac:{}, man:{}",
            i, device.ip_addr, device.mac_addr, man_name
        );
    }
}
