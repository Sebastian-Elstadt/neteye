use clap::Parser;
use mac_oui::Oui;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::MutablePacket;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::error;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "192.168.1.0/24")]
    network: String,
}

#[derive(Debug, Clone)]
struct Device {
    ip: Ipv4Addr,
    mac: MacAddr,
    manufacturer: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|ifa| ifa.is_up() && !ifa.is_loopback() && ifa.ips.iter().any(|ip| ip.is_ipv4()))
        .ok_or("No interface found.")?;

    let local_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()).unwrap().ip() {
        IpAddr::V4(ipv4) => ipv4,
        _ => return Err("Local IP is not IPv4.".into()),
    };
    let local_mac = interface.mac.unwrap_or(MacAddr::zero());

    println!(
        "scanning network on interface: {} [ip: {}]",
        interface.name, local_ip
    );

    let (network, prefix) = parse_cidr(&args.network)?;
    let devices = scan_network(&interface, local_ip, local_mac, network, prefix).await?;

    

    Ok(())
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u32), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("invalid CIDR".into());
    }

    let ip: Ipv4Addr = parts[0].parse()?;
    let prefix: u32 = parts[1].parse()?;

    Ok((ip, prefix))
}

async fn scan_network(
    interface: &NetworkInterface,
    local_ip: Ipv4Addr,
    local_mac: MacAddr,
    network: Ipv4Addr,
    prefix: u32,
) -> Result<Vec<Device>, Box<dyn std::error::Error>> {
    let channel = datalink::channel(interface, Default::default())?;
    let (mut tx, mut rx) = match channel {
        datalink::Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err("unsupported channel type".into()),
    };

    let mut devices: Vec<Device> = vec![];
    let oui_db = Oui::default()?;

    let num_hosts = (1u32 << (32 - prefix)) - 2; // exclude network/broadcast
    let network_u32 = u32::from(network);

    for i in 1..num_hosts {
        let target_ip_u32 = network_u32 + i;
        let target_ip = Ipv4Addr::from(target_ip_u32);

        if target_ip == local_ip {
            continue;
        }

        // setup ethernet "carrier" packet.
        let mut ethernet_buffer = [0u8, 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(local_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        // setup arp payload for the ethernet packet.
        let mut arp_buffer = [0u8, 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(local_mac);
        arp_packet.set_sender_proto_addr(local_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(&arp_buffer);

        // send packet.
        tx.send_to(ethernet_packet.packet_mut(), None);

        // listen for a reply
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(1) {
            if let Ok(packet) = rx.next() {
                let ethernet = pnet::packet::ethernet::EthernetPacket::new(packet).unwrap();
                if ethernet.get_ethertype() == EtherTypes::Arp {
                    let arp = pnet::packet::arp::ArpPacket::new(packet).unwrap();
                    if arp.get_operation() == ArpOperations::Reply
                        && arp.get_sender_proto_addr() == target_ip
                    {
                        let sender_hw_addr = arp.get_sender_hw_addr();
                        // let mac = MacAddr::new(
                        //     arp.get_sender_hw_addr()[0],
                        //     arp.get_sender_hw_addr()[1],
                        //     arp.get_sender_hw_addr()[2],
                        //     arp.get_sender_hw_addr()[3],
                        //     arp.get_sender_hw_addr()[4],
                        //     arp.get_sender_hw_addr()[5]
                        // );
                        let manufacturer = oui_db
                            .lookup_by_mac(&sender_hw_addr.to_string())
                            .ok()
                            .flatten()
                            .map(|entry| entry.company_name.clone());
                        devices.push(Device {
                            ip: target_ip,
                            mac: sender_hw_addr,
                            manufacturer,
                        });
                        break;
                    }
                }
            }
        }
    }

    Ok(devices)
}
