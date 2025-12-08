use crate::models::NetAccess;
use pnet::{
    datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        Packet,
        arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
        ethernet::{
            EtherTypes::{self},
            MutableEthernetPacket,
        },
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        tcp::{MutableTcpPacket, TcpFlags, TcpOption, ipv4_checksum},
    },
    transport::{
        TransportChannelType::Layer3, TransportReceiver, TransportSender, transport_channel,
    },
    util::MacAddr,
};
use std::net::{IpAddr, Ipv4Addr};

pub fn send_port_ip_packet(
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

pub fn parse_cidr(addr: &str) -> Result<(Ipv4Addr, u32), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() != 2 {
        return Err("cannot parse provided network address.".into());
    }

    let ip: Ipv4Addr = parts[0].parse()?;
    let mask: u32 = parts[1].parse()?;

    Ok((ip, mask))
}

pub fn get_transport_channels(
    buffer_size: usize,
) -> Result<(TransportSender, TransportReceiver), Box<dyn std::error::Error>> {
    transport_channel(buffer_size, Layer3(IpNextHeaderProtocols::Tcp)).map_err(|e| e.into())
}

pub fn send_arp_request(
    net_access: &NetAccess,
    target_ip: Ipv4Addr,
    tx: &mut Box<dyn DataLinkSender>,
) {
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

pub fn get_datalink_channels(
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
