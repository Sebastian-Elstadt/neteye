use std::net::Ipv4Addr;

use pnet::{
    util::MacAddr,
    datalink::NetworkInterface
};

pub struct NetAccess {
    pub interface: NetworkInterface,
    pub local_ip: Ipv4Addr,
    pub local_mac: MacAddr,
}

pub struct NetDevice {
    pub ip_addr: Ipv4Addr,
    pub mac_addr: MacAddr,
    pub manufacturer: Option<String>,
}