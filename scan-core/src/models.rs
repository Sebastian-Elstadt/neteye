use std::net::Ipv4Addr;

use pnet::{datalink::NetworkInterface, util::MacAddr};

pub struct NetAccess {
    pub interface: NetworkInterface,
    pub local_ip: Ipv4Addr,
    pub local_mac: MacAddr,
}

#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
#[cfg_attr(feature = "deserialize", derive(serde::Deserialize))]
pub struct NetDevice {
    #[cfg_attr(
        any(feature = "serialize", feature = "deserialize"),
        serde(
            serialize_with = "serialize_ipv4addr",
            deserialize_with = "deserialize_ipv4addr"
        )
    )]
    pub ip_addr: Ipv4Addr,
    #[cfg_attr(
        any(feature = "serialize", feature = "deserialize"),
        serde(serialize_with = "serialize_mac", deserialize_with = "deserialize_mac")
    )]
    pub mac_addr: MacAddr,
    pub manufacturer: Option<String>,
}

#[cfg(feature = "serialize")]
fn serialize_ipv4addr<S>(ip_addr: &Ipv4Addr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&ip_addr.to_string())
}

#[cfg(feature = "deserialize")]
fn deserialize_ipv4addr<'de, D>(deserializer: D) -> Result<Ipv4Addr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

#[cfg(feature = "serialize")]
fn serialize_mac<S>(mac: &MacAddr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&mac.to_string())
}

#[cfg(feature = "deserialize")]
fn deserialize_mac<'de, D>(deserializer: D) -> Result<MacAddr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    use std::str::FromStr;
    let s = String::deserialize(deserializer)?;
    MacAddr::from_str(&s).map_err(serde::de::Error::custom)
}
