use nix::sys::socket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn sockaddr_to_ipaddr(sockaddr: socket::SockAddr) -> Option<IpAddr> {
    match sockaddr {
        socket::SockAddr::Inet(addr) => match addr.ip() {
            socket::IpAddr::V4(ip4) => Some(IpAddr::V4(ip4.to_std())),
            socket::IpAddr::V6(ip6) => Some(IpAddr::V6(ip6.to_std())),
        },
        _ => None,
    }
}

pub fn mask_address(address: IpAddr, netmask: IpAddr) -> Option<IpAddr> {
    match address {
        IpAddr::V4(addr4) => {
            let mut addr = addr4.octets();
            let mask = match netmask {
                IpAddr::V4(mask4) => mask4.octets(),
                IpAddr::V6(_mask6) => return None,
            };
            for i in 0..addr.len() {
                addr[i] &= mask[i];
            }
            Some(IpAddr::from(Ipv4Addr::from(addr)))
        }
        IpAddr::V6(addr6) => {
            let mut addr = addr6.octets();
            let mask = match netmask {
                IpAddr::V4(_mask4) => return None,
                IpAddr::V6(mask6) => mask6.octets(),
            };
            for i in 0..addr.len() {
                addr[i] &= mask[i];
            }
            Some(IpAddr::from(Ipv6Addr::from(addr)))
        }
    }
}
