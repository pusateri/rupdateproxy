
use std::net::{UdpSocket, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use socket2::{self, Socket};

pub const MDNS_PORT: u16 = 5353;
lazy_static! {
    /// mDNS ipv4 address https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    pub static ref MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,251).into(), MDNS_PORT);
    /// link-local mDNS ipv6 address https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    pub static ref MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FB).into(), MDNS_PORT);
}

fn main() {
    let res = join_multicast(MDNS_IPV4);
}

/// Returns a socket joined to the multicast address
fn join_multicast(
    multicast_addr: &SocketAddr,
) -> Result<Option<std::net::UdpSocket>, io::Error> {
    if !mdns_query_type.join_multicast() {
        return Ok(None);
    }

    let ip_addr = multicast_addr.ip();
    // it's an error to not use a proper mDNS address
    if !ip_addr.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected multicast address for binding: {}", ip_addr),
        ));
    }

    // binding the UdpSocket to the multicast address tells the OS to filter all packets on thsi socket to just this
    //   multicast address
    // TODO: allow the binding interface to be specified
    let socket = match ip_addr {
        IpAddr::V4(ref mdns_v4) => {
            let socket = Socket::new(
                socket2::Domain::ipv4(),
                socket2::Type::dgram(),
                Some(socket2::Protocol::udp()),
            )?;
            socket.join_multicast_v4(mdns_v4, &Ipv4Addr::new(0, 0, 0, 0))?;
            socket
        }
        IpAddr::V6(ref mdns_v6) => {
            let socket = Socket::new(
                socket2::Domain::ipv6(),
                socket2::Type::dgram(),
                Some(socket2::Protocol::udp()),
            )?;

            socket.set_only_v6(true)?;
            socket.join_multicast_v6(mdns_v6, 0)?;
            socket
        }
    };

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)] // this is currently restricted to Unix's in socket2
    socket.set_reuse_port(true)?;
    Self::bind_multicast(&socket, multicast_addr)?;

    debug!("joined {}", multicast_addr);
    Ok(Some(socket.into_udp_socket()))
}

