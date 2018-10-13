extern crate socket2;
extern crate tokio;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};


const IP_ALL: [u8; 4] = [0, 0, 0, 0];
pub const MDNS_PORT: u16 = 5353;


/// Returns a socket joined to the multicast address
pub fn join_multicast(
    multicast_addr: &SocketAddr,
) -> Result<std::net::UdpSocket, std::io::Error> {

    use socket2::{Domain, Type, Protocol, Socket};

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
                Domain::ipv4(),
                Type::dgram(),
                Some(Protocol::udp()),
            ).expect("ipv4 dgram socket");
            socket.join_multicast_v4(mdns_v4, &Ipv4Addr::new(0, 0, 0, 0)).expect("join_multicast_v4");
            socket
        }
        IpAddr::V6(ref mdns_v6) => {
            let socket = Socket::new(
                Domain::ipv6(),
                Type::dgram(),
                Some(Protocol::udp()),
            ).expect("ipv6 dgram socket");

            socket.set_only_v6(true)?;
            socket.join_multicast_v6(mdns_v6, 0).expect("join_multicast_v6");
            socket
        }
    };

    let addr = SocketAddrV4::new(IP_ALL.into(), MDNS_PORT);
    socket.set_nonblocking(true).expect("nonblocking Error");
    socket.set_reuse_address(true).expect("reuse addr Error");
    #[cfg(unix)] // this is currently restricted to Unix's in socket2
    socket.set_reuse_port(true).expect("reuse port Error");
    socket.set_multicast_loop_v4(true)?;
    socket.bind(&socket2::SockAddr::from(addr))?;

    Ok(socket.into_udp_socket())
}

