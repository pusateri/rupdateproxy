use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

/*
 * Returns a socket joined to the multicast address
 * if_addr should be an IPv4 interface address or 0.0.0.0
 * if_index should be an interface index used only by IPv6
 */

pub fn join_multicast(
    multicast_addr: &SocketAddr,
    if_addr: &SocketAddr,
    if_index: u32,
) -> Result<UdpSocket, io::Error> {
    use socket2::{Domain, Protocol, Socket, Type};

    let mc_addr = multicast_addr.ip();
    // it's an error to not use a proper mDNS address
    if !mc_addr.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected multicast address for binding: {}", mc_addr),
        ));
    }

    // binding the UdpSocket to the multicast address tells the OS to filter all packets on thsi socket to just this
    //   multicast address
    // TODO: allow the binding interface to be specified
    let socket = match mc_addr {
        IpAddr::V4(ref mc_v4addr) => {
            let socket = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))
                .expect("ipv4 dgram socket");

            match if_addr.ip() {
                IpAddr::V4(ref addr4) => {
                    socket
                        .join_multicast_v4(mc_v4addr, addr4)
                        .expect("join_multicast_v4");
                    socket.set_multicast_loop_v4(true)?;
                    socket
                }
                IpAddr::V6(addr6) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("family mismatch: {} and {}", mc_addr, addr6),
                    ));
                }
            }
        }
        IpAddr::V6(ref mdns_v6) => {
            let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))
                .expect("ipv6 dgram socket");

            socket.set_only_v6(true)?;
            socket
                .join_multicast_v6(mdns_v6, if_index)
                .expect("join_multicast_v6");
            socket
        }
    };

    socket.set_nonblocking(true).expect("nonblocking Error");
    socket.set_reuse_address(true).expect("reuse addr Error");
    #[cfg(unix)] // this is currently restricted to Unix's in socket2
    socket.set_reuse_port(true).expect("reuse port Error");

    socket.bind(&socket2::SockAddr::from(*multicast_addr))?;

    Ok(socket.into_udp_socket())
}
