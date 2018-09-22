extern crate socket2;
extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
#[macro_use]
extern crate lazy_static;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use socket2::{Socket, Domain, Type, Protocol};
use futures::{Future, Stream};
use tokio_core::net::{UdpCodec, UdpSocket};
use tokio_core::reactor::Core;

pub const MDNS_PORT: u16 = 5353;
lazy_static! {
    /// mDNS ipv4 address https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    pub static ref MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,251).into(), MDNS_PORT);
    /// link-local mDNS ipv6 address https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    pub static ref MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FB).into(), MDNS_PORT);
}


// just a codec to send and receive bytes
pub struct LineCodec;
impl UdpCodec for LineCodec {
    type In = (SocketAddr, Vec<u8>);
    type Out = (SocketAddr, Vec<u8>);

    fn decode(&mut self, addr: &SocketAddr, buf: &[u8]) -> std::io::Result<Self::In> {
        Ok((*addr, buf.to_vec()))
    }

    fn encode(&mut self, (addr, buf): Self::Out, into: &mut Vec<u8>) -> SocketAddr {
        into.extend(buf);
        addr
    }
}

fn compute(handle: &Handle, addr: SocketAddr, _msg: Vec<u8>) -> Box<Future<Item = (), Error = ()>> {
    println!("Starting to compute for: {}", addr);
    Box::new(
        Timeout::new(std::time::Duration::from_secs(8), handle)
            .unwrap()
            .map_err(|e| panic!("timeout failed: {:?}", e))
            .and_then(move |()| {
                println!("Done computing for for: {}", addr);
                Ok(())
            }),
    )
}

fn main() {
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let socket = join_multicast(&MDNS_IPV4).expect("mDNS IPv4 join_multicast");

    let (writer, reader) = socket.framed(LineCodec).split();

    let socket_read = reader.for_each(|(addr, msg)| {
        println!("Got {:?}", msg);
        handle.spawn(compute(addr, msg));
        Ok(())
    });

    core.run(socket_read).unwrap();
}


#[cfg(unix)]
fn bind_multicast(socket: &Socket, addr: &SocketAddr) -> io::Result<()> {
    socket.bind(&socket2::SockAddr::from(*addr))
}

/// Returns a socket joined to the multicast address
fn join_multicast(
    multicast_addr: &SocketAddr,
) -> Result<Option<std::net::UdpSocket>, io::Error> {

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

    socket.set_nonblocking(true).expect("nonblocking Error");
    socket.set_reuse_address(true).expect("reuse addr Error");
    #[cfg(unix)] // this is currently restricted to Unix's in socket2
    socket.set_reuse_port(true).expect("reuse port Error");
    bind_multicast(&socket, &multicast_addr).expect("bind Error");

    Ok(Some(socket.into_udp_socket()))
}

