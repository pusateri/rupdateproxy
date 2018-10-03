extern crate socket2;
extern crate futures;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_io;
extern crate domain;
extern crate ttl_cache;
#[macro_use]
extern crate lazy_static;

use std::io;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use ttl_cache::TtlCache;
use futures::Stream;
use tokio::prelude::*;
use tokio::net::{UdpSocket, UdpFramed};
use tokio_codec::BytesCodec;
use domain::bits::message::Message;


const IP_ALL: [u8; 4] = [0, 0, 0, 0];
pub const MDNS_PORT: u16 = 5353;
lazy_static! {
    /// mDNS ipv4 address https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    pub static ref MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,251).into(), MDNS_PORT);
    /// link-local mDNS ipv6 address https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    pub static ref MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FB).into(), MDNS_PORT);
}

#[derive(PartialEq, Eq, Hash)]
struct RecordKey <'a> {
    name: &'a str,
    rrtype: u16,
    data: &'a [u8],
}

struct RecordInfo <'a> {
    name: &'a str,
    rrtype: u16,
    ttl: u32,
    data: &'a [u8],
}


// extract the buffer into a Packet struct and filter duplicates
fn extract_packet(_cache: &TtlCache<RecordKey, RecordInfo>, buf: &[u8]) -> Result<(), Box<Error>> {
    let msg = Message::from_bytes(buf).unwrap();

    if msg.is_error() {
        return Ok(());
    }

    if msg.header().qr() == false {
        return Ok(());
    }
    // cache responses
    for record in msg.answer().unwrap() {
        if let Ok(_record) = record {
        }
    }
    Ok(())
}

fn main() {
    let std_socket = join_multicast(&MDNS_IPV4).expect("mDNS IPv4 join_multicast");
    let socket = UdpSocket::from_std(std_socket, &tokio::reactor::Handle::current()).unwrap();
    let (_writer, reader) = UdpFramed::new(socket, BytesCodec::new()).split();
    let cache: TtlCache<RecordKey, RecordInfo> = TtlCache::new(10);

    let socket_read = reader.for_each(move |(msg, addr)| {
        match extract_packet(&cache, &msg) {
            Ok(()) => {},
            Err(e) => {
                eprintln!("Error from {}: {}", addr, e);
            }
        }
        Ok(())
    });

    tokio::run({
        socket_read.map(|_| ())
                   .map_err(|e| println!("error = {:?}", e))
    });
}


/// Returns a socket joined to the multicast address
fn join_multicast(
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

