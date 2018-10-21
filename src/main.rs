extern crate socket2;
extern crate futures;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_io;
extern crate tokio_timer;
extern crate bytes;
extern crate domain_core;
extern crate nix;
extern crate treebitmap;
extern crate ipnetwork;
#[macro_use]
extern crate lazy_static;

use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::process::exit;
use futures::Stream;
use tokio::prelude::*;
use tokio::net::{UdpSocket, UdpFramed};
use tokio_codec::BytesCodec;
use tokio::timer::Delay;
use nix::ifaddrs;
use nix::net::if_;
use bytes::Bytes;
use domain_core::bits::Dname;
use domain_core::bits::name::{ParsedDname, ToDname};
use domain_core::bits::message::Message;
use domain_core::rdata::AllRecordData;


mod multicast;
mod addrs;
mod args;

const IP_ALL: [u8; 4] = [0, 0, 0, 0];
pub const MDNS_PORT: u16 = 5353;
lazy_static! {
    /// mDNS ipv4 address https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml
    pub static ref MDNS_IPV4: SocketAddr = SocketAddr::new(Ipv4Addr::new(224,0,0,251).into(), MDNS_PORT);
    /// link-local mDNS ipv6 address https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml
    pub static ref MDNS_IPV6: SocketAddr = SocketAddr::new(Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00FB).into(), MDNS_PORT);
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RecordKey {
   name: Dname,
   data: AllRecordData<ParsedDname>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RecordInfo {
    ttl: u32,
}

struct IfState {
    if_index: u32,
    cache: HashMap<RecordKey, RecordInfo>,
}

// extract the buffer into a Packet struct and filter duplicates
fn extract_packet(intf: &mut IfState, buf: &[u8]) -> Result<(), Box<Error>> {
    let msg = Message::from_bytes(Bytes::from(buf)).unwrap();

    if msg.is_error() {
        return Ok(());
    }

    if msg.header().qr() == false {
        return Ok(());
    }

    // cache responses
    for record in msg.answer().unwrap().limit_to::<AllRecordData<ParsedDname>>() {
        if let Ok(record) = record {
            let key = RecordKey {
                name: record.owner().to_name(),
                data: record.data().clone(),
            };
            let ttl = record.ttl();
            let duration = Duration::from_secs(ttl.into());

            let when = Instant::now() + duration;
            let val = RecordInfo {
                ttl: ttl,
            };

            let v = intf.cache.entry(key.clone()).or_insert(val);
            println!("caching {}", key.name);
            v.ttl = ttl;

            let task = Delay::new(when)
                .and_then(move |_| {
                    println!("timeout for {}", key.name);
                    Ok(())
                })
                .map_err(|e| panic!("delay errored; err={:?}", e));
            tokio::spawn(task);
        }
    }
    Ok(())
}


fn ifaddr_to_prefix(ifaddr: ifaddrs::InterfaceAddress) -> Option <ipnetwork::IpNetwork> {
    let ip = addrs::sockaddr_to_ipaddr(ifaddr.address?)?;
    let mask = addrs::sockaddr_to_ipaddr(ifaddr.netmask?)?;
    let net = addrs::mask_address(ip, mask)?;
    let plen = match ipnetwork::ip_mask_to_prefix(mask) {
        Ok(len) => len,
        Err(_e) => return None,
    };
    match ipnetwork::IpNetwork::new(net, plen) {
        Ok(ipnet) => return Some(ipnet),
        Err(_e) => return None
    };
}


fn intf_for_v4_address(sockaddr: SocketAddr,
                            ifs: &mut treebitmap::IpLookupTable<Ipv4Addr, IfState>) -> Option<&mut IfState>
{
    match sockaddr {
        SocketAddr::V4(sockaddr_v4) => {
            let prefix_opt = ifs.longest_match_mut(*sockaddr_v4.ip());
            match prefix_opt {
                Some((_addr, _plen, intf)) => Some(intf),
                None => None,
            }
        },
        _ => None
    }
}

fn intf_for_v6_address(sockaddr: SocketAddr,
                            ifs: &mut treebitmap::IpLookupTable<Ipv6Addr, IfState>) -> Option<&mut IfState>
{
    match sockaddr {
        SocketAddr::V6(sockaddr_v6) => {
            let prefix_opt = ifs.longest_match_mut(*sockaddr_v6.ip());
            match prefix_opt {
                Some((_addr, _plen, intf)) => Some(intf),
                None => None,
            }
        },
        _ => None
    }
}

fn main() {
    let mut options = args::Options {
        nofork: false,
        verbose: false,
        nofour: false,
        nosix: false,
        pid_file: "/var/run/rupdateproxy.pid".to_string(),
        domain: "".to_string(),
        include_interfaces: "en0".to_string(),
        exclude_interfaces: "lo0".to_string(),
    };
    args::parse_opts(&mut options);

    if options.verbose {
        eprintln!("interfaces included {}", options.include_interfaces);
        eprintln!("interfaces excluded {}", options.exclude_interfaces);
        eprintln!("disable IPv4: {}", options.nofour);
        eprintln!("disable IPv6: {}", options.nosix);
    }

    if options.nofour && options.nosix {
        eprintln!("Must enable either IPv4, IPv6, or both");
        exit(1);
    }

    let mut v4_ifs = treebitmap::IpLookupTable::new();
    let mut v6_ifs = treebitmap::IpLookupTable::new();

    let addrs = ifaddrs::getifaddrs().unwrap();
    for ifaddr in addrs {
        let (ip, plen) = match ifaddr_to_prefix(ifaddr.clone()) {
            Some(ipnet) => (ipnet.ip(), ipnet.prefix()),
            None => {
                continue;
            },
        };

        let if_index = if_::if_nametoindex(&ifaddr.interface_name[..]).unwrap();
        let intf = IfState {
            if_index: if_index,
            cache: HashMap::new(),
        };
        match ip {
            IpAddr::V4(ip4) => v4_ifs.insert(ip4, plen.into(), intf),
            IpAddr::V6(ip6) => v6_ifs.insert(ip6, plen.into(), intf),
        };
    }

    // IPv4 listener
    let v4_listen_addr = SocketAddr::from(SocketAddrV4::new(IP_ALL.into(), MDNS_PORT));
    
    let v4_std_socket = multicast::join_multicast(&MDNS_IPV4, &v4_listen_addr, 0).expect("mDNS IPv4 join_multicast");
    let v4_socket = UdpSocket::from_std(v4_std_socket, &tokio::reactor::Handle::current()).unwrap();
    let (_v4_writer, v4_reader) = UdpFramed::new(v4_socket, BytesCodec::new()).split();

    let v4_socket_read = v4_reader.for_each(move |(msg, addr)| {
        match intf_for_v4_address(addr, &mut v4_ifs) {
            Some(ref mut intf) => {
                match extract_packet(intf, &msg) {
                    Ok(()) => {},
                    Err(e) => {
                        eprintln!("Error from {}: {}", addr, e);
                    }
                }
            },
            None => {
                eprintln!("No interface for addr {:?}", addr);
            },
        };

        Ok(())
    });
    

    let v6_std_socket = multicast::join_multicast(&MDNS_IPV6, &v4_listen_addr, 0).expect("mDNS IPv6 join_multicast");
    let v6_socket = UdpSocket::from_std(v6_std_socket, &tokio::reactor::Handle::current()).unwrap();
    let (_v6_writer, v6_reader) = UdpFramed::new(v6_socket, BytesCodec::new()).split();

    let v6_socket_read = v6_reader.for_each(move |(msg, addr)| {
        match intf_for_v6_address(addr, &mut v6_ifs) {
            Some(ref mut intf) => {
                match extract_packet(intf, &msg) {
                    Ok(()) => {},
                    Err(e) => {
                        eprintln!("Error from {}: {}", addr, e);
                    }
                }
            },
            None => {
                eprintln!("No interface for addr {:?}", addr);
            },
        };

        Ok(())
    });

    tokio::run({
        v4_socket_read.join(v6_socket_read)
                      .map(|_| ())
                      .map_err(|e| println!("error = {:?}", e))
    });
}
