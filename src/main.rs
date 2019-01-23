use crate::services::{ServiceAction, ServiceEvent};
use bytes::Bytes;
use domain_core::bits::message::Message;
use domain_core::bits::name::{ParsedDname, ToDname};
use domain_core::bits::Dname;
use domain_core::rdata::AllRecordData;
use futures::sync::mpsc;
use interface_events::{get_current_events, IfEvent};
use lazy_static::lazy_static;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::process::exit;
use std::time::{Duration, Instant};
use tokio::net::{UdpFramed, UdpSocket};
use tokio::prelude::*;
use tokio::runtime::Runtime;
use tokio::timer::Delay;
use tokio_codec::BytesCodec;
use treebitmap;

mod args;
mod multicast;
mod services;

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

// extract the received packet buffer into a Service Event and send on shared channel
fn extract_packet(
    ifindex: u32,
    buf: &[u8],
    tx: &mut mpsc::Sender<services::ServiceEvent>,
) -> Result<(), Box<Error>> {
    let msg = Message::from_bytes(Bytes::from(buf)).expect("DNS Message::from_bytes failed");

    if msg.is_error() {
        return Ok(());
    }
    if msg.header().qr() == false {
        return Ok(());
    }

    for record in msg
        .answer()
        .unwrap()
        .limit_to::<AllRecordData<ParsedDname>>()
    {
        if let Ok(record) = record {
            let se = ServiceEvent::new(
                ServiceAction::DYNAMIC,
                record.owner().to_name(),
                record.data().clone(),
                ifindex,
                record.ttl(),
            );
            tx.send(se).wait().unwrap();
        }
    }
    Ok(())
}

fn index_for_v4_address(
    sockaddr: SocketAddr,
    ifs: &treebitmap::IpLookupTable<Ipv4Addr, u32>,
) -> Option<u32> {
    match sockaddr {
        SocketAddr::V4(sockaddr_v4) => {
            let prefix_opt = ifs.longest_match(*sockaddr_v4.ip());
            match prefix_opt {
                Some((_addr, _plen, ifindex)) => Some(*ifindex),
                None => None,
            }
        }
        _ => None,
    }
}

fn index_for_v6_address(
    sockaddr: SocketAddr,
    ifs: &treebitmap::IpLookupTable<Ipv6Addr, u32>,
) -> Option<u32> {
    match sockaddr {
        SocketAddr::V6(sockaddr_v6) => {
            let prefix_opt = ifs.longest_match(*sockaddr_v6.ip());
            match prefix_opt {
                Some((_addr, _plen, ifindex)) => Some(*ifindex),
                None => None,
            }
        }
        _ => None,
    }
}

fn index_interface_trees_init(
    v4_ifs: &mut treebitmap::IpLookupTable<std::net::Ipv4Addr, u32>,
    v6_ifs: &mut treebitmap::IpLookupTable<std::net::Ipv6Addr, u32>,
) {
    // lookup ifindex by source IP address until we have IN_PKTINFO/RECV_IF

    let events = get_current_events()
        .into_iter()
        .filter(|event| IfEvent::not_loopback(event));
    for event in events {
        match event.ip {
            IpAddr::V4(ip4) => v4_ifs.insert(ip4, event.plen.into(), event.ifindex),
            IpAddr::V6(ip6) => v6_ifs.insert(ip6, event.plen.into(), event.ifindex),
        };
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
        include_interfaces: "".to_string(),
        exclude_interfaces: "".to_string(),
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

    // initialize interface index trees
    let mut v4_ifs = treebitmap::IpLookupTable::new();
    let mut v6_ifs = treebitmap::IpLookupTable::new();
    index_interface_trees_init(&mut v4_ifs, &mut v6_ifs);

    // create crossbeam channels for ServiceEvents
    let (tx, rx) = mpsc::channel(1000);

    // create cache receiver for ServiceEvents
    // create a services cache per interface index, IPv4 & IPv6 should be merged
    let mut cache_map: HashMap<u32, HashMap<RecordKey, RecordInfo>> = HashMap::new();

    let service_sink = rx.for_each(move |msg: services::ServiceEvent| {
        if !cache_map.contains_key(&msg.ifindex) {
            let table = HashMap::new();
            cache_map.insert(msg.ifindex, table);
        }
        let cache = cache_map.get_mut(&msg.ifindex).unwrap();
        let when = Instant::now() + Duration::from_secs(msg.ttl.into());
        let key = RecordKey {
            name: msg.sname,
            data: msg.sdata,
        };
        let val = RecordInfo { ttl: msg.ttl };

        let _v = match cache.entry(key.clone()) {
            Vacant(entry) => {
                println!(
                    "caching {} + {:?} on ifindex: {}",
                    key.name, key.data, msg.ifindex
                );
                let task = Delay::new(when)
                    .map_err(|e| panic!("delay errored; err={:?}", e))
                    .and_then(move |_| {
                        println!("timeout for {} + {:?}", key.name, key.data);
                        Ok(())
                    });

                tokio::spawn(task);
                entry.insert(val)
            }
            Occupied(exists) => {
                println!(
                    "found: {} + {:?} on ifindex: {}",
                    key.name, key.data, msg.ifindex
                );
                let mut entry = exists.into_mut();
                entry.ttl = msg.ttl;
                entry
            }
        };
        Ok(())
    });

    // listen for IPv4 mDNS packets
    let v4_listen_addr = SocketAddr::from(SocketAddrV4::new(IP_ALL.into(), MDNS_PORT));

    let v4_std_socket = multicast::join_multicast(&MDNS_IPV4, &v4_listen_addr, 0)
        .expect("mDNS IPv4 join_multicast");
    let v4_socket = UdpSocket::from_std(v4_std_socket, &tokio::reactor::Handle::default()).unwrap();
    let (_v4_writer, v4_reader) = UdpFramed::new(v4_socket, BytesCodec::new()).split();

    let mut source = tx.clone();
    let v4_socket_read = v4_reader.for_each(move |(msg, addr)| {
        match index_for_v4_address(addr, &v4_ifs) {
            Some(ifindex) => match extract_packet(ifindex, &msg, &mut source) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error from {}: {}", addr, e);
                }
            },
            None => {
                eprintln!("No interface for addr {:?}", addr);
            }
        };

        Ok(())
    });

    // listen for IPv6 mDNS packets
    let v6_std_socket = multicast::join_multicast(&MDNS_IPV6, &v4_listen_addr, 11)
        .expect("mDNS IPv6 join_multicast");
    let v6_socket = UdpSocket::from_std(v6_std_socket, &tokio::reactor::Handle::default()).unwrap();
    let (_v6_writer, v6_reader) = UdpFramed::new(v6_socket, BytesCodec::new()).split();

    let mut source = tx.clone();
    let v6_socket_read = v6_reader.for_each(move |(msg, addr)| {
        match index_for_v6_address(addr, &v6_ifs) {
            Some(ifindex) => match extract_packet(ifindex, &msg, &mut source) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error from {}: {}", addr, e);
                }
            },
            None => {
                eprintln!("No interface for addr {:?}", addr);
            }
        };

        Ok(())
    });

    let mut rt = Runtime::new().unwrap();

    // Spawn the server task
    rt.spawn(
        v4_socket_read
            .map(|_| ())
            .map_err(|_| eprintln!("v4_socket_read")),
    );
    rt.spawn(
        v6_socket_read
            .map(|_| ())
            .map_err(|_| eprintln!("v6_socket_read")),
    );
    rt.spawn(service_sink);

    // Wait until the runtime becomes idle and shut it down.
    rt.shutdown_on_idle().wait().unwrap();
}
