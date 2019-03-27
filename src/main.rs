
use crate::services::{ServiceAction, ServiceEvent};
use bytes::Bytes;
use domain_core::bits::message::Message;
use domain_core::bits::name::{ParsedDname, ToDname};
use domain_core::bits::Dname;
use domain_core::bits::record::Record;
use domain_core::rdata::AllRecordData;
use domain_resolv::StubResolver;
use interface_events::{get_current_events, IfEvent};
use lazy_static::lazy_static;
use socket2::Domain;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::process::exit;
use std::time::{Duration, Instant};
use mio::net::UdpSocket;
use mio::{Events, Ready, Poll, PollOpt, Token};
use crossbeam_channel::{unbounded, Sender};
use treebitmap;

mod args;
mod multicast;
mod services;
mod update;

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

#[derive(Debug)]
struct IfState {
    ifindex: u32,
    subdomain: String,
}

fn extract_mdns_record(ifindex: u32, subdomain: &String, from: SocketAddr, record: Record<ParsedDname, AllRecordData<ParsedDname>>) -> Option<ServiceEvent>
{
    match record.data() {
        AllRecordData::A(addr) =>
            Some(ServiceEvent::new_a(
                ServiceAction::DYNAMIC,
                record.owner().to_name(),
                record.data().clone(),
                ifindex,
                subdomain,
                from,
                addr,
                record.ttl(),
            )),
        AllRecordData::Aaaa(addr) =>
            Some(ServiceEvent::new_aaaa(
                ServiceAction::DYNAMIC,
                record.owner().to_name(),
                record.data().clone(),
                ifindex,
                subdomain,
                from,
                addr,
                record.ttl(),
            )),
        AllRecordData::Ptr(name) =>
            Some(ServiceEvent::new_ptr(
                ServiceAction::DYNAMIC,
                record.owner().to_name(),
                record.data().clone(),
                ifindex,
                subdomain,
                from,
                name,
                record.ttl(),
            )),
        AllRecordData::Srv(srv) =>
            Some(ServiceEvent::new_srv(
                ServiceAction::DYNAMIC,
                record.owner().to_name(),
                record.data().clone(),
                ifindex,
                subdomain,
                from,
                srv.priority(),
                srv.weight(),
                srv.port(),
                srv.target(),
                record.ttl(),
            )),
        AllRecordData::Txt(txt) =>
            Some(ServiceEvent::new_txt(
                ServiceAction::DYNAMIC,
                record.owner().to_name(),
                record.data().clone(),
                ifindex,
                subdomain,
                from,
                txt.text(),
                record.ttl(),
            )),
        AllRecordData::Opt(opt) =>
            Some(ServiceEvent::new_opt(
                ServiceAction::DYNAMIC,
                record.owner().to_name(),
                record.data().clone(),
                ifindex,
                subdomain,
                from,
                opt.clone(),
                record.ttl(),
            )),
        _ => {
            println!("        record {} not handled", record.rtype());
            return None;
        },
    }
}

// extract the received packet buffer into a Service Event and send on shared channel
fn extract_mdns_response(
    ifindex: u32,
    subdomain: &String,
    from: SocketAddr,
    buf: &[u8],
    tx: &mut Sender<services::ServiceEvent>,
) {
    let msg = Message::from_bytes(Bytes::from(buf)).expect("DNS Message::from_bytes failed");

    if msg.is_error() {
        return;
    }
    if msg.header().qr() == false {
        return;
    }

    for section in vec![msg.answer(), msg.additional()] {
        for record in section
            .unwrap()
            .limit_to::<AllRecordData<ParsedDname>>()
        {
            match record {
                Ok(r) => {
                    let se = extract_mdns_record(ifindex, subdomain, from, r);
                    if let Some(event) = se {
                        // send over channel combining IPv4 and IPv6 received mDNS messages
                        tx.send(event).unwrap();
                    }
                },
                Err(_e) => (),
            }
        }
    }
}

fn ifstate_for_v4_address(
    sockaddr: SocketAddr,
    ifs: &treebitmap::IpLookupTable<Ipv4Addr, IfState>,
) -> Option<&IfState> {
    match sockaddr {
        SocketAddr::V4(sockaddr_v4) => {
            let prefix_opt = ifs.longest_match(*sockaddr_v4.ip());
            match prefix_opt {
                Some((_addr, _plen, ifstate)) => Some(ifstate),
                None => None,
            }
        }
        _ => None,
    }
}

fn ifstate_for_v6_address(
    sockaddr: SocketAddr,
    ifs: &treebitmap::IpLookupTable<Ipv6Addr, IfState>,
) -> Option<&IfState> {
    match sockaddr {
        SocketAddr::V6(sockaddr_v6) => {
            let prefix_opt = ifs.longest_match(*sockaddr_v6.ip());
            match prefix_opt {
                Some((_addr, _plen, ifstate)) => Some(ifstate),
                None => None,
            }
        }
        _ => None,
    }
}

fn interface_trees_init(
    domain: String,
    v4_ifs: &mut treebitmap::IpLookupTable<std::net::Ipv4Addr, IfState>,
    v6_ifs: &mut treebitmap::IpLookupTable<std::net::Ipv6Addr, IfState>,
) {
    // Build tree of interface address/prefix lengths containing ifindex for later verification
    let events = get_current_events()
        .into_iter()
        .filter(|event| IfEvent::not_link_local(event))
        .filter(|event| IfEvent::not_loopback(event));
    for event in events {
        match event.ipnet {
            IpAddr::V4(ip4) => {
                let label: String = ip4.octets().into_iter().map(|d| format!("{:02x}", d)).collect();
                let subdomain = format!("{}.{}", label, domain);
                let ifs = IfState {
                    ifindex: event.ifindex,
                    subdomain: subdomain,
                };
                v4_ifs.insert(ip4, event.plen.into(), ifs);
            },
            IpAddr::V6(ip6) => {
                let mut len: u8 = event.plen / 8;
                if event.plen % 8 > 0 {
                    len += 1;
                }
                let label: String = ip6.octets().into_iter().take(len as usize).map(|d| format!("{:02x}", d)).collect();
                let subdomain = format!("{}.{}", label, domain);
                let ifs = IfState {
                    ifindex: event.ifindex,
                    subdomain: subdomain,
                };
                v6_ifs.insert(ip6, event.plen.into(), ifs);
            },
        };
    }
}

fn update_servers_init(
    v4_ifs: &treebitmap::IpLookupTable<std::net::Ipv4Addr, IfState>,
    v6_ifs: &treebitmap::IpLookupTable<std::net::Ipv6Addr, IfState>,
) -> HashMap <String, Arc<Mutex<update::UpdateServer>>>{
    let mut usmap = HashMap::new();
    for (_addr, _plen, intf) in v4_ifs.iter() {
        let up = update::UpdateServer::new(Domain::ipv4(), intf.subdomain.clone());
        usmap.insert(intf.subdomain.clone(), Arc::new(Mutex::new(up)));
    }
    for (_addr, _plen, intf) in v6_ifs.iter() {
        let up = update::UpdateServer::new(Domain::ipv6(), intf.subdomain.clone());
        usmap.insert(intf.subdomain.clone(), Arc::new(Mutex::new(up)));
    }
    usmap
}

fn build_update(se: &services::ServiceEvent) -> Message
{
    use std::str::FromStr;
    use domain_core::bits::{Dname, MessageBuilder, SectionBuilder, RecordSectionBuilder};
    use domain_core::iana::opcode;
    use domain_core::iana::Rtype;

    let mut msg = MessageBuilder::with_capacity(4096);
    msg.header_mut().set_opcode(opcode::Opcode::Update);

    // Zone section
    let name = Dname::from_str(&se.subdomain).unwrap();
    msg.push((&name, Rtype::Soa)).unwrap();

    // skip prereq sections
    let msg = msg.answer();

    // add to Update section
    let mut msg = msg.authority();
    match &se.sdata {
        AllRecordData::A(_addr) => {
            msg.push((&se.sname, 86400, se.sdata.clone())).unwrap();
        },
        AllRecordData::Aaaa(_addr) => {
            msg.push((&se.sname, 86400, se.sdata.clone())).unwrap();
        },  
        AllRecordData::Ptr(_name) => {
            msg.push((&se.sname, 86400, se.sdata.clone())).unwrap();
        },  
        AllRecordData::Srv(_srv) => {
            msg.push((&se.sname, 86400, se.sdata.clone())).unwrap();
        },  
        AllRecordData::Txt(_txt) => {
            msg.push((&se.sname, 86400, se.sdata.clone())).unwrap();
        },
        _ => {},
    }           

    let mut msg = msg.opt().unwrap();
    msg.set_udp_payload_size(4096);
    msg.freeze()
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

    if options.domain.len() == 0 {
        let resolver = StubResolver::new();
        let s = resolver.options();
        if s.search.len() > 0 {
            options.domain = s.search[0].to_string();
        } else {
            eprintln!("no domain name suffix available");
            exit(1);
        }
    }
    // initialize interface index trees
    let mut v4_ifs = treebitmap::IpLookupTable::new();
    let mut v6_ifs = treebitmap::IpLookupTable::new();
    interface_trees_init(options.domain, &mut v4_ifs, &mut v6_ifs);

    // create a mapping from subdomain name to update server
    // TODO: periodically refresh
    let usmap = update_servers_init(&v4_ifs, &v6_ifs);

    // create channel for ServiceEvents
    let (tx, rx) = unbounded::<services::ServiceEvent>();

    // create cache receiver for ServiceEvents
    // create a services cache per interface index, IPv4 & IPv6 should be merged
    let mut cache_map: HashMap<u32, HashMap<RecordKey, RecordInfo>> = HashMap::new();

    // receive mDNS events over channel
    thread::spawn(move || {
        for se in rx.iter() {
            if !cache_map.contains_key(&se.ifindex) {
                let table = HashMap::new();
                cache_map.insert(se.ifindex, table);
            }
            let cache = cache_map.get_mut(&se.ifindex).unwrap();
            let when = Instant::now() + Duration::from_secs(se.ttl.into());

            let key = RecordKey {
                name: se.sname.clone(),
                data: se.sdata.clone(),
            };
            let val = RecordInfo { ttl: se.ttl };

            match cache.entry(key.clone()) {
                Vacant(entry) => {
                    println!(
                        "caching {} + {:?} on ifindex: {}, subdomain: {}",
                        key.name, key.data, se.ifindex, se.subdomain,
                    );
                    /* TODO: 
                    let task = Delay::new(when)
                        .map_err(|e| panic!("delay errored; err={:?}", e))
                        .and_then(move |_| {
                            println!("timeout for {} + {:?}", key.name, key.data);
                            Ok(())
                        });

                    tokio::spawn(task);
                    */
                    entry.insert(val);

                    // send new cache entries to DNS Update server.
                    if let Some(ups) = usmap.get(&se.subdomain) {
                        update::send(ups, build_update(&se));
                    }
                    
                }
                Occupied(exists) => {
                    println!(
                        "found: {} + {:?} on ifindex: {}, subdomain {}",
                        key.name, key.data, se.ifindex, se.subdomain,
                    );
                    let mut entry = exists.into_mut();
                    entry.ttl = se.ttl;
                }
            };
        }
    });

    const IPV4MC_ALLIF: Token = Token(0);
    let poll = Poll::new().expect("Poll::new() failed");

    let v4_listen_addr = SocketAddr::from(SocketAddrV4::new(IP_ALL.into(), MDNS_PORT));
    let v4_std_socket = multicast::join_multicast(&MDNS_IPV4, &v4_listen_addr, 0)
                                .expect("mDNS IPv4 join_multicast");
    let v4_socket = UdpSocket::from_socket(v4_std_socket).expect("mio from_socket()");
    if options.nofour == false {
        poll.register(&v4_socket, IPV4MC_ALLIF, Ready::readable(), PollOpt::edge()).expect("poll.register failed");
    }

    let mut events = Events::with_capacity(1024);
    let mut source = tx.clone();
    let mut buf = [0; 4096];
    loop {
        poll.poll(&mut events, None).expect("poll.poll failed");
        for event in events.iter() {
            match event.token() {
                IPV4MC_ALLIF => {
                    let (_length, from_addr) = v4_socket.recv_from(&mut buf).expect("recv_from failed");
                    //println!("event from {:?}", from_addr);
                    match ifstate_for_v4_address(from_addr, &v4_ifs) {
                        Some(ifs) => {
                            extract_mdns_response(ifs.ifindex, &ifs.subdomain, from_addr, &buf, &mut source);
                        },
                        None => {
                            eprintln!("No interface for addr {:?}", from_addr);
                        }
                    };
                }
                _ => unreachable!()
            }
        }
    }
}