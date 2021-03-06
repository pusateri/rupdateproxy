use domain_core::message::Message;
use mio::net::UdpSocket;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

const DNS_PORT: u16 = 53;

/*
 * An Update server instance is created for each subdomain (created for each IP Subnet)
 * It must be able to handle sending a DNS Update message and waiting for the response.
 */

pub enum UpLocate {
    Initial,
    ResovleSRV,
    ResolveSOA,
    NotFound,
    FoundUDP,
    FoundTCP,
    FoundTLS,
}

pub struct UpdateServer {
    state: UpLocate,
    subdomain: String,
    target: Option<String>,
    port: u16,
    udp: Option<UdpSocket>,
}

impl UpdateServer {
    pub fn new(_family: Domain, subdomain: String) -> Self {
        //let addr = SocketAddr::new(Ipv4Addr::new(127,0,0,1).into(), 8053);
        let socket = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))
            .expect("ipv4 dgram socket");
        let mio_socket =
            UdpSocket::from_socket(socket.into_udp_socket()).expect("mio from_socket()");
        UpdateServer {
            state: UpLocate::Initial,
            subdomain: subdomain,
            target: None,
            port: 0,
            udp: Some(mio_socket),
        }
    }

    pub fn locate(self) {
        match self.state {
            UpLocate::Initial => (),
            UpLocate::ResovleSRV => (),
            UpLocate::ResolveSOA => (),
            UpLocate::NotFound => (),
            UpLocate::FoundUDP => (),
            UpLocate::FoundTCP => (),
            UpLocate::FoundTLS => (),
        }
    }
}

// eventually, this should perform a SRV query _dns-update._udp.<subdomain>.<domain>.
pub fn resolve_server(_domain: String) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), DNS_PORT)
}

pub fn send(uswrap: &Arc<Mutex<UpdateServer>>, msg: Message) {
    let us = uswrap.lock().unwrap();
    let addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8053);
    match &us.udp {
        Some(socket) => socket.send_to(msg.as_bytes(), &addr).unwrap(),
        None => 0,
    };
}
