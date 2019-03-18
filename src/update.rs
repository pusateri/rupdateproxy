use std::net::UdpSocket;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use domain_core::bits::message::Message;

const DNS_PORT: u16 = 53;

#[derive(Debug)]
pub struct UpdateServer {
    sa: SocketAddr,
    socket: Option<UdpSocket>,
}

// eventually, this should perform a SRV query _dns-update._udp.<subdomain>.<domain>. 
pub fn resolve_server(_domain: String) -> SocketAddr
{
	SocketAddr::new(Ipv4Addr::new(127,0,0,1).into(), DNS_PORT)
}

pub fn send(_server: &UpdateServer, _msg: Message)
{
	
}