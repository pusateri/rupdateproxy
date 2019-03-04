use std::net::SocketAddr;
use std::net::Ipv4Addr;
use domain_core::bits::message::Message;

const DNS_PORT: u16 = 53;

// eventually, this should perform a SRV query _dns-update._udp.<subdomain>.<domain>. 
pub fn resolve_server(_domain: String) -> SocketAddr
{
	SocketAddr::new(Ipv4Addr::new(127,0,0,1).into(), DNS_PORT)
}

pub fn send(msg: Message)
{

}