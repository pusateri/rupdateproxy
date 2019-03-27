use socket2::Domain;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use domain_core::bits::message::Message;

const DNS_PORT: u16 = 53;

/*
 * An Update server instance is created for each subdomain (created for each IP Subnet)
 * It must be able to handle sending a DNS Update message and waiting for the response.
 * Any errors should propagate upstream.
 */


pub struct UpdateServer {
	subdomain: String,
}

impl UpdateServer {
    pub fn new(_family: Domain, subdomain: String) -> Self {
    	//let addr = SocketAddr::new(Ipv4Addr::new(127,0,0,1).into(), 8053);
        UpdateServer {
        	subdomain: subdomain,
        }
    }
}

// eventually, this should perform a SRV query _dns-update._udp.<subdomain>.<domain>. 
pub fn resolve_server(_domain: String) -> SocketAddr
{
	SocketAddr::new(Ipv4Addr::new(127,0,0,1).into(), DNS_PORT)
}

pub fn send(uswrap: &Arc<Mutex<UpdateServer>>, _msg: Message)
{
    let _result = { 
        let _us = uswrap.lock().unwrap();
    };
    
}