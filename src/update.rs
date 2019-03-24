#![feature(optin_builtin_traits)]

use socket2::Domain;
use std::sync::{Arc, Mutex};
use futures::stream::{SplitSink, SplitStream};
use tokio::prelude::*;
use tokio::net::{UdpFramed, UdpSocket};
use tokio_codec::BytesCodec;
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
    sa: SocketAddr,
    sink: Arc<Mutex<SplitSink<UdpFramed<BytesCodec>>>>,
    stream: Arc<Mutex<SplitStream<UdpFramed<BytesCodec>>>>,
}

unsafe impl Send for UpdateServer {}
unsafe impl Sync for UpdateServer {}

impl UpdateServer {
    pub fn new(_family: Domain, subdomain: String) -> Self {
    	let addr = SocketAddr::new(Ipv4Addr::new(127,0,0,1).into(), 8053);
    	let sock = UdpSocket::bind(&addr).expect("bind failed");
    	let (a_sink, a_stream) = UdpFramed::new(sock, BytesCodec::new()).split();
        UpdateServer {
        	subdomain: subdomain,
            sa: addr,
            sink: Arc::new(Mutex::new(a_sink)),
            stream: Arc::new(Mutex::new(a_stream)),
        }
    }
}

// eventually, this should perform a SRV query _dns-update._udp.<subdomain>.<domain>. 
pub fn resolve_server(_domain: String) -> SocketAddr
{
	SocketAddr::new(Ipv4Addr::new(127,0,0,1).into(), DNS_PORT)
}

pub fn send(uswrap: &Arc<Mutex<UpdateServer>>, msg: Message)
{
	let us = uswrap.lock().unwrap();
	let a_sink = us.sink.lock().unwrap();
    let task = a_sink.send((msg.as_bytes().clone(), us.sa))
    	.and_then(move |_| {
    		let a_stream = us.stream.lock().unwrap();
			let _a_stream = a_stream.take(1)
        	.into_future()
        	.map(move |(_response, addr)| {
            	println!("task recv from {:?}", addr);
        	})
        	.map_err(|e| panic!("send update err={:?}", e));
        	Ok(())
    	})
    	.or_else(|n| {
            println!("read {:?} bytes2", n);
            Ok(())
        });
    tokio::spawn(task);
}