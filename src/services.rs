use bytes::Bytes;
use domain_core::name::ParsedDname;
use domain_core::opt::Opt;
use domain_core::rdata::AllRecordData;
use domain_core::Dname;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, PartialEq)]
pub enum ServiceAction {
    DYNAMIC,
    STATIC,
    FILTER,
}

#[derive(Debug)]
pub struct ServiceEvent {
    pub saction: ServiceAction,
    pub sname: Dname,
    pub sdata: AllRecordData<ParsedDname>,
    pub ifindex: u32,
    pub subdomain: String,
    pub from: SocketAddr,
    pub ip4: Option<Ipv4Addr>,
    pub ip6: Option<Ipv6Addr>,
    pub ptr: Option<ParsedDname>,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: Option<ParsedDname>,
    pub txt: Option<Bytes>,
    pub opt: Option<Opt>,
    pub ttl: u32,
}

impl ServiceEvent {
    pub fn new_a(
        action: ServiceAction,
        dname: Dname,
        data: AllRecordData<ParsedDname>,
        idx: u32,
        sub: &String,
        from: SocketAddr,
        ip4: &Ipv4Addr,
        ttl: u32,
    ) -> ServiceEvent {
        ServiceEvent {
            saction: action,
            sname: dname,
            sdata: data,
            ifindex: idx,
            subdomain: sub.to_string(),
            from: from,
            ip4: Some(*ip4),
            ip6: None,
            ptr: None,
            priority: 0,
            weight: 0,
            port: 0,
            target: None,
            txt: None,
            opt: None,
            ttl: ttl,
        }
    }
    pub fn new_aaaa(
        action: ServiceAction,
        dname: Dname,
        data: AllRecordData<ParsedDname>,
        idx: u32,
        sub: &String,
        from: SocketAddr,
        ip6: &Ipv6Addr,
        ttl: u32,
    ) -> ServiceEvent {
        ServiceEvent {
            saction: action,
            sname: dname,
            sdata: data,
            ifindex: idx,
            subdomain: sub.to_string(),
            from: from,
            ip4: None,
            ip6: Some(*ip6),
            ptr: None,
            priority: 0,
            weight: 0,
            port: 0,
            target: None,
            txt: None,
            opt: None,
            ttl: ttl,
        }
    }
    pub fn new_ptr(
        action: ServiceAction,
        dname: Dname,
        data: AllRecordData<ParsedDname>,
        idx: u32,
        sub: &String,
        from: SocketAddr,
        ptrname: &ParsedDname,
        ttl: u32,
    ) -> ServiceEvent {
        ServiceEvent {
            saction: action,
            sname: dname,
            sdata: data,
            ifindex: idx,
            subdomain: sub.to_string(),
            from: from,
            ip4: None,
            ip6: None,
            ptr: Some(ptrname.clone()),
            priority: 0,
            weight: 0,
            port: 0,
            target: None,
            txt: None,
            opt: None,
            ttl: ttl,
        }
    }
    pub fn new_srv(
        action: ServiceAction,
        dname: Dname,
        data: AllRecordData<ParsedDname>,
        idx: u32,
        sub: &String,
        from: SocketAddr,
        priority: u16,
        weight: u16,
        port: u16,
        target: &ParsedDname,
        ttl: u32,
    ) -> ServiceEvent {
        ServiceEvent {
            saction: action,
            sname: dname,
            sdata: data,
            ifindex: idx,
            subdomain: sub.to_string(),
            from: from,
            ip4: None,
            ip6: None,
            ptr: None,
            priority: priority,
            weight: weight,
            port: port,
            target: Some(target.clone()),
            txt: None,
            opt: None,
            ttl: ttl,
        }
    }
    pub fn new_txt(
        action: ServiceAction,
        dname: Dname,
        data: AllRecordData<ParsedDname>,
        idx: u32,
        sub: &String,
        from: SocketAddr,
        txt: Bytes,
        ttl: u32,
    ) -> ServiceEvent {
        ServiceEvent {
            saction: action,
            sname: dname,
            sdata: data,
            ifindex: idx,
            subdomain: sub.to_string(),
            from: from,
            ip4: None,
            ip6: None,
            ptr: None,
            priority: 0,
            weight: 0,
            port: 0,
            target: None,
            txt: Some(txt),
            opt: None,
            ttl: ttl,
        }
    }
    pub fn new_opt(
        action: ServiceAction,
        dname: Dname,
        data: AllRecordData<ParsedDname>,
        idx: u32,
        sub: &String,
        from: SocketAddr,
        opt: Opt,
        ttl: u32,
    ) -> ServiceEvent {
        ServiceEvent {
            saction: action,
            sname: dname,
            sdata: data,
            ifindex: idx,
            subdomain: sub.to_string(),
            from: from,
            ip4: None,
            ip6: None,
            ptr: None,
            priority: 0,
            weight: 0,
            port: 0,
            target: None,
            txt: None,
            opt: Some(opt),
            ttl: ttl,
        }
    }
}
