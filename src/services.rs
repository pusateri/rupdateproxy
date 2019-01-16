
use domain_core::bits::Dname;
use domain_core::bits::name::ParsedDname;
use domain_core::rdata::AllRecordData;

#[derive(Debug, PartialEq)]
pub enum ServiceAction {
    DYNAMIC,
    STATIC,
    FILTER,
}

#[derive(Debug, PartialEq)]
pub struct ServiceEvent {
    pub saction: ServiceAction,
    pub sname: Dname,
    pub sdata: AllRecordData<ParsedDname>,
    pub ifindex: u32,
    pub ttl: u32,
}

impl ServiceEvent {
    pub fn new(
        action: ServiceAction,
        dname: Dname,
        data: AllRecordData<ParsedDname>,
        idx: u32,
        ttl: u32,
    ) -> ServiceEvent {
        ServiceEvent {
            saction: action,
            sname: dname,
            sdata: data,
            ifindex: idx,
            ttl: ttl,
        }
    }
}



