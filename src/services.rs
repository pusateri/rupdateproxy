
use domain_core::bits::Dname;
use domain_core::bits::name::ParsedDname;
use domain_core::rdata::AllRecordData;
use futures::sync::mpsc;

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

pub struct ServiceController {
	pub sender: mpsc::Sender<ServiceEvent>,
	pub receiver: mpsc::Receiver<ServiceEvent>,
}

impl ServiceController {
	pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1000);
		let controller = ServiceController {
			sender: tx,
			receiver: rx,
		};
		controller
	}

    /// get a sender channel
    pub fn originate(&self) -> mpsc::Sender<ServiceEvent> {
        self.sender.clone()
    }
}


