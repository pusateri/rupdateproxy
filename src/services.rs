
use domain_core::bits::Dname;
use domain_core::bits::name::ParsedDname;
use domain_core::rdata::AllRecordData;
use crossbeam_channel::{unbounded, Receiver, Sender};

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

#[derive(Clone)]
pub struct ServiceController {
	sender: Sender<ServiceEvent>,
	receiver: Receiver<ServiceEvent>,
}

impl ServiceController {
	pub fn new() -> Self {
		let (s, r) = unbounded::<ServiceEvent>();
		let controller = ServiceController {
			sender: s,
			receiver: r,
		};
		controller
	}

	/// subscribe to future service events
	pub fn subscribe(&self) -> Receiver<ServiceEvent> {
		self.receiver.clone()
	}

	/// unsubscribe to future service events
	pub fn unsubscribe(&self, r: Receiver<ServiceEvent>) {
		drop(r);
	}

    /// get a sender channel
    pub fn originate(&self) -> Sender<ServiceEvent> {
        self.sender.clone()
    }
}


