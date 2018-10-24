extern crate argparse;

use self::argparse::{ArgumentParser, StoreTrue, Store, Print};

pub struct Options {
    pub(crate) nofork: bool,
    pub(crate) verbose: bool,
    pub(crate) nofour: bool,
    pub(crate) nosix: bool,
    pub(crate) pid_file: String,
    pub(crate) domain: String,
    pub(crate) include_interfaces: String,
    pub(crate) exclude_interfaces: String,
}


// parse config options
pub fn parse_opts(opts: &mut Options)
{
    let mut ap = ArgumentParser::new();
    let version = env!("CARGO_PKG_VERSION").to_string();
    let git_version = env!("PKG_GIT_VERSION").to_string();
    let package = env!("CARGO_PKG_NAME").to_string();
    let home = env!("CARGO_PKG_HOMEPAGE").to_string();
    let vstring = format!("{} {} {} ({})", package, version, git_version, home);
    ap.set_description("DNS Update Proxy");
    ap.refer(&mut opts.verbose)
        .add_option(&["-v", "--verbose"], StoreTrue,
        "Verbose output to stderr");
    ap.add_option(&["-V", "--version"],
        Print(vstring), "Show version");
    ap.refer(&mut opts.nofork)
        .add_option(&["-n", "--nofork"], StoreTrue,
        "Run in foreground");
    ap.refer(&mut opts.include_interfaces)
        .add_option(&["-i", "--include-interfaces"], Store,
        "Comma separated list of interface names to include")
        .metavar("\"eth0, eth1, etc.\"");
    ap.refer(&mut opts.exclude_interfaces)
        .add_option(&["-x", "--exclude-interfaces"], Store,
        "Comma separated list of interface names to exclude")
        .metavar("\"eth0, eth1, etc.\"");
    ap.refer(&mut opts.pid_file)
        .add_option(&["-p", "--pid-file"], Store,
        "Path to pid file")
        .metavar("<pid-file-path>");
    ap.refer(&mut opts.domain)
        .add_option(&["-d", "--domain"], Store,
        "Domain name suffix (without leading '.')");
    ap.refer(&mut opts.nofour)
        .add_option(&["--no-ipv4"], StoreTrue,
        "Disable IPv4");
    ap.refer(&mut opts.nosix)
        .add_option(&["--no-ipv6"], StoreTrue,
        "Disable IPv6");
    ap.parse_args_or_exit();
}
