/// Rustsocket
/// 
/// Helper program for Rustwall
/// Forwards data from tap interface over sockets to a remote machine
/// To be run on a VM
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate smoltcp;

/// Auxilliary tools
mod utils;
use std::os::unix::io::AsRawFd;
use std::time::Instant;
use std::thread;
use std::sync::mpsc;
use std::str::FromStr;

/// Firewall related
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::TapInterface;
use std::net::UdpSocket;
use smoltcp::socket::{RawSocket, RawSocketBuffer, RawPacketBuffer, AsSocket, SocketSet};
use smoltcp::iface::{ArpCache, SliceArpCache, EthernetInterface};
use smoltcp::wire::{EthernetAddress, IpVersion, IpProtocol, IpAddress, Ipv4Address};

const HARDWARE_ADDRESS: EthernetAddress = EthernetAddress([0x04, 0x00, 0x00, 0x00, 0x00, 0x04]);

/// Configuration struct that holds
/// data about which packeets to pass
struct RustsocketConfiguration {
    name: String,
    hardware_addr: EthernetAddress,
}

impl RustsocketConfiguration {
    fn new(name: &str) -> RustsocketConfiguration {
        RustsocketConfiguration {
            name: String::from(name),
            hardware_addr: HARDWARE_ADDRESS,
        }
    }
}


///
/// Auxilliary thread - receives data over channel from the main firewall thread
/// and sends it over socket to the VM
///
fn thread_socket_sender(name: String, // typically SocketSender
                        local_addr: Ipv4Address, // iface connected to VM
                        remote_addr: Ipv4Address, // address of the VM (from the VM side)
                        port: u16, // comm port, typically 6666
                        rx: mpsc::Receiver<Vec<u8>>) {
    let local_addr = format!("{}:{}", local_addr, port);
    let remote_addr = format!("{}:{}", remote_addr, port);
    let socket = UdpSocket::bind(local_addr).expect("couldn't bind to address"); // local interface

    socket
        .connect(remote_addr)
        .expect("connect function failed");

    println!("{} starting", name);
    loop {
        let data = rx.recv().expect("Couldn't receive data");
        let len = socket
            .send(data.as_slice())
            .expect("Couldn't send data");
        println!("{} Sent {} data.", name, len);
    }
}


///
/// Auxilliary thread - receives data over channel from the main firewall thread
/// and sends it over socket to the VM
///
fn thread_socket_receiver(name: String, // typically SocketReceiiver
                          local_addr: Ipv4Address, // iface connected to VM
                          remote_addr: Ipv4Address, // address of the VM (from the VM side)
                          port: u16, // comm port, typically 6667
                          tx: mpsc::Sender<Vec<u8>>) {
    let local_addr = format!("{}:{}", local_addr, port);
    let remote_addr = format!("{}:{}", remote_addr, port);
    let socket = UdpSocket::bind(local_addr).expect("couldn't bind to address"); // local interface

    socket
        .connect(remote_addr)
        .expect("connect function failed");

    let mut buf = vec![0; 1024];

    println!("{} starting", name);
    loop {
        match socket.recv(&mut buf) {
            Ok(len) => {
                println!("{} received {} data.", name, len);
                let data = buf[0..len].to_vec();
                tx.send(data).expect("Couldn't send data");
            }
            Err(e) => println!("{} recv function failed: {:?}", name, e),
        }
    }
}



///
/// Main function
///
fn main() {
    // logging and options setup
    utils::setup_logging("warn");
    let (opts, free) = utils::create_options();
    let mut matches = utils::parse_options(&opts, free);

    // iface and socket setup
    let device_name = utils::parse_tap_options(&mut matches);
    println!("device_name {}", device_name);
    let local_address = Ipv4Address::from_str(&matches.free.remove(0)).expect("invalid address format");
    println!("local_address {}", local_address);
    let vm_iface_addr = Ipv4Address::from_str(&matches.free.remove(0)).expect("invalid address format");
    println!("vm_iface {}", vm_iface_addr);
    let vm_address = Ipv4Address::from_str(&matches.free.remove(0)).expect("invalid address format");
    println!("vm_address {}", vm_address);
    let tx_port = u16::from_str(&matches.free.remove(0)).expect("invalid port format");
    println!("tx_port {}", tx_port);
    let rx_port = u16::from_str(&matches.free.remove(0)).expect("invalid port format");
    println!("rx_port {}", rx_port);

    // channels setup
    let (tx_0, rx_0) = mpsc::channel();
    let (tx_1, rx_1) = mpsc::channel();

    // actual firewall configuration
    let cfg_0 = RustsocketConfiguration::new(&device_name);


    println!("Rustwall starting.");

    let th_0 = thread::spawn(move || thread_iface(&device_name, local_address, rx_0, tx_1, cfg_0));

    // Sending socket
    // Passes data to the VM interface
    let th_tx = thread::spawn(move || {
                                  thread_socket_sender(String::from("SocketSender"),
                                                       vm_iface_addr,
                                                       vm_address,
                                                       tx_port,
                                                       rx_1)
                              });

    // Receiving socket
    // Receives data from the VM interface and passes it to the firewall
    let th_rx = thread::spawn(move || {
                                  thread_socket_receiver(String::from("SocketReceiver"),
                                                         vm_iface_addr,
                                                         vm_address,
                                                         rx_port,
                                                         tx_0)
                              });

    th_0.join().expect("Thread 0 error");
    th_tx.join().expect("SocketSender error");
    th_rx.join().expect("SocketReceiver error");
    println!("Rustwall terminating.");
}


///
/// Interface thread
///
fn thread_iface(iface_name: &str,
                ipaddr: Ipv4Address,
                rx: mpsc::Receiver<Vec<u8>>,
                tx: mpsc::Sender<Vec<u8>>,
                cfg: RustsocketConfiguration) {
    let startup_time = Instant::now();

    let device = TapInterface::new(iface_name).unwrap();

    let fd = device.as_raw_fd();

    let raw_rx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 1024])]);
    let raw_tx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 1024])]);
    let raw_socket = RawSocket::new(IpVersion::Ipv4,
                                    IpProtocol::Udp,
                                    raw_rx_buffer,
                                    raw_tx_buffer);

    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);

    println!("{} Creating interface {}", cfg.name, iface_name);
    let mut iface = EthernetInterface::new(Box::new(device),
                                           Box::new(arp_cache) as Box<ArpCache>,
                                           cfg.hardware_addr,
                                           [IpAddress::from(ipaddr)]);

    let mut sockets = SocketSet::new(vec![]);
    let raw_handle = sockets.add(raw_socket);

    println!("{} Starting", cfg.name);

    loop {
        {
            let socket: &mut RawSocket = sockets.get_mut(raw_handle).as_socket();

            // Receive a new packet from the socket
            if socket.can_recv() {
                println!("{} Got data", cfg.name);
                let payload = socket.recv().unwrap();
                //println!("{} raw packet: {:?}", cfg.name, payload);
                tx.send(payload.to_vec()).unwrap();
            } // if socket.can_recv()

            // Check if we have a packet to send
            if socket.can_send() {
                match rx.try_recv() {
                    Ok(payload) => {
                        println!("{} Sending data", cfg.name);
                        println!("Payload len = {}", payload.len());
                        let raw_payload = socket.send(payload.len()).unwrap(); // get a slice
                        for i in 0..payload.len() {
                        	raw_payload[i] = payload[i];
                        }
                        println!("Payload: {:?}", payload);
                        println!("Raw payload: {:?}", raw_payload);

                    }
                    Err(err) => {
                        println!("{} Error receiving data: {}", cfg.name, err);
                    }
                }
            } // if socket.can_send()
        }

        let timestamp = utils::millis_since(startup_time);
        let poll_at = iface.poll(&mut sockets, timestamp).expect("poll error");
        phy_wait(fd, Some(1)).expect("wait error");
    }
}
