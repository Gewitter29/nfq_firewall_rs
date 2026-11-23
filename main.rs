use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use nfq::{Queue, Verdict};

fn main() -> std::io::Result<()> {
    let mut queue = Queue::open()?;
    queue.bind(0)?;

    println!("[*] Rust Firewall active (Queue 0). Listening for packets...");

    loop {
        let mut msg = queue.recv()?;
        let payload = msg.get_payload();

        let verdict = inspect_packet(payload);
        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    }
}

fn inspect_packet(data: &[u8]) -> Verdict {
    match SlicedPacket::from_ip(data) {
        Ok(packet) => {
            let src_ip = match packet.net {
                Some(NetSlice::Ipv4(ipv4)) => ipv4.header().source_addr().to_string(),
                Some(NetSlice::Ipv6(ipv6)) => ipv6.header().source_addr().to_string(),
                _ => String::from("Unknown IP"),
            };

            match packet.transport {
                Some(TransportSlice::Tcp(tcp)) => {
                    let dst_port = tcp.destination_port();
                    if dst_port == 8080 {
                        println!("[BLOCKED] TCP {} -> Port {}", src_ip, dst_port);
                        return Verdict::Drop;
                    }
                }
                Some(TransportSlice::Udp(udp)) => {
                    let dst_port = udp.destination_port();
                    if dst_port == 8080 {
                        println!("[BLOCKED] UDP {} -> Port {}", src_ip, dst_port);
                        return Verdict::Drop;
                    }
                }
                _ => {}
            }
            Verdict::Accept
        }
        Err(_) => Verdict::Accept,
    }
}
