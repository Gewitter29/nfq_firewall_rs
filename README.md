# nfq_firewall_rs

A lightweight packet-filtering firewall for Linux written in Rust using Netfilter Queue (`nfq`) and `etherparse`. It intercepts packets routed to a kernel queue, parses IPv4/IPv6 and TCP/UDP headers, and enforces `Accept` or `Drop` rules in real time.

## Requirements

- Linux kernel with Netfilter Queue (`nfnetlink_queue`) support
- Rust toolchain (`cargo`, `rustc`)
- `libnetfilter_queue` development headers

### Installing System Dependencies

**Fedora / RHEL:**
```bash
sudo dnf install libnetfilter_queue-devel clang

**Ubuntu / Debian:**
                sudo apt install libnetfilter-queue-dev clang

**Build:**
cargo build --release
Usage

    Start the firewall (requires root privileges to bind to the netfilter queue):
    Bash

    sudo ./target/release/nfq_firewall_rs

    Route traffic to Queue 0 using nftables:
    Bash

    sudo nft add table inet rustfw
    sudo nft add chain inet rustfw output '{ type filter hook output priority 0; policy accept; }'
    sudo nft add rule inet rustfw output tcp dport 8080 queue num 0

    Remove the nftables rule when finished:
    Bash

    sudo nft delete table inet rustfw
