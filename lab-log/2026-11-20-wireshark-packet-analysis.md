# 2026-11-20 · Packet analysis with Wireshark and tshark

| | |
| --- | --- |
| **Track** | Cyber Security |
| **Status** | Done (my own output and screenshots still to add) |
| **Environment** | Ubuntu, Wireshark and tshark |

## What the lab covered

Capturing live traffic, slicing it with display filters for HTTP, TCP and DNS, looking for signs of suspicious activity, and exporting the results for a report.

## Commands and configs used

```bash
# install and allow non-root capture
sudo apt install wireshark
sudo usermod -aG wireshark "$USER"
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
getcap /usr/bin/dumpcap

# capture
tshark -D                                   # list interfaces
sudo tshark -i <iface> -c 100 -w capture.pcap

# generate traffic in another terminal
curl -I http://example.com
dig example.org
ping -c 5 8.8.8.8
```

Display filters I used:

| Goal | Filter |
| --- | --- |
| HTTP GET requests | `http.request.method == "GET"` |
| New TCP connections | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| Retransmissions | `tcp.analysis.retransmission` |
| DNS queries only | `dns.flags.response == 0` |
| DNS errors | `dns.flags.rcode != 0` |
| Web traffic | `tcp.port == 80 or tcp.port == 443` |

```bash
# export and report
tshark -r capture.pcap -Y http -w http_only.pcap
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name -e dns.a > dns.csv
tshark -r capture.pcap -q -z io,phs        # protocol hierarchy
tshark -r capture.pcap -q -z conv,tcp      # TCP conversations
```

The lab finishes with a small shell script that runs the `-z` reports above and collects them into one text report.

## What to look for (anomaly hunting)

- Many SYNs from one host to many ports with RSTs coming back: likely a port scan.
- Long, random-looking domain names or a burst of DNS queries: possible malware using generated domains.
- HTTP on unusual ports, or credentials in clear text.
- Unexpectedly large outbound transfers.

## What broke and how I fixed it

_To do: note any errors from my own run here._

## Key takeaway

A capture is noise until you ask it a question. Learning a handful of display filters is what turns it into evidence.

## Screenshots

Folder: [`screenshots/2026-11-20-wireshark-packet-analysis/`](screenshots/) (to add: filtered packet list, protocol hierarchy output).

> Raw `.pcap` files are not committed, because they can contain real traffic from my network.
