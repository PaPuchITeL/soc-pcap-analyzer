import argparse
import ipaddress
import json
from collections import Counter
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, Raw, TCP, UDP, rdpcap


HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

SEVERITY_LABELS = {
    "low": "INFO",
    "medium": "WARNING",
    "high": "ALERT",
}

# short list on purpose, just enough for practice
COMMON_PORTS = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    110,
    123,
    143,
    161,
    389,
    443,
    445,
    465,
    587,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    8080,
    8443,
}


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file and find simple suspicious activity."
    )
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument(
        "-o",
        "--output",
        default="analysis_results.json",
        help="Path to the JSON output file",
    )
    parser.add_argument(
        "--dns-threshold",
        "--dns-burst-count",
        dest="dns_burst_count",
        type=int,
        default=5,
        help="How many DNS requests inside the short window should trigger an event",
    )
    parser.add_argument(
        "--dns-window",
        type=float,
        default=10.0,
        help="Short time window in seconds for DNS burst detection",
    )
    parser.add_argument(
        "--correlation-window",
        type=float,
        default=5.0,
        help="Time window in seconds for simple DNS/IP correlation",
    )
    return parser.parse_args()


def get_ip_layer(packet):
    if packet.haslayer(IP):
        return packet[IP]
    if packet.haslayer(IPv6):
        return packet[IPv6]
    return None


def get_packet_time(packet):
    try:
        return float(packet.time)
    except (TypeError, ValueError):
        return 0.0


def choose_connection_port(src_port, dst_port):
    if src_port is None or dst_port is None:
        return None

    if src_port in COMMON_PORTS and dst_port not in COMMON_PORTS:
        return src_port

    if dst_port in COMMON_PORTS and src_port not in COMMON_PORTS:
        return dst_port

    if src_port <= 1024 < dst_port:
        return src_port

    if dst_port <= 1024 < src_port:
        return dst_port

    return dst_port


def build_connection_key(src_ip, dst_ip, src_port, dst_port, protocol):
    if src_port is None or dst_port is None:
        return None

    endpoints = sorted(((src_ip, src_port), (dst_ip, dst_port)))
    return protocol, tuple(endpoints)


def guess_service_port(packet, src_ip, dst_ip, src_port, dst_port, protocol, flow_ports):
    if src_port is None or dst_port is None:
        return None

    connection_key = build_connection_key(src_ip, dst_ip, src_port, dst_port, protocol)
    if connection_key in flow_ports:
        return flow_ports[connection_key]

    service_port = None

    if protocol == "TCP":
        tcp_flags = int(packet[TCP].flags)
        is_syn = bool(tcp_flags & 0x02)
        is_ack = bool(tcp_flags & 0x10)

        if is_syn and not is_ack:
            service_port = dst_port
        elif is_syn and is_ack:
            service_port = src_port

    if service_port is None:
        service_port = choose_connection_port(src_port, dst_port)

    flow_ports[connection_key] = service_port
    return service_port


def build_packet_record(packet_number, packet, first_packet_time, flow_ports, seen_flows):
    ip_layer = get_ip_layer(packet)
    if ip_layer is None:
        return None

    src_port = None
    dst_port = None
    protocol = "IP"

    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        protocol = "TCP"
    elif packet.haslayer(UDP):
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
        protocol = "UDP"

    flow_key = build_connection_key(ip_layer.src, ip_layer.dst, src_port, dst_port, protocol)
    is_new_flow = flow_key is not None and flow_key not in seen_flows
    if is_new_flow:
        seen_flows.add(flow_key)

    timestamp = get_packet_time(packet)

    return {
        "packet_number": packet_number,
        "timestamp": round(timestamp, 6),
        "time_offset": round(timestamp - first_packet_time, 6),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "port": guess_service_port(
            packet,
            ip_layer.src,
            ip_layer.dst,
            src_port,
            dst_port,
            protocol,
            flow_ports,
        ),
        "protocol": protocol,
        "flow_key": flow_key,
        "is_new_flow": is_new_flow,
    }


def safe_decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def ensure_record_list(value, record_type):
    if value is None:
        return []

    if isinstance(value, record_type):
        return [value]

    if hasattr(value, "__iter__"):
        return [item for item in value if isinstance(item, record_type)]

    return []


def extract_dns_queries(packet):
    if not packet.haslayer(DNS):
        return []

    dns_layer = packet[DNS]
    if dns_layer.qr != 0 or dns_layer.qdcount == 0:
        return []

    domains = []
    for question in ensure_record_list(dns_layer.qd, DNSQR):
        domain = safe_decode(question.qname).rstrip(".")
        if domain:
            domains.append(domain)

    return domains


def extract_dns_answers(packet):
    if not packet.haslayer(DNS):
        return []

    dns_layer = packet[DNS]
    if dns_layer.qr != 1 or dns_layer.ancount == 0:
        return []

    domain = ""
    questions = ensure_record_list(dns_layer.qd, DNSQR)
    if questions:
        domain = safe_decode(questions[0].qname).rstrip(".")

    answers = []
    for answer in ensure_record_list(dns_layer.an, DNSRR):
        if answer.type in (1, 28):
            resolved_ip = safe_decode(answer.rdata).strip()
            if domain and resolved_ip:
                answers.append((domain, resolved_ip))

    return answers


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_host(host_value):
    if not host_value:
        return ""

    host_value = host_value.strip()

    if host_value.startswith("[") and "]" in host_value:
        return host_value[1 : host_value.index("]")]

    if host_value.count(":") == 1 and "." in host_value:
        return host_value.split(":", 1)[0]

    return host_value


def extract_http_request_info(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None

    payload = bytes(packet[Raw].load)
    if not any(payload.startswith(method) for method in HTTP_METHODS):
        return None

    text = payload.decode("latin-1", errors="ignore")
    lines = text.split("\r\n")
    request_line = lines[0] if lines else ""
    host = ""

    for line in lines[1:]:
        if not line:
            break

        if ":" not in line:
            continue

        header_name, header_value = line.split(":", 1)
        if header_name.strip().lower() == "host":
            host = header_value.strip()
            break

    return {
        "request_line": request_line,
        "host": host,
    }


def request_line_uses_ip(request_line):
    parts = request_line.split()
    if len(parts) < 2:
        return False

    target = parts[1]
    if "://" not in target:
        return False

    host_part = target.split("://", 1)[1].split("/", 1)[0]
    return is_ip_address(normalize_host(host_part))


def uses_ip_in_http_request(http_info):
    host = normalize_host(http_info["host"])
    if host and is_ip_address(host):
        return True

    return request_line_uses_ip(http_info["request_line"])


def create_event(record, event_type, severity, reason, extra_fields=None):
    event = {
        "packet_number": record["packet_number"],
        "timestamp": record["timestamp"],
        "time_offset": record["time_offset"],
        "src_ip": record["src_ip"],
        "dst_ip": record["dst_ip"],
        "port": record["port"],
        "protocol": record["protocol"],
        "event_type": event_type,
        "severity": severity,
        "reason": reason,
    }

    if extra_fields:
        event.update(extra_fields)

    return event


def add_event(events, seen_keys, event):
    event_key = (
        event["event_type"],
        event["packet_number"],
        event["src_ip"],
        event["dst_ip"],
        event["port"],
        event["reason"],
    )

    if event_key in seen_keys:
        return

    seen_keys.add(event_key)
    events.append(event)


def find_best_dns_window(entries, window_seconds):
    left = 0
    best_count = 0
    best_start = 0
    best_end = 0

    for right, entry in enumerate(entries):
        while entry["timestamp"] - entries[left]["timestamp"] > window_seconds:
            left += 1

        current_count = right - left + 1
        if current_count > best_count:
            best_count = current_count
            best_start = left
            best_end = right

    return best_count, best_start, best_end


def detect_periodic_requests(entries):
    if len(entries) < 4:
        return None

    intervals = []
    for index in range(1, len(entries)):
        interval = entries[index]["timestamp"] - entries[index - 1]["timestamp"]
        if interval <= 0:
            return None
        intervals.append(interval)

    average_interval = sum(intervals) / len(intervals)
    if average_interval > 60:
        return None

    tolerance = max(1.0, average_interval * 0.3)
    similar_intervals = 0

    for interval in intervals:
        if abs(interval - average_interval) <= tolerance:
            similar_intervals += 1

    if similar_intervals >= max(3, len(intervals) - 1):
        return round(average_interval, 2)

    return None


def analyze_dns_activity(dns_queries, dns_counter, dns_window, dns_burst_count):
    events = []
    top_domains = []
    seen_keys = set()

    for domain, count in dns_counter.most_common(10):
        top_domains.append({"domain": domain, "count": count})

    for (src_ip, domain), entries in dns_queries.items():
        entries.sort(key=lambda item: item["timestamp"])

        # quick check for frequent domains
        best_count, start_index, end_index = find_best_dns_window(entries, dns_window)
        if best_count >= dns_burst_count:
            end_entry = entries[end_index]
            start_time = entries[start_index]["timestamp"]
            end_time = entries[end_index]["timestamp"]
            duration = max(end_time - start_time, 0.1)
            severity = "high" if best_count >= dns_burst_count * 2 else "medium"
            reason = (
                f"Domain '{domain}' was requested {best_count} times in "
                f"{duration:.1f} seconds"
            )
            event = create_event(
                end_entry["record"],
                "dns_burst",
                severity,
                reason,
                {
                    "domain": domain,
                    "request_count": best_count,
                },
            )
            add_event(events, seen_keys, event)

        # not perfect but works for now
        periodic_interval = detect_periodic_requests(entries)
        if periodic_interval is not None:
            trigger_entry = entries[-1]
            reason = (
                f"Domain '{domain}' was requested in a regular pattern "
                f"(about every {periodic_interval:.1f} seconds)"
            )
            event = create_event(
                trigger_entry["record"],
                "dns_periodic",
                "medium",
                reason,
                {
                    "domain": domain,
                    "request_count": len(entries),
                    "average_interval": periodic_interval,
                },
            )
            add_event(events, seen_keys, event)

    return events, top_domains


def correlate_dns_and_connections(dns_answers, connection_records, correlation_window):
    events = []
    seen_keys = set()
    answers_by_target = {}

    for answer in dns_answers:
        answer_key = (answer["client_ip"], answer["resolved_ip"])
        answers_by_target.setdefault(answer_key, []).append(answer)

    for answer_list in answers_by_target.values():
        answer_list.sort(key=lambda item: item["timestamp"])

    for record in connection_records:
        answer_list = answers_by_target.get((record["src_ip"], record["dst_ip"]), [])
        if not answer_list:
            continue

        for answer in reversed(answer_list):
            time_gap = record["timestamp"] - answer["timestamp"]
            if time_gap < 0:
                continue

            if time_gap > correlation_window:
                break

            severity = "high" if record["port"] not in COMMON_PORTS else "medium"
            reason = (
                f"Host resolved '{answer['domain']}' and connected to "
                f"{answer['resolved_ip']} {time_gap:.1f} seconds later"
            )
            event = create_event(
                record,
                "dns_ip_correlation",
                severity,
                reason,
                {
                    "domain": answer["domain"],
                    "resolved_ip": answer["resolved_ip"],
                },
            )
            add_event(events, seen_keys, event)
            break

    return events


def prepare_packet_output(records):
    packet_output = []

    for record in records:
        packet_output.append(
            {
                "packet_number": record["packet_number"],
                "timestamp": record["timestamp"],
                "time_offset": record["time_offset"],
                "src_ip": record["src_ip"],
                "dst_ip": record["dst_ip"],
                "src_port": record["src_port"],
                "dst_port": record["dst_port"],
                "port": record["port"],
                "protocol": record["protocol"],
            }
        )

    return packet_output


def format_event_line(event):
    label = SEVERITY_LABELS[event["severity"]]
    port_text = event["port"] if event["port"] is not None else "-"
    return (
        f"[{label}] Packet {event['packet_number']} | {event['event_type']} | "
        f"{event['src_ip']} -> {event['dst_ip']} | {event['protocol']}/{port_text} | "
        f"{event['reason']}"
    )


def print_soc_report(results):
    print(f"[INFO] Total packets read: {results['summary']['total_packets_read']}")
    print(f"[INFO] Total IP packets: {results['summary']['total_ip_packets']}")
    print(f"[INFO] Total events: {results['summary']['total_events']}")

    severity_counts = results["summary"]["severity_counts"]
    print(
        "[INFO] Severity counts: "
        f"low={severity_counts['low']}, "
        f"medium={severity_counts['medium']}, "
        f"high={severity_counts['high']}"
    )

    if not results["events"]:
        print("[INFO] No suspicious events found.")
        return

    for event in results["events"]:
        print(format_event_line(event))


def analyze_pcap(pcap_file, dns_burst_count, dns_window, correlation_window):
    packets = rdpcap(pcap_file)
    first_packet_time = get_packet_time(packets[0]) if packets else 0.0

    records = []
    events = []
    event_keys = set()
    dns_queries = {}
    dns_counter = Counter()
    dns_answers = []
    connection_records = []
    flow_ports = {}
    seen_flows = set()

    for packet_number, packet in enumerate(packets, start=1):
        record = build_packet_record(
            packet_number,
            packet,
            first_packet_time,
            flow_ports,
            seen_flows,
        )
        if record is None:
            continue

        records.append(record)

        if record["is_new_flow"] and record["port"] is not None and record["port"] != 53:
            connection_records.append(record)

        if record["is_new_flow"] and record["port"] is not None and record["port"] not in COMMON_PORTS:
            reason = f"Connection uses uncommon port {record['port']}"
            event = create_event(record, "uncommon_port", "medium", reason)
            add_event(events, event_keys, event)

        domains = extract_dns_queries(packet)
        for domain in domains:
            dns_counter[domain] += 1
            dns_key = (record["src_ip"], domain)
            dns_queries.setdefault(dns_key, []).append(
                {
                    "timestamp": record["timestamp"],
                    "record": record,
                }
            )

        answers = extract_dns_answers(packet)
        for domain, resolved_ip in answers:
            dns_answers.append(
                {
                    "timestamp": record["timestamp"],
                    "client_ip": record["dst_ip"],
                    "domain": domain,
                    "resolved_ip": resolved_ip,
                }
            )

        http_info = extract_http_request_info(packet)
        if http_info and uses_ip_in_http_request(http_info):
            reason = "HTTP request uses an IP address instead of a domain name"
            event = create_event(record, "http_ip_destination", "low", reason)
            add_event(events, event_keys, event)

    dns_events, top_domains = analyze_dns_activity(
        dns_queries,
        dns_counter,
        dns_window,
        dns_burst_count,
    )
    for event in dns_events:
        add_event(events, event_keys, event)

    correlation_events = correlate_dns_and_connections(
        dns_answers,
        connection_records,
        correlation_window,
    )
    for event in correlation_events:
        add_event(events, event_keys, event)

    events.sort(key=lambda item: (item["timestamp"], item["packet_number"], item["event_type"]))
    severity_counts = Counter(event["severity"] for event in events)
    event_type_counts = Counter(event["event_type"] for event in events)

    return {
        "input_file": str(Path(pcap_file).resolve()),
        "summary": {
            "total_packets_read": len(packets),
            "total_ip_packets": len(records),
            "total_events": len(events),
            "severity_counts": {
                "low": severity_counts.get("low", 0),
                "medium": severity_counts.get("medium", 0),
                "high": severity_counts.get("high", 0),
            },
            "event_type_counts": dict(event_type_counts),
            "top_dns_domains": top_domains,
        },
        "events": events,
        "packets": prepare_packet_output(records),
    }


def save_results(results, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file_handle:
        json.dump(results, file_handle, indent=4)


def main():
    args = parse_arguments()

    try:
        results = analyze_pcap(
            args.pcap_file,
            args.dns_burst_count,
            args.dns_window,
            args.correlation_window,
        )
        save_results(results, args.output)
        print_soc_report(results)
    except FileNotFoundError:
        print(f"[ALERT] File not found: {args.pcap_file}")
        return
    except Exception as error:
        print(f"[ALERT] Failed to analyze PCAP: {error}")
        return

    print(f"[INFO] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
