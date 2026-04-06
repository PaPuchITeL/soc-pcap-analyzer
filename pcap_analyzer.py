import argparse
import ipaddress
import json
from collections import Counter
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, IPv6, Raw, TCP, UDP, rdpcap


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

CLASSIFICATION_ORDER = {
    "normal": 0,
    "suspicious": 1,
    "highly suspicious": 2,
}

# This is only a small educational list, not a full port database.
STANDARD_PORTS = {
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
        description="Analyze a PCAP file and detect simple suspicious patterns."
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
        type=int,
        default=10,
        help="How many times a domain must appear before it is marked as suspicious",
    )
    return parser.parse_args()


def get_ip_layer(packet):
    if packet.haslayer(IP):
        return packet[IP]
    if packet.haslayer(IPv6):
        return packet[IPv6]
    return None


def choose_connection_port(src_port, dst_port):
    if src_port is None or dst_port is None:
        return None

    if src_port in STANDARD_PORTS and dst_port not in STANDARD_PORTS:
        return src_port

    if dst_port in STANDARD_PORTS and src_port not in STANDARD_PORTS:
        return dst_port

    if src_port <= 1024 < dst_port:
        return src_port

    if dst_port <= 1024 < src_port:
        return dst_port

    # If we still cannot tell, prefer the destination port.
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

    if connection_key is not None:
        flow_ports[connection_key] = service_port

    return service_port


def build_packet_record(packet_number, packet, flow_ports):
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

    return {
        "packet_number": packet_number,
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
        "classification": "normal",
        "reason": "No suspicious activity detected",
        "reasons": [],
    }


def add_reason(record, level, message):
    if message not in record["reasons"]:
        record["reasons"].append(message)

    if CLASSIFICATION_ORDER[level] > CLASSIFICATION_ORDER[record["classification"]]:
        record["classification"] = level

    record["reason"] = "; ".join(record["reasons"])


def safe_decode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def extract_dns_queries(packet):
    if not packet.haslayer(DNS):
        return []

    dns_layer = packet[DNS]
    if dns_layer.qr != 0 or dns_layer.qdcount == 0:
        return []

    domains = []
    question = dns_layer.qd

    for _ in range(int(dns_layer.qdcount)):
        if question is None or not isinstance(question, DNSQR):
            break

        domain = safe_decode(question.qname).rstrip(".")
        if domain:
            domains.append(domain)

        next_question = question.payload
        question = next_question if isinstance(next_question, DNSQR) else None

    return domains


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


def analyze_pcap(pcap_file, dns_threshold):
    packets = rdpcap(pcap_file)
    records = []
    dns_hits = []
    dns_counter = Counter()
    flow_ports = {}

    for packet_number, packet in enumerate(packets, start=1):
        record = build_packet_record(packet_number, packet, flow_ports)
        if record is None:
            continue

        records.append(record)
        record_index = len(records) - 1

        if record["port"] is not None and record["port"] not in STANDARD_PORTS:
            add_reason(
                record,
                "suspicious",
                f"Connection uses non-standard port {record['port']}",
            )

        domains = extract_dns_queries(packet)
        for domain in domains:
            dns_counter[domain] += 1
            dns_hits.append((record_index, domain))

        http_info = extract_http_request_info(packet)
        if http_info and uses_ip_in_http_request(http_info):
            add_reason(
                record,
                "suspicious",
                "HTTP request uses an IP address instead of a domain name",
            )

    for record_index, domain in dns_hits:
        count = dns_counter[domain]
        if count < dns_threshold:
            continue

        level = "highly suspicious" if count >= dns_threshold * 2 else "suspicious"
        add_reason(
            records[record_index],
            level,
            f"DNS domain '{domain}' was requested {count} times",
        )

    findings = [record for record in records if record["classification"] != "normal"]
    classification_counts = Counter(record["classification"] for record in records)

    return {
        "input_file": str(Path(pcap_file).resolve()),
        "summary": {
            "total_packets_read": len(packets),
            "total_ip_packets": len(records),
            "suspicious_packets": len(findings),
            "classification_counts": {
                "normal": classification_counts.get("normal", 0),
                "suspicious": classification_counts.get("suspicious", 0),
                "highly_suspicious": classification_counts.get(
                    "highly suspicious", 0
                ),
            },
            "top_dns_domains": [
                {"domain": domain, "count": count}
                for domain, count in dns_counter.most_common(10)
            ],
        },
        "findings": findings,
        "packets": records,
    }


def save_results(results, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file_handle:
        json.dump(results, file_handle, indent=4)


def main():
    args = parse_arguments()

    try:
        results = analyze_pcap(args.pcap_file, args.dns_threshold)
        save_results(results, args.output)
    except FileNotFoundError:
        print(f"File not found: {args.pcap_file}")
        return
    except Exception as error:
        print(f"Failed to analyze PCAP: {error}")
        return

    print(f"Analysis finished. Results saved to: {Path(args.output).resolve()}")


if __name__ == "__main__":
    main()
