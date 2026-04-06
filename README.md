# PCAP Analyzer

Small Python project for practicing PCAP analysis and finding simple suspicious activity.

## What the script does

- reads packets from a PCAP file
- extracts basic info:
  - source IP
  - destination IP
  - source port
  - destination port
  - protocol
- creates simple SOC-like events
- saves results to JSON
- prints console messages like `[INFO]`, `[WARNING]`, and `[ALERT]`

## Detection ideas

### DNS

- count how often domains are requested
- check if one domain is requested many times in a short time window
- do a simple periodicity check for repeated DNS requests

### HTTP

- detect HTTP requests that use an IP address instead of a domain name

### Ports

- flag connections that use uncommon ports

### Correlation

- check if a host resolves a domain in DNS
- then see if the same host connects to the resolved IP shortly after

This logic is intentionally simple. It is not a real SOC product, but it is good for practice.

## Install

```powershell
py -m pip install -r requirements.txt
```

## Run

```powershell
py pcap_analyzer.py sample.pcap -o results.json
```

Optional settings:

```powershell
py pcap_analyzer.py sample.pcap -o results.json --dns-burst-count 5 --dns-window 10 --correlation-window 5
```

## JSON output

The output file contains:

- `summary`
- `events`
- `packets`

Each event includes fields like:

- `src_ip`
- `dst_ip`
- `port`
- `protocol`
- `event_type`
- `severity`
- `reason`

Severity values:

- `low`
- `medium`
- `high`

Example event types:

- `dns_burst`
- `dns_periodic`
- `http_ip_destination`
- `uncommon_port`
- `dns_ip_correlation`

## Notes

- the rules are simple on purpose
- false positives are normal
- comments in the code are short and practical
- the goal is to understand traffic analysis, not build something advanced
