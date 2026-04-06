# PCAP Analyzer

Small learning project for analyzing PCAP files and marking simple suspicious traffic.

## What it does

- reads packets from a PCAP file
- extracts basic network data:
  - source IP
  - destination IP
  - source port
  - destination port
  - protocol
- applies a few simple detection rules
- saves the result to JSON

## Detection rules

1. DNS
   - count how often each requested domain appears
   - if a domain is requested many times, mark it as suspicious
   - if it appears much more than the threshold, mark it as highly suspicious

2. HTTP
   - look for HTTP requests where an IP address is used instead of a domain name
   - mark those requests as suspicious

3. Ports
   - look for traffic that uses ports outside a small list of common service ports
   - mark those connections as suspicious

## Install

```powershell
py -m pip install -r requirements.txt
```

## Run

```powershell
py pcap_analyzer.py sample.pcap -o results.json
```

Optional DNS threshold:

```powershell
py pcap_analyzer.py sample.pcap -o results.json --dns-threshold 10
```

## Output

The JSON file contains:

- `summary` with packet counts and top DNS domains
- `findings` with suspicious or highly suspicious packets
- `packets` with all parsed IP packets

Each packet record includes fields like:

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `port`
- `protocol`
- `classification`
- `reason`

## Notes

This project uses very simple rules, so false positives are normal. That is fine for a practice project because the goal is to understand the analysis process, not to build a real SOC product.
