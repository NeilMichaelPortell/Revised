# Port Scanning

Category: NET

## Description
Port scanning occurs when an endpoint probes many ports, services, or hosts to identify reachable systems.

## Risk interpretation
Internal scanning from a user endpoint should be treated as risky unless it is tied to an approved security test.

## Expected indicators
- port_scan
- internal_reconnaissance
- network_scanner

## Example scenarios
- `nmap.exe` scans an internal subnet.
- A workstation connects to many hosts over a short time.
- A standard user device enumerates reachable services.
