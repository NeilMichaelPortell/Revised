# Suspicious External Connections

Category: NET

## Description
Suspicious external connections include repeated outbound connections to unknown hosts, unusual DNS patterns, or traffic following a new download.

## Risk interpretation
Risk is high or critical when outbound behavior suggests command and control, tunneling, or data exfiltration.

## Expected indicators
- unknown_outbound_connections
- dns_tunneling
- network_exfiltration_risk

## Example scenarios
- A downloaded binary repeatedly contacts unknown hosts.
- DNS queries show tunneling-like patterns.
- PowerShell drives unusual outbound traffic.
