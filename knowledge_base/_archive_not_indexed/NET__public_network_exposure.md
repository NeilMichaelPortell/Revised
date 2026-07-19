# Public Network Exposure

Category: NET

## Description
Public network exposure includes risky services, remote access, or weakened firewall controls while an endpoint is on a public network profile.

## Risk interpretation
Exposure is high risk when services such as RDP or SMB are reachable from untrusted networks.

## Expected indicators
- public_network
- rdp_exposure
- network_exposure

## Example scenarios
- A managed endpoint switches to a public profile with RDP exposed.
- Firewall posture weakens on an untrusted network.
- Service changes increase inbound reachability.
