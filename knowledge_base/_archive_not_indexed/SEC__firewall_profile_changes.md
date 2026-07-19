# Firewall Profile Changes

Category: SEC

## Description
Firewall profile changes include weakening endpoint firewall controls, especially when the endpoint is on a public network profile.

## Risk interpretation
Risk is high when firewall changes increase inbound exposure or happen outside approved policy management.

## Expected indicators
- firewall_change
- public_network
- network_exposure

## Example scenarios
- Firewall rules are changed with `netsh.exe`.
- A laptop switches to a public network profile with weaker controls.
- Inbound services become reachable after a local firewall change.
