# Routine User Activity

Category: NORMAL

## Description
Routine activity includes expected logins, document editing, browser use, and approved business workflows on a managed endpoint.

## Risk interpretation
Normal behavior should usually be classified as `normal` with `low` risk unless it is combined with unusual configuration, process, or access signals.

## Expected indicators
- successful_login
- trusted_network
- no_sensitive_changes

## Example scenarios
- A user logs in during business hours and edits documents.
- A managed endpoint downloads an approved update.
- One failed login occurs during a helpdesk-supported password reset.
