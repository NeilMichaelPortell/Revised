# Severity Calibration

Document ID: GLOBAL_002
Category: GLOBAL
Document type: global severity framework
Version: 1.0

## Purpose

Defines a single severity framework used consistently across all categories.

## Low

Use when activity is routine or authorised; settings are viewed only; there is
no meaningful security-control change; a harmless test artefact is removed; a
command-line tool is used for a basic benign action; or a single isolated
authentication error occurs.

## Medium

Use when one unusual or policy-relevant action occurs; an unknown removable
device is connected without execution; repeated failed logins occur at a
limited level; a process-enumeration or network-information command is used; a
security setting is changed temporarily and restored; or a scanner is opened or
checked but no scan is executed.

## High

Use when a confirmed risky action occurs; a script is executed; an unusual or
encoded command pattern appears; Defender is disabled; a firewall configuration
changes; a network scan is performed; an executable is accessed or executed; or
a scheduled task or other persistence mechanism is created or modified.

## Critical

Use only when multiple severe indicators occur together; for example
persistence creation combined with disabled protection, execution combined with
security-control weakening, or scanning combined with public-network exposure
and authentication anomalies. Do not describe one isolated medium or high signal
as critical without a clear compound justification.

## Interpretation constraints

- Severity must follow the evidence, not the category label.
- A single high-risk signal is high, not critical, unless combined with other
  severe signals.
