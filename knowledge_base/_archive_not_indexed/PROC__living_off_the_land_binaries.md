# Living-Off-The-Land Binaries

Category: PROC

## Description
Living-off-the-land binaries are legitimate system tools used in suspicious ways, such as downloading files, launching scripts, or changing system state.

## Risk interpretation
Risk increases when tools such as `certutil.exe`, `reg.exe`, `netsh.exe`, or `schtasks.exe` are used outside expected administration.

## Expected indicators
- certutil_download
- suspicious_process
- file_download

## Example scenarios
- `certutil.exe` downloads an executable from an unknown site.
- `wscript.exe` launches an unsigned downloaded script.
- `reg.exe` modifies a startup key.
