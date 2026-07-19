# Data Copy To Removable Media

Category: USB

## Description
Data copy risk appears when files, archives, or sensitive material are staged near removable media activity.

## Risk interpretation
Risk is higher when USB connections are paired with downloaded archives, unusual file movement, or multiple removable devices.

## Expected indicators
- data_exfiltration_risk
- data_staging_risk
- multiple_usb_connections

## Example scenarios
- Several USB drives are connected in a short period.
- A USB connection is followed by archive download activity.
- A removable drive appears during an unusual file staging window.
