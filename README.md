# pyBLE Scanner

A Python-based BLE (Bluetooth Low Energy) scanner that utilizes the `bluepy` library. This tool is designed to be compatible with Debian and Debian-based systems.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Contributors](#contributors)
- [License](#license)

## Installation
0. Prequesite: `Python 3.7+`

1. Install the `bluepy` library:
   ```bash
   pip install bluepy
   ```

## Usage

Here's a basic example of how to use the BLE Scanner:

```python
from your_ble_scanner_module import BLE_SCANNER  # Replace with your actual module name
from bluepy.btle import BTLEDisconnectError
from time import sleep

BT_SCAN_TIME = 5  # Define your desired scan time

scanner1 = BLE_SCANNER()

try:
    scanner1.scan(BT_SCAN_TIME)
except BTLEDisconnectError:
    try:
        log("[*] First scanning attempt failed. Trying again after 0.2 seconds...")
        sleep(0.2)
        scanner1.scan(BT_SCAN_TIME)
    except:
        log_error(f"[-] An error occurred while scanning devices")
        pass

for addr, device in scanner1.scanned_devices.items():
    if device.connectable:
        try:
            log(f"[*] Connecting to {device.address} ({device.name if hasattr(device, 'name') else 'Unknown'})...")
            scanner1.connectandread(addr)
        except:
            continue

scanner1.save_to_json("ble_data_3.json")
```

## Info

This code is part of my master's thesis at FernUniversität in Hagen

## License

This project is licensed under the the MIT license (MIT) - see the [LICENSE.md](LICENSE.md) file for details.

