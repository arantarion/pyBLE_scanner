#!/usr/bin/env python3

from bluepy import btle
from bluepy.btle import Scanner, Peripheral, Characteristic, ScanEntry, UUID
import pprint


class CONNECTABLE_DEVICE:

    def __init__(self, addr, gap, generic_attr, services) -> None:
        self.addr = addr
        self.gap = gap
        self.generic_attr = generic_attr
        self.services = services


class BLE_SCANNER:

    def __init__(self) -> None:
        self.scanner = None
        self.publicdevices = []
        self.scanned_devices = {}

    def scan(self, duration=10):
        try:
            print("scan: starting scan for {}s".format(duration))
            self.scanner = Scanner()
            devices = self.scanner.scan(duration)
            foundDevices = 0
            for dev in devices:
                devname = dev.getValueText(btle.ScanEntry.COMPLETE_LOCAL_NAME)
                if devname is None:
                    devname = dev.getValueText(btle.ScanEntry.SHORT_LOCAL_NAME)

                print(f"scan: Device {dev.addr} [{devname}] ({dev.addrType}), Connect={dev.connectable}, RSSI={dev.rssi} dB")
                
                if dev.addrType == btle.ADDR_TYPE_PUBLIC and dev.connectable:
                    foundDevices = foundDevices + 1
                    self.publicdevices.append(dev)

            print(f"scan: Complete, found {len(devices)} devices, {len(self.publicdevices)} public")

        except Exception as e:
            print("scan: Error, ", e)


    def connectandread(self, addr):
        device_data = {
            "services": [],
            "descriptors": []
        }

        try:
            p = Peripheral()
            p.connect(addr)

            services = p.getServices()
            for serv in services:
                service_data = {
                    "uuid": serv.uuid,
                    "name": UUID(serv.uuid).getCommonName(),
                    "characteristics": []
                }

                characteristics = serv.getCharacteristics()
                for chara in characteristics:
                    char_data = {
                        "uuid": chara.uuid,
                        "name": UUID(chara.uuid).getCommonName(),
                        "handle": chara.getHandle(),
                        "properties": chara.propertiesToString(),
                        "value": chara.read() if chara.supportsRead() else None
                    }
                    service_data["characteristics"].append(char_data)

                device_data["services"].append(service_data)

            descriptors = p.getDescriptors()
            for desc in descriptors:
                desc_data = {
                    "uuid": desc.uuid,
                    "name": UUID(desc.uuid).getCommonName(),
                    "handle": desc.handle
                }
                device_data["descriptors"].append(desc_data)

            self.scanned_devices[addr] = device_data

        except Exception as e:
            print("connectandread: Error,", e)


if __name__ == '__main__':
    _SCAN_DURATION = 5

    scanner1 = BLE_SCANNER()
    scanner1.scan(_SCAN_DURATION)

    for dev in scanner1.publicdevices:
        curr_addr = dev.addr
        scanner1.connectandread(curr_addr)
        pprint.pprint(scanner1.scanned_devices[curr_addr])
    
