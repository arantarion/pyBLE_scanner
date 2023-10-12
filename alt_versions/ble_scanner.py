#!/usr/bin/env python3

from bluepy import btle
from bluepy.btle import Scanner, Peripheral, Characteristic, ScanEntry, UUID

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
        try:
            p = Peripheral()
            p.connect(addr)

            print("Listing services...")
            services = p.getServices()
            for serv in services:
                print("   -- SERVICE: {} [{}]".format(serv.uuid, UUID(serv.uuid).getCommonName()))
                characteristics = serv.getCharacteristics()
                for chara in characteristics:
                    print("   --   --> CHAR: {}, Handle: {} (0x{:04x}) - {} - [{}]".format(chara.uuid,
                                                                                    chara.getHandle(),
                                                                                    chara.getHandle(),
                                                                                    chara.propertiesToString(),
                                                                                    UUID(chara.uuid).getCommonName()))
            print("Listing descriptors...")
            descriptors = p.getDescriptors()
            for desc in descriptors:
                print("   --  DESCRIPTORS: {}, [{}], Handle: {} (0x{:04x})".format(desc.uuid, 
                                                                                    UUID(desc.uuid).getCommonName(),
                                                                                    desc.handle, desc.handle))
            
            print("Reading characteristics...")
            chars = p.getCharacteristics()
            for c in chars:
                print("  -- READ: {} [{}] (0x{:04x}), {}, Value: {}".format(c.uuid, UUID(c.uuid).getCommonName(),
                                                                c.getHandle(), c.descs, c.read() if c.supportsRead() else ""))


        except Exception as e:
            print("connectandread: Error,", e)


if __name__ == '__main__':
    _SCAN_DURATION = 5

    scanner1 = BLE_SCANNER()
    scanner1.scan(_SCAN_DURATION)
    print(scanner1.publicdevices)

    for dev in scanner1.publicdevices:
        curr_addr = dev.addr
        scanner1.connectandread(curr_addr)

