import os
import json
import logging
from threading import Thread
from time import sleep
from ble_appearance_dict import BLE_APPEARANCE
from bluepy import btle
from bluepy.btle import Peripheral, UUID, Scanner, DefaultDelegate, BTLEDisconnectError, ADDR_TYPE_PUBLIC

logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)

BT_INTERFACE_INDEX = 0
BT_SCAN_TIME = 2
CONNECTION_TIMOUT = 5 
BLE_PERMISSIONS = ["WRITE NO RESPONSE", "SIGNED WRITE COMMAND", "QUEUED WRITE", "BROADCAST", "READ", "WRITE", "NOTIFY", "INDICATE", "WRITABLE AUXILIARIES"]

cls = lambda: os.system('cls' if os.name=='nt' else 'clear')

def log(msg):
    logging.info(msg)

def log_error(msg):
    logging.error(msg)


class BLEDescriptor:
    def __init__(self, uuid, handle):
        self.uuid = str(uuid)
        self.name = UUID(uuid).getCommonName()
        self.handle = handle
        self.handle_short = "0x{:04x}".format(self.handle)
        self.declaration_handle = "0x{:04x}".format(self.handle-1)

    def __str__(self):
        return f"Descriptor: {self.name} ({self.uuid}) - Handle: {self.handle}"

    def __repr__(self):
        return f"<BLEDescriptor(uuid={self.uuid}, handle={self.handle})>"

    def to_dict(self):
        return {
            "uuid": self.uuid,
            "name": self.name,
            "value_handle": self.handle,
            "value_handle_int": self.handle_short,
            "declaration_handle": self.declaration_handle
        }


class BLECharacteristic:
    def __init__(self, uuid, handle, permissions, descs, value=None, special_service=False):
        self.uuid = str(uuid)
        self.name = UUID(uuid).getCommonName()
        self.handle = handle
        self.handle_short = "0x{:04x}".format(self.handle)
        self.declaration_handle = "0x{:04x}".format(self.handle-1)

        self.permissions = self._parse_permissions(permissions, BLE_PERMISSIONS)

        if special_service:
            try:
                self.value = value.decode()
            except:
                self.value = value
        elif value: 
            self.value = ':'.join(format(x, '02x') for x in value) if self.name != "Device Name" else value.decode()
        else:
            self.value = "None"

        self.appearance = ""
        if self.name == "Appearance":
            self.value = f'{BLE_APPEARANCE.get(int.from_bytes(value, byteorder="little"), ["", ""])[1]} ({int.from_bytes(value, byteorder="little")})'
        
        if self.name == "Peripheral Privacy Flag":
            self.value = "Device Privacy is not in use (00)" if self.value == '00' else "Device Privacy is in use (1)"

        self.descs = descs
        self.descriptors = []

    def _parse_permissions(self, permissions_str, all_permissions):
        permissions_dict = {}
        for perm in all_permissions:
            if perm in permissions_str:
                permissions_dict[perm] = True
                permissions_str = permissions_str.replace(perm, "").strip()
            else:
                permissions_dict[perm] = False
        return permissions_dict

    def __str__(self):
        desc_str = ', '.join([str(d) for d in self.descriptors])
        permissions_str = ', '.join([k for k, v in self.permissions.items() if v])
        return f"Characteristic: {self.name} ({self.uuid}) - Handle: {self.handle} - Permissions: {permissions_str} - Descs: {self.descs} - Value: {self.value} - Descriptors: [{desc_str}]"
        

    def __repr__(self):
        return f"<BLECharacteristic(uuid={self.uuid}, handle={self.handle}, properties={self.permissions})>"

    def to_dict(self):
        return {
            "uuid": self.uuid,
            "name": self.name,
            "value_handle_int": self.handle,
            "value_handle": self.handle_short,
            "declaration_handle": self.declaration_handle,
            "permissions": self.permissions,
            "descs": self.descs,
            "value": self.value,
            "descriptors": [desc.to_dict() for desc in self.descriptors]
        }


    def add_descriptor(self, descriptor):
        self.descriptors.append(descriptor)


class BLEService:
    def __init__(self, uuid1):
        self.uuid = str(uuid1)
        self.name = UUID(uuid1).getCommonName()
        self.characteristics = []

    def __str__(self):
        char_str = '\n    '.join([str(c) for c in self.characteristics])
        return f"Service: {self.name} ({self.uuid})\n    {char_str}"

    def __repr__(self):
        return f"<BLEService(uuid={self.uuid})>"

    def to_dict(self):
        return {
            "uuid": self.uuid,
            "name": self.name,
            "characteristics": [char.to_dict() for char in self.characteristics]
        }

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)


class BLEDevice:
    def __init__(self, address, rssi):
        self.address = address
        self.services = []
        self.connectable = False
        self.rssi = rssi
        self.name = ""

    def __str__(self):
        service_str = '\n  '.join([str(s) for s in self.services])
        return f"Device Address: {self.address}, Name: {getattr(self, 'name', 'Unknown')}\n  {service_str}"

    def __repr__(self):
        return f"<BLEDevice(address={self.address}, name={getattr(self, 'name', 'Unknown')})>"

    def to_dict(self):
        return {
            "address": self.address,
            "name": getattr(self, 'name', 'Unknown'),
            "connectable": self.connectable,
            "rssi": self.rssi,
            "services": [service.to_dict() for service in self.services]
        }

    def add_service(self, service):
        self.services.append(service)


class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if isNewDev:
            devname = dev.getValueText(btle.ScanEntry.COMPLETE_LOCAL_NAME)
            if devname is None:
                devname = dev.getValueText(btle.ScanEntry.SHORT_LOCAL_NAME)
            address = dev.addr if dev.addr else ""
            address_type = dev.addrType if dev.addrType else ""
            conn = str(dev.connectable) if str(dev.connectable) else ""
            rssi = dev.rssi if dev.rssi else ""
            devname = devname if devname else ""

            print(f"{address:<20} {devname:<30} {address_type:<15} {conn:<15} {rssi:<10}")


class NotificationDelegate(DefaultDelegate):
    def __init__(self, params):
        DefaultDelegate.__init__(self)

    def handleNotification(self, cHandle, data):
        print((f"[*] Notification from handle {cHandle:04x}:"
               f"\n    {data.hex()}"))            


class BLE_SCANNER:
    def __init__(self):
        self.scanned_devices = {}
        self.scanner = Scanner(BT_INTERFACE_INDEX).withDelegate(ScanDelegate())


    def __repr__(self) -> str:
        return f"<BLE_SCANNER(scanned_devices={self.scanned_devices})>"
    

    def __str__(self) -> str:
        output_string = ""
        for _, device in scanner1.scanned_devices.items():
            output_string += device.__str__()
        output_string += "\n"
        return output_string
    
    def _connect_peripheral(self, peripheral, addr, addr_type):
        global connection_error
        try:
            peripheral.connect(addr, addr_type)
        except:
            connection_error = True


    def scan(self, duration=10):
        log(f"[*] scanning for {duration} seconds")
        print("")
        print(f"{'Device':<20} {'Name':<30} {'Address Type':<15} {'Connectable':<15} {'RSSI (dB)':<10}")
        print('-' * 100)
        devices = self.scanner.scan(duration)
        print("")
        log(f"[*] found {len(devices)} devices")
        for dev in devices:
            device = BLEDevice(dev.addr, dev.rssi)
            device.connectable = dev.connectable 
            devname = dev.getValueText(btle.ScanEntry.COMPLETE_LOCAL_NAME)
            if devname is None:
                devname = dev.getValueText(btle.ScanEntry.SHORT_LOCAL_NAME)
            if devname:
                device.name = devname
            self.scanned_devices[dev.addr] = device


    def connectandread(self, addr):
        device = self.scanned_devices.get(addr)
        if not device:
            return

        try:
            p = Peripheral(iface=BT_INTERFACE_INDEX)
            
            # Implementation to enforce the timeout
            connection_error = False
            thread = Thread(target=self._connect_peripheral, args=[p, device.address, ADDR_TYPE_PUBLIC])
            thread.start()
            thread.join(CONNECTION_TIMOUT)
            if thread.is_alive() or connection_error:
                raise Exception()
            log(f"[*] Connected to {addr}.")

            log(f"[*] reading services of '{addr}'")
            services = p.getServices()
            for serv in services:
                service = BLEService(serv.uuid)
                device.add_service(service)

                log(f"[*] reading characteristics of service '{service.name}' on device '{addr}'")
                characteristics = serv.getCharacteristics()
                for chara in characteristics:
                    char_value = chara.read() if chara.supportsRead() else None
                    is_special_service = UUID(chara.uuid).getCommonName() != str(chara.uuid) and not len(UUID(chara.uuid).getCommonName()) == 4
                    characteristic = BLECharacteristic(chara.uuid, chara.getHandle(), chara.propertiesToString(), chara.descs, char_value, is_special_service)
                    service.add_characteristic(characteristic)

                    log(f"[*] reading descriptors of characteristic '{characteristic.name}' of service '{service.name}' on device '{addr}'")
                    for desc in chara.getDescriptors():
                        descriptor = BLEDescriptor(desc.uuid, desc.handle)
                        characteristic.add_descriptor(descriptor)
            
            log(f"[*] successfully read all data from device {addr}")
            p.disconnect()
            log(f"[-] disconnected from '{addr}'")

        except Exception as e:
            log_error(f"[-] connectandread: Error {e}")
            log_error(f"[-] disconnecting...")
            p.disconnect()
    

    def save_to_json(self, filename="ble_data.json"):
        log(f"[*] Writing to file {filename}")
        data = {addr: device.to_dict() for addr, device in self.scanned_devices.items()}
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        log(f"[*] File created successfully")


    def get_characteristic(self, peripheral, service_uid, characteristic_uid):
        log(("[*] Searching for service/characteristic:"
            f"\n    {service_uid}\n    {characteristic_uid}"))
        try:
            service = peripheral.getServiceByUUID(service_uid)
            characteristics = service.getCharacteristics(characteristic_uid)
            characteristic = characteristics[0]
            char_value = characteristic.read() if characteristic.supportsRead() else None
            is_special_service = UUID(characteristic.uuid).getCommonName() != str(characteristic.uuid) and not len(UUID(characteristic.uuid).getCommonName()) == 4
            characteristic = BLECharacteristic(characteristic.uuid, characteristic.getHandle(), characteristic.propertiesToString(), characteristic.descs, char_value, is_special_service)
            log("[*] Characteristic found.")
            return characteristic
        except:
            log_error("[-] Service or characteristic not found.")
            return None


    # This is a characteristic element from Bluepy
    def write_data_to_characteristic(self, characteristic, data, withResponse=False):
        try:
            log((f"[*] Writing data to handle 0x{characteristic.getHandle():04x}:"
                f"\n    {data.hex()}"))
            characteristic.write(data, withResponse)
            sleep(0.1)
            return True
        except Exception as ex:
            log_error(f"[-] Error on writing.\n    {ex}")
            return False


    def subscribe_to_characteristic(self, peripheral, service_uid, characteristic_uid):
        characteristic = self.get_characteristic(peripheral, service_uid, characteristic_uid)
        
        if characteristic is None:
            log_error("[-] Error subscribing to characteristic.")
            return False
        
        descriptor = characteristic.getDescriptors()[0]
        
        try:
            log("[*] Trying to subscribe to characteristic.")
            descriptor.write(b'\x01\x00')
        except:
            log_error("[-] Error subscribing to characteristic.")
            return False
        
        peripheral.setDelegate(NotificationDelegate(None))
        log("[*] Subscribed to characteristic.")
        return True



# ---------------------------------------------------------------------------------------------------------------------#


log("[*] Starting Script. Initializing Scanner Object")
scanner1 = BLE_SCANNER()
try:
    scanner1.scan(BT_SCAN_TIME)
except BTLEDisconnectError:
    try:
        log("[*] First scanning attempt failed. Trying again after 0.2 seconds...")
        sleep(0.2)
        scanner1.scan(BT_SCAN_TIME)
    except:
        log_error(f"[-] An error occured while scanning devices")
        pass

for addr, device in scanner1.scanned_devices.items():
    if device.connectable:
        try:
            log(f"[*] Connecting to {device.address} ({device.name if hasattr(device, 'name') else 'Unknown'})...")
            scanner1.connectandread(addr)
        except:
            continue

scanner1.save_to_json("ble_data.json")
