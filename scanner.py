import argparse
import json
import logging
from threading import Thread
from time import sleep
from ble_appearance_dict import BLE_APPEARANCE
from bluepy import btle
from bluepy.btle import Peripheral, UUID, Scanner, DefaultDelegate, BTLEDisconnectError

logging.basicConfig(format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)

BT_INTERFACE_INDEX = 0
BT_SCAN_TIME = 2
CONNECTION_TIMOUT = 5
BLE_PERMISSIONS = ["WRITE NO RESPONSE", "SIGNED WRITE COMMAND", "QUEUED WRITE", "BROADCAST", "READ", "WRITE", "NOTIFY",
                   "INDICATE", "WRITABLE AUXILIARIES"]
connection_error = False


class BLEDescriptor:
    """
    Represents a Bluetooth Low Energy (BLE) Descriptor.
    """
    def __init__(self, uuid: str, handle: int) -> None:
        """
        Initialize a BLEDescriptor object.

        :param uuid: UUID of the descriptor.
        :type uuid: str
        :param handle: Handle value for the descriptor.
        :type handle: int
        """
        self.uuid = str(uuid)
        self.name = UUID(uuid).getCommonName()
        self.value_handle_int = handle
        self.value_handle = "0x{:04x}".format(self.value_handle_int)
        self.declaration_handle = "0x{:04x}".format(self.value_handle_int - 1)

    def __str__(self) -> str:
        """
        Return a string representation of the BLEDescriptor object.

        :return: String representation of the descriptor.
        :rtype: str
        """
        return (f"Descriptor: {self.name} ({self.uuid}) - Handle: {self.value_handle_int} ({self.value_handle} "
                f"[{self.declaration_handle}])")

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLEDescriptor object.

        :return: Formal representation of the descriptor.
        :rtype: str
        """
        return f"<BLEDescriptor(uuid={self.uuid}, handle={self.value_handle})>"

    def to_dict(self) -> dict:
        """
        Convert the BLEDescriptor object to a dictionary.

        :return: Dictionary representation of the descriptor.
        :rtype: dict
        """
        return {
            "uuid": self.uuid,
            "name": self.name,
            "value_handle": self.value_handle,
            "value_handle_int": self.value_handle_int,
            "declaration_handle": self.declaration_handle
        }


class BLECharacteristic:
    """
    Represents a Bluetooth Low Energy (BLE) Characteristic.
    """
    def __init__(self, uuid: str, handle: int, permissions: str, value: bytearray = None,
                 special_service: bool = False) -> None:
        """
        Initialize a BLECharacteristic object.

        :param uuid: UUID of the characteristic.
        :type uuid: str
        :param handle: Handle value for the characteristic.
        :type handle: int
        :param permissions: Permissions string for the characteristic.
        :type permissions: str
        :param value: Optional value for the characteristic.
        :type value: bytearray
        :param special_service: Flag indicating if this is a special service.
        :type special_service: bool
        """
        self.uuid = str(uuid)
        self.name = UUID(uuid).getCommonName()
        self.value_handle_int = handle
        self.value_handle = "0x{:04x}".format(self.value_handle_int)
        self.declaration_handle = "0x{:04x}".format(self.value_handle_int - 1)
        self.permissions = self._parse_permissions(permissions, BLE_PERMISSIONS)

        if special_service:
            try:
                self.value = value.decode()
            except Exception:
                self.value = value
        elif value:
            self.value = ':'.join(format(x, '02x') for x in value) if self.name != "Device Name" else value.decode()
        else:
            self.value = "None"

        self.appearance = ""
        if self.name == "Appearance":
            self.value = (f'{BLE_APPEARANCE.get(int.from_bytes(value, byteorder="little"), ["", ""])[1]} '
                          f'({int.from_bytes(value, byteorder="little")})')

        if self.name == "Peripheral Privacy Flag":
            self.value = "Device Privacy is not in use (00)" if self.value == '00' else "Device Privacy is in use (1)"

        self.descriptors = []

    def _parse_permissions(self, permissions_str: str, all_permissions: list) -> dict:
        """
        Parse permissions from a string representation.

        :param permissions_str: Permissions in string format.
        :type permissions_str: str
        :param all_permissions: str of all possible permissions.
        :type all_permissions: list
        :return: Dictionary of permissions.
        :rtype: dict
        """
        permissions_dict = {}
        for permission in all_permissions:
            if permission in permissions_str:
                permissions_dict[permission] = True
                permissions_str = permissions_str.replace(permission, "").strip()
            else:
                permissions_dict[permission] = False
        return permissions_dict

    def __str__(self) -> str:
        """
        Return a string representation of the BLECharacteristic object.

        :return: String representation of the characteristic.
        :rtype: str
        """
        desc_str = ', '.join([str(d) for d in self.descriptors])
        permissions_str = ', '.join([k for k, v in self.permissions.items() if v])
        return (f"Characteristic: {self.name} ({self.uuid}) - Handle: {self.value_handle_int} - "
                f"Permissions: {permissions_str} - Value: {self.value} - Descriptors: [{desc_str}]")

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLECharacteristic object.

        :return: Formal representation of the characteristic.
        :rtype: str
        """
        return f"<BLECharacteristic(uuid={self.uuid}, handle={self.value_handle_int}, properties={self.permissions})>"

    def to_dict(self) -> dict:
        """
        Convert the BLECharacteristic object to a dictionary.

        :return: Dictionary representation of the characteristic.
        :rtype: dict
        """
        return {
            "uuid": self.uuid,
            "name": self.name,
            "value_handle_int": self.value_handle_int,
            "value_handle": self.value_handle,
            "declaration_handle": self.declaration_handle,
            "permissions": self.permissions,
            "value": self.value,
            "descriptors": [descriptor.to_dict() for descriptor in self.descriptors]
        }

    def add_descriptor(self, descriptor: BLEDescriptor) -> None:
        """
        Add a BLEDescriptor to the characteristic.

        :param descriptor: BLEDescriptor to add.
        :type descriptor: BLEDescriptor
        """
        self.descriptors.append(descriptor)


class BLEService:
    """
    Represents a Bluetooth Low Energy (BLE) Service.
    """
    def __init__(self, uuid: str) -> None:
        """
        Initialize a BLEService object.

        :param uuid: UUID of the service.
        :type uuid: str
        """
        self.uuid = str(uuid)
        self.name = UUID(uuid).getCommonName()
        self.characteristics = []

    def __str__(self) -> str:
        """
        Return a string representation of the BLEService object.

        :return: String representation of the service.
        :rtype: str
        """
        char_str = '\n    '.join([str(c) for c in self.characteristics])
        return f"Service: {self.name} ({self.uuid})\n    {char_str}"

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLEService object.

        :return: Formal representation of the service.
        :rtype: str
        """
        return f"<BLEService(uuid={self.uuid})>"

    def to_dict(self) -> dict:
        """
        Convert the BLEService object to a dictionary.

        :return: Dictionary representation of the service.
        :rtype: dict
        """
        return {
            "uuid": self.uuid,
            "name": self.name,
            "characteristics": [char.to_dict() for char in self.characteristics]
        }

    def add_characteristic(self, characteristic: BLECharacteristic) -> None:
        """
        Add a BLECharacteristic to the service.

        :param characteristic: BLECharacteristic to add.
        :type characteristic: BLECharacteristic
        """
        self.characteristics.append(characteristic)


class BLEDevice:
    """
    Represents a Bluetooth Low Energy (BLE) Device.
    """
    def __init__(self, address: str, addr_type: str, rssi: str) -> None:
        """
        Initialize a BLEDevice object.

        :param address: Address of the BLE device.
        :type address: str
        :param rssi: RSSI value for the device.
        :type rssi: str
        """
        self.address = address
        self.services = []
        self.connectable = False
        self.addr_type = addr_type
        self.rssi = rssi
        self.name = ""

    def __str__(self) -> str:
        """
        Return a string representation of the BLEDevice object.

        :return: String representation of the device.
        :rtype: str
        """
        service_str = '\n  '.join([str(s) for s in self.services])
        return (f"Device Address: {self.address}, Name: {getattr(self, 'name', 'Unknown')} "
                f"({self.connectable}) [{self.rssi}] [Type: {self.addr_type}]\n  {service_str}")

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLEDevice object.

        :return: Formal representation of the device.
        :rtype: str
        """
        return f"<BLEDevice(address={self.address}, name={getattr(self, 'name', 'Unknown')})>"

    def to_dict(self) -> dict:
        """
        Convert the BLEDevice object to a dictionary.

        :return: Dictionary representation of the device.
        :rtype: dict
        """
        return {
            "address": self.address,
            "name": getattr(self, 'name', 'Unknown'),
            "connectable": self.connectable,
            "rssi": self.rssi,
            "services": [service.to_dict() for service in self.services]
        }

    def add_service(self, service: BLEService) -> None:
        """
        Add a BLEService to the device.

        :param service: BLEService to add.
        :type service: BLEService
        """
        self.services.append(service)


class ScanDelegate(DefaultDelegate):
    """
    Delegate class for handling BLE device discovery during scanning. Specified in the BluePy documentation.
    """
    def __init__(self):
        DefaultDelegate.__init__(self)

    def handleDiscovery(self, dev, isNewDev, isNewData):
        """
        Handle the discovery of a new BLE device or new data from an existing device.

        :param dev: The discovered BLE device.
        :param isNewDev: Flag indicating if the device is newly discovered.
        :type isNewDev: bool
        :param isNewData: Flag indicating if new data is received from an existing device.
        :type isNewData: bool
        """
        if isNewDev:
            device_name = dev.getValueText(btle.ScanEntry.COMPLETE_LOCAL_NAME)
            if device_name is None:
                device_name = dev.getValueText(btle.ScanEntry.SHORT_LOCAL_NAME)
            address = dev.addr if dev.addr else ""
            address_type = dev.addrType if dev.addrType else ""
            conn = str(dev.connectable) if str(dev.connectable) else ""
            rssi = dev.rssi if dev.rssi else ""
            device_name = device_name if device_name else ""

            print(f"{address:<20} {device_name:<30} {address_type:<15} {conn:<15} {rssi:<10}")


class NotificationDelegate(DefaultDelegate):
    """
    Delegate class for handling BLE notifications. Specified in the BluePy documentation.
    """
    def __init__(self, params):
        DefaultDelegate.__init__(self)

    def handleNotification(self, cHandle, data):
        """
        Handle BLE notifications.

        :param cHandle: Handle of the characteristic sending the notification.
        :type cHandle: int
        :param data: Data received in the notification.
        :type data: bytes
        """
        logging.info((f"[*] Notification from handle {cHandle:04x}:"
                     f"\n    {data.hex()}"))


class BLEScanner:
    """
    Class for scanning BLE devices.
    """

    def __init__(self) -> None:
        """
        Initialize the BLEScanner object.
        """
        self.scanned_devices = {}
        self.scanner = Scanner(BT_INTERFACE_INDEX).withDelegate(ScanDelegate())
        self.successful_scans = 0

    def __repr__(self) -> str:
        """
        Return a formal string representation of the BLEScanner object.

        :return: Formal representation of the scanner.
        :rtype: str
        """
        return f"<BLE_SCANNER(scanned_devices={self.scanned_devices})>"

    def __str__(self) -> str:
        """
        Return a string representation of the BLEScanner object.

        :return: String representation of the scanner.
        :rtype: str
        """
        output_string = ""
        for _, device in self.scanned_devices.items():
            output_string += device.__str__()
        output_string += "\n"
        return output_string

    def _connect_peripheral(self, peripheral: Peripheral, addr: str, addr_type: str) -> None:
        """
        Connect to a BLE peripheral.

        :param peripheral: Peripheral to connect to.
        :type peripheral: bluepy.btle.Peripheral
        :param addr: Address of the peripheral.
        :type addr: str
        :param addr_type: Address type of the peripheral.
        :type addr_type: str
        """
        global connection_error
        try:
            peripheral.connect(addr, addr_type)
        except Exception:
            connection_error = True

    def scan(self, duration: int = 10) -> None:
        """
        Scan for BLE devices.

        :param duration: Duration of the scan in seconds.
        :type duration: int
        """
        logging.info(f"[*] scanning for {duration} seconds")
        print("")
        print(f"{'Device':<20} {'Name':<30} {'Address Type':<15} {'Connectable':<15} {'RSSI (dB)':<10}")
        print('-' * 100)
        devices = self.scanner.scan(timeout=duration)
        print("")
        logging.info(f"[*] found {len(devices)} BLE devices - "
                    f"{len([dev for dev in devices if dev.connectable])} connectable")
        for device in devices:
            scanned_device = BLEDevice(address=device.addr,
                                       addr_type=device.addrType,
                                       rssi=device.rssi)
            scanned_device.connectable = device.connectable
            device_name = device.getValueText(btle.ScanEntry.COMPLETE_LOCAL_NAME)
            if device_name is None:
                device_name = device.getValueText(btle.ScanEntry.SHORT_LOCAL_NAME)
            if device_name:
                scanned_device.name = device_name
            self.scanned_devices[device.addr] = scanned_device

    def connect_and_read_all(self, addr: str, addr_type: str, with_descriptors: bool = False) -> None:
        """
        Connect to a BLE device and read all its services, characteristics, and descriptors.

        :param addr: Address of the BLE device to connect to.
        :type addr: str
        :param addr_type: Address type for the connection -> either 'public' or 'random'
        :type addr_type: str
        :param with_descriptors: Flag indicating if descriptors should be read.
        :type with_descriptors: bool
        """
        device = self.scanned_devices.get(addr)

        if not device:
            return

        p = Peripheral(iface=BT_INTERFACE_INDEX)
        try:
            # Implementation to enforce the timeout
            thread = Thread(target=self._connect_peripheral,
                            args=[p, device.address, addr_type])
            thread.start()
            thread.join(CONNECTION_TIMOUT)
            if thread.is_alive() or connection_error:
                logging.error(f"[-] The device did not respond in the connection timeout of {CONNECTION_TIMOUT}")
                raise Exception()
            logging.info(f"[*] Connected to {addr}.")

            logging.info(f"[*] reading services of '{addr}'")
            services = p.getServices()
            for serv in services:
                service = BLEService(uuid=serv.uuid)
                device.add_service(service=service)

                logging.info(f"[*] reading characteristics of service '{service.name}' on device '{addr}'")
                characteristics = serv.getCharacteristics()
                for chara in characteristics:
                    char_value = chara.read() if chara.supportsRead() else None
                    is_special_service = (UUID(chara.uuid).getCommonName() != str(chara.uuid)
                                          and not len(UUID(chara.uuid).getCommonName()) == 4)
                    characteristic = BLECharacteristic(uuid=chara.uuid,
                                                       handle=chara.getHandle(),
                                                       permissions=chara.propertiesToString(),
                                                       value=char_value,
                                                       special_service=is_special_service)
                    service.add_characteristic(characteristic=characteristic)

                    if with_descriptors:
                        logging.info(f"[*] reading descriptors of characteristic '{characteristic.name}' of service "
                                    f"'{service.name}' on device '{addr}'")
                        for desc in chara.getDescriptors():
                            descriptor = BLEDescriptor(uuid=desc.uuid,
                                                       handle=desc.handle)
                            characteristic.add_descriptor(descriptor=descriptor)

            logging.info(f"[*] successfully read all data from device {addr}")
            self.successful_scans += 1
            p.disconnect()
            logging.info(f"[*] disconnected from '{addr}'\n")

        except KeyboardInterrupt:
            logging.error(f"[-] KeyboardInterrupt - Skipping this device")

        except Exception as e:
            logging.error(f"[-] connect_and_read_all: Error {e}")
            logging.error(f"[-] disconnecting...")
            p.disconnect()

    def save_to_json(self, filename: str) -> None:
        """
        Save the scanned BLE devices inside a BLEScanner to a JSON file.

        :param filename: Name of the file to save the data to.
        :type filename: str
        """
        logging.info(f"[*] Writing to file {filename}")
        data = {address: device.to_dict() for address, device in self.scanned_devices.items()}
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"[*] File created successfully")


# ---------------------------------------------------------------------------------------------------------------------#

def scan_all_devices_and_read_all_fields(filename: str, with_descriptors: bool = False) -> None:
    """
    Scan for all BLE devices in the vicinity and read all their fields.

    This function will scan for all available BLE devices. If a device is connectable,
    it will attempt to connect to the device and read all its services, characteristics,
    and descriptors (if the `with_descriptors` flag is set to True). After reading all
    the data, it will save the information to a JSON file.

    :param filename: Name of the file to save the scanned data to.
    :type filename: str
    :param with_descriptors: Flag indicating if descriptors should be read. Default is False.
    :type with_descriptors: bool
    """
    # ----------------- SCANNING ALL DEVICES ----------------- #

    logging.info("[*] Starting Script. Initializing Scanner Object")
    scanner1 = BLEScanner()
    try:
        scanner1.scan(duration=BT_SCAN_TIME)
    except BTLEDisconnectError:
        try:
            logging.info("[*] First scanning attempt failed. Trying again after 0.2 seconds...")
            sleep(0.2)
            scanner1.scan(duration=BT_SCAN_TIME)
        except Exception:
            logging.error(f"[-] An error occurred while scanning devices")
            pass

    # ---------------- READING ALL ATTRIBUTES ---------------- #

    for address, device in scanner1.scanned_devices.items():
        if device.connectable:
            try:
                logging.info(f"[*] Connecting to {device.address} ({device.name})...")
                scanner1.connect_and_read_all(addr=address,
                                              addr_type=device.addr_type,
                                              with_descriptors=with_descriptors)
            except Exception:
                continue

    if scanner1.successful_scans > 0:
        scanner1.save_to_json(filename=filename)


def main() -> None:
    """
    Main function to provide CLI for the BLE scanner script.
    """
    parser = argparse.ArgumentParser(description="BLE Scanner: Scan and read all fields from nearby BLE devices.")

    parser.add_argument("-f", "--filename", type=str, default="output.json",
                        help="Name of the file to save the scanned data to. Default is 'output.json'.")

    parser.add_argument("-d", "--descriptors", action="store_true",
                        help="Flag to indicate if descriptors should be read. Default is False.")

    parser.add_argument("-i", "--interface", type=int, default=0,
                        help="Bluetooth interface index to use. Default is 0.")

    parser.add_argument("-t", "--scan-time", type=int, default=5,
                        help="Duration in seconds for the BLE scan. Default is 2 seconds.")

    parser.add_argument("-c", "--connection-timeout", type=int, default=5,
                        help="Timeout in seconds for the BLE connection. Default is 5 seconds.")

    args = parser.parse_args()

    global BT_INTERFACE_INDEX, BT_SCAN_TIME, CONNECTION_TIMOUT
    BT_INTERFACE_INDEX = args.interface
    BT_SCAN_TIME = args.scan_time
    CONNECTION_TIMOUT = args.connection_timeout

    args = parser.parse_args()

    scan_all_devices_and_read_all_fields(filename=args.filename,
                                         with_descriptors=args.descriptors)


if __name__ == "__main__":
    main()

