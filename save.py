from scan import Scan


class Save:
    def __init__(self):
        self.scan_ip = []
        self.scan_ip_no_use = []
        self.scan_mac = []
        self.ip_mac = {}
        self.ip_port = []

    def add(self, scan: Scan):
        for val in scan.scan_ip:
            if val not in self.scan_ip:
                self.scan_ip.append(val)
        for val in scan.scan_mac:
            if val not in self.scan_mac:
                self.scan_mac.append(val)
        for val in scan.scan_ip_no_use:
            if val not in self.scan_ip_no_use:
                self.scan_ip_no_use.append(val)
        for key, val in scan.ip_mac.items():
            if val not in self.ip_mac:
                self.ip_mac[key] = val
        for val in scan.ip_port:
            if val not in self.ip_port:
                self.ip_port.append(val)
