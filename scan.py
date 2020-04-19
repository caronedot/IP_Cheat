from kamene.layers.inet import *
from kamene.all import *
from scapy.all import RandShort
from config import Config
import threading

class Scan:
    def __init__(self):
        self._iface = None
        self._mac = None
        self._ip = None
        self.scan_ip = []
        self.scan_ip_no_use = []
        self.scan_mac = []
        self.ip_port = []
        self.ip_mac = {}

    def init_port(self):
        self.ip_port = []

    def init_adp(self, config: Config):
        self._iface = config.adp
        self._mac = config.mac
        self._ip = config.ip

    def init_ip_mac(self):
        self.scan_ip = []
        self.scan_ip_no_use = []
        self.scan_mac = []
        self.ip_mac.clear()

    # arp扫描主机
    def _arp_scan(self, ip_input: str):
        self.init_ip_mac()

        # 发送arp广播包
        answer, un_as = srp(
            Ether(src=self._mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(psrc=self._ip, pdst=ip_input),
            inter=0.1, timeout=2, iface=self._iface, verbose=0)
        # print(answer.summary())
        # 检查接收数据包
        for s, r in answer:
            if r[ARP].op == 2:
                self.scan_ip.append(r[ARP].psrc)
                self.scan_mac.append(r[ARP].hwsrc)
                self.ip_mac[r[ARP].psrc] = r[ARP].hwsrc
        # 记录局域网未使用IP
        for value in un_as:
            if value not in self.scan_ip_no_use:
                self.scan_ip_no_use.append(value[ARP].pdst)
        """
        answer, un_as = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_input),
            inter=0.1, timeout=2, iface=self._iface, verbose=0)
        mac_list = []
        # answer.nsummary()
        for s, r in answer:
            if r[ARP].op == 2:
                if r[ARP].psrc not in self.scan_ip:
                    self.scan_ip.append(r[ARP].psrc)
                    self.scan_mac.append(r[ARP].hwsrc)
                mac_list.append([r[ARP].psrc, r[ARP].hwsrc])
        print(mac_list)
        for value in un_as:
            if value not in self.scan_ip_no_use:
                self.scan_ip_no_use.append(value[ARP].pdst)
        """

    # icmp扫描主机
    def _icmp_scan(self, ip_input: str):
        self.init_ip_mac()
        # 发送icmp询问包
        ans, un_an = srp(Ether(src=self._mac, dst="ff:ff:ff:ff:ff:ff") /
                         IP(dst=ip_input, src=self._ip) /
                         ICMP(), inter=0.1, timeout=2, iface=self._iface, verbose=0)
        # 检查接收数据包
        for s, r in ans:
            if r[ICMP].type == 0:
                self.scan_ip.append(r[IP].src)
                self.scan_mac.append(r[Ether].src)
                self.ip_mac[r[IP].src] = r[Ether].src
        # 记录局域网未使用IP
        for value in un_an:
            if value not in self.scan_ip_no_use:
                self.scan_ip_no_use.append(value[IP].dst)

    def _extra_icmp_scan(self, ip_input: str, gw_mac: str):
        self.init_ip_mac()
        # 发送icmp询问包
        ans, un_an = srp(Ether(src=self._mac, dst=gw_mac) /
                         IP(dst=ip_input, src=self._ip) /
                         ICMP(), inter=0.1, timeout=2, iface=self._iface, verbose=0)
        # 检查接收数据包
        for s, r in ans:
            if r[ICMP].type == 0:
                self.scan_ip.append(r[IP].src)
                self.scan_mac.append(r[Ether].src)
                self.ip_mac[r[IP].src] = r[Ether].src
        # 记录局域网未使用IP
        for value in un_an:
            if value not in self.scan_ip_no_use:
                self.scan_ip_no_use.append(value[IP].dst)

    # 输入字符串处理
    def port_handle(self, port_list: str):
        pattern = re.compile(r'\d+')
        result = re.findall(pattern, port_list)
        result_handle = []
        for value in result:
            value = int(value)
            result_handle.append(value)

            # print(value)
        # print(result_handle)
        return result_handle

    # tcp端口扫描
    def _tcp_port(self, ip_input: str, port: str):
        self.init_port()
        if '-' in port:
            port = self.port_handle(port)
            port = tuple(port)
        else:
            port = self.port_handle(port)
        ans, un_an = srp(Ether(src=self._mac, dst="ff:ff:ff:ff:ff:ff") /
                         IP(dst=ip_input) /
                         TCP(sport=RandShort(), dport=port, flags="S"),
                         inter=0.1, timeout=2, iface=self._iface, verbose=0)
        for s, r in ans:
            if r[TCP].flags == 0x012:
                self.ip_port.append(str(r[IP].src) + ':' + str(r[TCP].sport) + ':tcp')

    # udp端口扫描
    def _udp_port(self, ip_input: str, port: str):
        self.init_port()
        if '-' in port:
            port = self.port_handle(port)
            port = tuple(port)
            for i in range(port[0], port[1]+1):
                self.ip_port.append(ip_input + ':' + str(i) + ':udp')
        else:
            port = self.port_handle(port)
            self.ip_port.append(ip_input + ':' + str(port[0]) + ':udp')
        ans, un_an = sr(IP(dst=ip_input) /
                        UDP(sport=RandShort(), dport=port),
                        inter=0.1, timeout=2, iface=self._iface, verbose=0)

        for s, r in ans:
            if r.haslayer(ICMP):
                self.ip_port.pop(self.ip_port.index(ip_input + ':' + str(r["UDP in ICMP"].dport)+':udp'))
            """
            elif r[ICMP].type == 3 and r[ICMP].code in [1, 2, 3, 9, 10, 13]:
                port_no_list.append(r[ICMP].dport)
            """

    def icmp_scan(self, ip_input: str):
        threading.Thread(target=self._icmp_scan, args=ip_input).start()

    def extra_icmp_scan(self, ip_input: str, gw_mac: str):
        threading.Thread(target=self._extra_icmp_scan, args=ip_input).start()

    def arp_scan(self, ip_input: str):
        threading.Thread(target=self._arp_scan, args=ip_input).start()

    def tcp_port(self, ip_input:str, port:str):
        threading.Thread(target=self._tcp_port, args=(ip_input, port)).start()

    def udp_port(self, ip_input: str, port: str):
        threading.Thread(target=self._udp_port, args=(ip_input, port)).start()
