from scapy.layers.l2 import *
from scapy.layers.inet import *
from scapy.all import RandShort, sniff, AsyncSniffer
from scapy.layers.http import *
from config import Config
from save import Save
import threading


class Cheat:
    def __init__(self, config: Config, save: Save, ip_s: str, ip_r: str, port_r: int, save_path: str, visit_path: str):
        self._nw_if = config.adp
        self._ack = 0
        self._seq = 1
        self._ip_mac = save.ip_mac
        self.ip_s = ip_s
        self.ip_r = ip_r
        self._port_s = int(RandShort())
        self.port_r = port_r
        self._threads = []
        self._filter_string = "tcp and src port " + str(self.port_r) + " and src host " + self.ip_r
        self._last_ack = 0
        self._last_seq = 0
        self._mac_r = None
        self._mac_s = None
        self.so = None
        self.res = None
        self.need_get = []
        self.save_path = save_path
        self.visit_path = visit_path

    def init(self):
        self._ack = 0
        self._seq = 1
        self._last_ack = 0
        self._last_seq = 0
        self._mac_s, self._mac_r = self.get_mac(self.ip_s, self.ip_r)

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

    def whole_tcp(self):
        ans, un_an = srp(Ether(src=self._mac_s, dst=self._mac_r) /
                         IP(src=self.ip_s, dst=self.ip_r) /
                         TCP(sport=self._port_s, dport=self.port_r, flags="S", seq=self._seq, window=65535),
                         inter=0.1, iface=self._nw_if, timeout=2, verbose=0)
        # sleep(0.5)
        for s, r in ans:
            self._ack = r[TCP].seq + 1
        self._seq = self._seq + 1
        sendp(Ether(src=self._mac_s, dst=self._mac_r) /
              IP(src=self.ip_s, dst=self.ip_r) /
              TCP(sport=self._port_s, dport=self.port_r, flags="A", ack=self._ack, seq=self._seq, window=65535),
              inter=0.1, iface=self._nw_if, verbose=0)

    def http_request(self, path):
        # load_layer("http")
        self.so.start()
        sendp(Ether(src=self._mac_s, dst=self._mac_r) /
              IP(src=self.ip_s, dst=self.ip_r) /
              TCP(sport=self._port_s, dport=self.port_r, flags="A", ack=self._ack, seq=self._seq, window=65535)
              / HTTP()
              /
              HTTPRequest(
                  Method="GET",
                  Path=path,
                  Http_Version="HTTP/1.1",
                  Host=self.ip_r + ":" + str(self.port_r),
                  Connection="keep-alive",
                  Upgrade_Insecure_Requests="1",
                  Cookie="this is my fake cookie",
                  User_Agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                             "Chrome/77.0.3865.90 Safari/537.36",
                  Accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;"
                         "q=0.8,application/signed-exchange;v=b3",
                  # Accept_Encoding="gzip, deflate",
                  Accept_Language="zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6"
              ),
              inter=0.1, iface=self._nw_if, verbose=0)
        an = sniff(iface=self._nw_if, filter=self._filter_string, count=1)
        self._seq = an[0][TCP].ack
        # TCP数据包54字节
        self._ack = an[0][TCP].seq + len(an[0])-54
        # print(self._seq, self._ack)

    def data_trans(self):
        sendp(Ether(src=self._mac_s, dst=self._mac_r) /
              IP(src=self.ip_s, dst=self.ip_r) /
              TCP(sport=self._port_s, dport=self.port_r, flags="A", ack=self._ack, seq=self._seq, window=65535),
              inter=0.1, iface=self._nw_if, verbose=0)
        an = sniff(iface=self._nw_if, filter=self._filter_string, count=1, timeout=1)
        if an:
            if an[0][TCP].flags == 0x018 or an[0][TCP].flags == 0x010:
                self._ack = an[0][TCP].seq + len(an[0])-54
                self._seq = an[0][TCP].ack
                self.data_trans()
                if an[0].ack > self._last_seq:
                    self._last_ack = an[0][TCP].seq + len(an[0])-54
                    self._last_seq = an[0][TCP].ack
        else:
            if self._ack > self._last_ack:
                self._last_ack = self._ack
                self._last_seq = self._seq

    def four_tcp(self):
        self.res = self.so.stop()
        ans, un_an = srp(Ether(src=self._mac_s, dst=self._mac_r) /
                         IP(src=self.ip_s, dst=self.ip_r) /
                         TCP(sport=self._port_s, dport=self.port_r, flags="AF", ack=self._last_ack, seq=self._last_seq,
                             window=65535),
                         inter=0.1, iface=self._nw_if, verbose=0, retry=3)
        for s, value in ans:
            sendp(Ether(src=self._mac_s, dst=self._mac_r) /
                  IP(src=self.ip_s, dst=self.ip_r) /
                  TCP(sport=self._port_s, dport=self.port_r, flags="A", seq=value[TCP].ack, ack=value[TCP].seq + 1,
                      window=65535),
                  inter=0.1, iface=self._nw_if, verbose=0)

    def _ip_defeat(self, path: str):
        self.log()
        self.whole_tcp()
        self.http_request(path)
        self.data_trans()
        self.four_tcp()
        self.find_ans_packet(path)

    def find_ans_packet(self, path):
        i = -1
        if path == '/':
            f = open(self.save_path+"/index.html", 'wb+')
        else:
            f = open(self.save_path + path, 'wb+')
        for val in self.res:
            # val.show()
            if val.haslayer(Raw):
                if i <= val[TCP].seq:
                    f.write(val[Raw].load)
                    i = val[TCP].seq
        f.close()
        f = None
        if path == '/':
            f = open(self.save_path+"/index.html", 'r+')
        elif not path.endswith('.jpg') \
                and not path.endswith('.png') \
                and not path.endswith('.jpeg') \
                and not path.endswith('gif'):
            f = open(self.save_path + path, 'r+')
        if f:
            s = f.read()
            res = re.findall(r'src=".*?"', s)
            ans = []
            for i in res:
                ans.append(*re.findall(r'".*"', i))
            for i in ans:
                visit_path = "/" + i.strip('\"')
                threading.Thread(target=self._ip_defeat, args=(visit_path,)).start()
            f.close()

    def log(self):
        self.so = AsyncSniffer(iface=self._nw_if, filter=self._filter_string)
        # f.write(str(an[0][Raw].load))

    def ip_defeat(self):
        # path = urllib.parse.quote(path)
        new = threading.Thread(target=self._ip_defeat, args=(self.visit_path,))
        new.start()
