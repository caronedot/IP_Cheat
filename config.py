import psutil
from kamene.route import *
import re


class Config:
    def __init__(self):
        self.ipv4_mac = {}
        self.ipv4_adp = {}
        self.adp = None
        self.mac = None
        self.ip = None
        self.get_net_if_addr()

    # 获取网卡列表
    def get_net_if_addr(self):
        dic = psutil.net_if_addrs()
        # print(dic)
        for adapter in dic:
            s_list = dic[adapter]
            mac = None
            # print(adapter)
            # 虚拟的网卡名称
            # adp_list.append(adapter)
            for s_nic in s_list:
                # print(s_nic)
                if s_nic.family.name in {'AF_LINK', 'AF_PACKET'}:
                    mac = s_nic.address
                elif s_nic.family.name == 'AF_INET':
                    # 获取kamene真正的网卡名称
                    self.ipv4_mac[s_nic.address] = mac
                    self.ipv4_adp[s_nic.address] = conf.route.route(s_nic.address)[0]

    def change_adp(self, network: str):
        """
        pattern = re.compile(r'\d+\.\d+\.\d+\.')
        s = pattern.match(network)
        s = s.group(0)+'1'
        """
        self.ip = network
        self.adp = self.ipv4_adp[network]
        self.mac = self.ipv4_mac[network].replace('-', ':')
        # print(self.adp, self.ip, self.mac)

