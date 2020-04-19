from config import Config
from scan import Scan
from attack import Attack
from cheat import Cheat
from save import Save
import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from IP_Cheat import Ui_MainWindow
import ctypes


class MyWindow(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MyWindow, self).__init__(parent)
        self.setupUi(self)
        # 窗体图标
        self.setWindowIcon(QIcon("ip_cheat.ico"))
        self.config = None
        self.scan = None
        self.attack = None
        self.save = None
        self.cheat = None
        self.init()

    def init(self):
        self.scan = Scan()
        self.config = Config()
        self.save = Save()
        self.attack = Attack()
        for val in self.config.ipv4_adp.keys():
            self.send_card.addItem(val)

    # 选择文件路径
    def chose_filepath(self):
        path = QFileDialog.getExistingDirectory(parent=None)
        self.save_file_path_T.setPlainText(path)

    # 开始ip欺骗
    def start_cheat(self):
        path = self.save_file_path_T.toPlainText()
        f = open(path + "/log.txt", 'a+', encoding='UTF-8')
        adp_ip = self.send_card.currentText()
        self.config.change_adp(adp_ip)
        t_ip = self.trust_ip_C.currentText()
        s_ip = self.server_ip_C.currentText()
        t_port = int(self.cheat_port_T.toPlainText())
        path = self.http_view_T.toPlainText()
        self.cheat = Cheat(self.config, self.save, t_ip, s_ip, t_port)
        self.cheat.ip_defeat(path, f)

    # 开始洪泛攻击
    def start_attack(self):
        adp_ip = self.send_card.currentText()
        attack_ip = self.attack_ip_T.toPlainText()
        attack_port = int(self.flood_port_T.toPlainText())
        stc = self.attack_type_C.currentText()
        self.config.change_adp(adp_ip)
        self.attack.init(self.config, self.save)
        if stc == "SYN洪泛":
            self.attack.syn_flood(attack_ip, attack_port)
        if stc == "UDP洪泛":
            self.attack.udp_flood(attack_ip, attack_port)
        if stc == "ICMP洪泛":
            self.attack.icmp_flood(attack_ip)

    # 开始arp欺骗
    def start_arp_cheat(self):
        adp_ip = self.send_card.currentText()
        first = self.cheat_host_one_C.currentText()
        second = self.cheat_host_two_C.currentText()
        self.config.change_adp(adp_ip)
        self.attack.init(self.config, self.save)
        self.attack.arp_double_attack(first, second)

    # 停止所有攻击
    def stop_attack(self):
        self.attack.stop_all()
        self.attack = Attack()

    def init_scan(self):
        self.config.change_adp(self.send_card.currentText())
        self.scan.init_adp(self.config)

    # 开始扫描
    def start_scan(self):
        scan_ip = self.need_scan_ip_T.toPlainText()
        port = self.need_scan_port_T.toPlainText()
        self.init_scan()
        if self.host_choice.isChecked():
            if self.gwcheck.isChecked():
                stc = self.scan_type_C.currentText()
                gw_mac = self.save.scan_mac[self.save.scan_ip.index(self.gw.currentText())]
                if stc == "ICMP扫描":
                    self.scan.extra_icmp_scan(scan_ip, gw_mac)
                self.save.add(self.scan)
                self.live_host.clear()
                self.cheat_host_one_C.clear()
                self.cheat_host_two_C.clear()
                self.gw.clear()
                self.trust_ip_C.clear()
                self.server_ip_C.clear()
                for val in self.save.scan_ip:
                    self.live_host.addItem(val)
                    self.cheat_host_one_C.addItem(val)
                    self.cheat_host_two_C.addItem(val)
                    self.trust_ip_C.addItem(val)
                    self.server_ip_C.addItem(val)
                    self.gw.addItem(val)
            else:
                stc = self.scan_type_C.currentText()
                if stc == "ARP扫描":
                    self.scan.arp_scan(scan_ip)
                if stc == "ICMP扫描":
                    self.scan.icmp_scan(scan_ip)
                self.save.add(self.scan)
                self.gw.clear()
                self.live_host.clear()
                self.cheat_host_one_C.clear()
                self.cheat_host_two_C.clear()
                self.trust_ip_C.clear()
                self.server_ip_C.clear()
                for val in self.save.scan_ip:
                    self.live_host.addItem(val)
                    self.cheat_host_one_C.addItem(val)
                    self.cheat_host_two_C.addItem(val)
                    self.trust_ip_C.addItem(val)
                    self.server_ip_C.addItem(val)
                    self.gw.addItem(val)
            """
            self.trust_ip_C.addItem("192.168.1.200")
            self.cheat_host_one_C.addItem("192.168.1.200")
            """
        if self.port_choice.isChecked():
            ptr = self.port_type_C.currentText()
            if ptr == "TCP端口":
                self.scan.tcp_port(scan_ip, port)
            if ptr == "UDP端口":
                self.scan.udp_port(scan_ip, port)
            self.save.add(self.scan)
            self.ip_and_open_port.clear()
            for val in self.save.ip_port:
                self.ip_and_open_port.addItem(val)


if __name__ == '__main__':
    # 任务栏图标
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("myappid")
    app = QApplication(sys.argv)
    ui = MyWindow()
    ui.show()
    sys.exit(app.exec_())
