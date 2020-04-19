# IP_Cheat
毕业设计-IP欺骗

该设计使用框架有scapy,kamene,pyqt5

主界面如下

![Mainwindow](https://github.com/lixiaobei/IP_Cheat/tree/master/example_photo/MainWindow.png)

主要使用方法：

    先选择发包网卡的IP

    ![chose_send](https://github.com/lixiaobei/IP_Cheat/tree/master/example_photo/chose_send_card.png)

    输入扫描的IP：192.168.1.1，192.168.1.1/24

    ![input_scan_ip](https://github.com/lixiaobei/IP_Cheat/tree/master/example_photo/input_scan_ip.png)

    选择网关：即将数据包交给网关，由网关转发数据包（仅有ICMP实现——主要实现扫描不是本网段的主机）

    ![chose_gw](https://github.com/lixiaobei/IP_Cheat/tree/master/example_photo/chose_gw.png)

    选择欺骗的主机，实现ARP欺骗，该欺骗主机列表需要先进行主机扫描

    ![arp_cheat](https://github.com/lixiaobei/IP_Cheat/tree/master/example_photo/start_arp_asproof.png)

    输入攻击主机，进行攻击方式（由于python全局锁的关系，scapy发包速率只有每秒3000个数据包，该功能仅有观看作用）

    ![chose_flood](https://github.com/lixiaobei/IP_Cheat/tree/master/example_photo/flood_attack.png)

    进行IP欺骗，选择信任的IP，选择服务器的IP，输入服务器开启的端口，输入要访问的路径，即以信任IP的IP与服务器IP建立TCP连接，并发送Get请求

    ![ip_cheat](https://github.com/lixiaobei/IP_Cheat/tree/master/example_photo/start_ip_cheat.png)
