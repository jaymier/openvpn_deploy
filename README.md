@[TOC](企业部署远程办公环境OPENVPN)

# 一、服务端安装配置(Linux)


 1. 安装openvpn
	`[root@slave1 ~]# yum install -y epel-release`
	`[root@slave1 ~]# yum install  -y install openvpn easy-rsa net-tools bridge-utils`
	```bash
   	[root@slave1 ~]# yum install -y epel-release
   	......
   	Complete!
   	[root@slave1 ~]# yum install  -y install openvpn easy-rsa net-tools bridge-utils
   	......
   	Complete!
	```
 2. 创建PKI证书和CA证书
 	`！注意: 创建CA证书时输入的密码，后续会用上`
 	`[root@slave1 ]# cd /usr/share/easy-rsa/3`
 	`[root@slave1 3]# ./easyrsa init-pki `
 	`[root@slave1 3]#./easyrsa build-ca`
   	```bash
   	[root@slave1 openvpn-2.4.8]# cd /usr/share/easy-rsa/3
	[root@slave1 3]# ./easyrsa init-pki 
	init-pki complete; you may now create a CA or requests.
	Your newly created PKI dir is: /usr/share/easy-rsa/3/pki
	
	[root@slave1 3]# ./easyrsa build-ca

	Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017

	Enter New CA Key Passphrase:                # 设定密码，后面签约证书时需要
	Re-Enter New CA Key Passphrase:             # 确认密码
	Generating RSA private key, 2048 bit long modulus
	....+++
	......+++
	e is 65537 (0x10001)
	You are about to be asked to enter information that will be incorporated
	into your certificate request.
	What you are about to enter is what is called a Distinguished Name or a DN.
	There are quite a few fields but you can leave some blank
	For some fields there will be a default value,
	If you enter '.', the field will be left blank.
	-----
	Common Name (eg: your user, host, or server name) [Easy-RSA CA]:ZCREATE_VPN # 自定义名称

	CA creation complete and you may now import and sign cert requests.
	Your new CA certificate file for publishing is at:
	/usr/share/easy-rsa/3/pki/ca.crt
   	```
 3. 创建服务器证书和客户端证书
 	`[root@slave1 3]# ./easyrsa build-server-full server1 nopass`
 	`[root@slave1 3]# ./easyrsa build-client-full client1 nopass`
 	```bash
 	[root@slave1 3]# ./easyrsa build-server-full server1 nopass

	Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017
	Generating a 2048 bit RSA private key
	.+++
	.......................+++
	writing new private key to '/usr/share/easy-rsa/3/pki/private/server1.key.jYEjOIedC6'
	-----
	Using configuration from /usr/share/easy-rsa/3/pki/safessl-easyrsa.cnf
	Enter pass phrase for /usr/share/easy-rsa/3/pki/private/ca.key:  #输入创建CA证书时的密码
	Check that the request matches the signature
	Signature ok
	The Subject’s Distinguished Name is as follows
	commonName            :ASN.1 12:'server1'    #服务器证书名称
	Certificate is to be certified until Jan 20 17:06:08 2023 GMT (1080 days)

	Write out database with 1 new entries
	Data Base Updated
	
	[root@slave1 3]# ./easyrsa build-client-full client1 nopass

	Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017
	Generating a 2048 bit RSA private key
	................................................+++
	................................................................+++
	writing new private key to '/usr/share/easy-rsa/3/pki/private/client1.key.LB0gwbDPAA'
	-----
	Using configuration from /usr/share/easy-rsa/3/pki/safessl-easyrsa.cnf
	Enter pass phrase for /usr/share/easy-rsa/3/pki/private/ca.key: #输入创建CA证书时的密码
	Check that the request matches the signature
	Signature ok
	The Subject’s Distinguished Name is as follows
	commonName            :ASN.1 12:'client1'   #客户端证书名称
	Certificate is to be certified until Jan 20 17:19:56 2023 GMT (1080 days)
	
	Write out database with 1 new entries
	Data Base Updated
 	```
 4. 生成创建Diffie-Hellman，确保key穿越不安全网络的命令; 创建TLS-Auth Key
 	`[root@slave1 3]# ./easyrsa gen-dh`
 	`[root@slave1 3]# openvpn --genkey --secret ./pki/ta.key `
 	```bash
 	[root@slave1 3]# ./easyrsa gen-dh

	Using SSL: openssl OpenSSL 1.0.2k-fips  26 Jan 2017
	Generating DH parameters, 2048 bit long safe prime, generator 2
	This is going to take a long time
	....................................................................................................................................................................................................................................................................................................................................................................+.................+........................................+....................................................................+............................................................................................................................+...........................................................................+........................................................................................................................................................................................................................................................................................................................+......................+..................................................................................+...................................................................................+.......................+..........+................................................................+............................+...........+....................................................................................................................................................................................................................++*++*
	
	DH parameters of size 2048 created at /usr/share/easy-rsa/3/pki/dh.pem
	
	[root@slave1 3]# openvpn --genkey --secret ./pki/ta.key 
 	```
 	
 5. 配置OpenVPN Server
        将证书秘钥拷贝至/etc/openvpn/server/的issued与private中
 	`[root@slave1 3]# cp -pR /usr/share/easy-rsa/3/pki/{issued,private,ca.crt,dh.pem,ta.key} /etc/openvpn/server/  `
 	拷贝配置文件模板并编辑
	`[root@slave1 3]# cp /usr/share/doc/openvpn-2.4.8/sample/sample-config-files/server.conf /etc/openvpn/server/`
	`[root@slave1 3]# vim /etc/openvpn/server/server.conf`
	```bash
	[root@slave1 3]# cp -pR /usr/share/easy-rsa/3/pki/{issued,private,ca.crt,dh.pem,ta.key} /etc/openvpn/server/  
	[root@slave1 3]# cp /usr/share/doc/openvpn-2.4.8/sample/sample-config-files/server.conf /etc/openvpn/server/
	[root@slave1 3]# vim /etc/openvpn/server/server.conf

	#################################################
	# Sample OpenVPN 2.0 config file for            #
	# multi-client server.                          #
	#                                               #
	# This file is for the server side              #
	# of a many-clients <-> one-server              #
	# OpenVPN configuration.                        #
	#                                               #
	# OpenVPN also supports                         #
	# single-machine <-> single-machine             #
	# configurations (See the Examples page         #
	# on the web site for more info).               #
	#                                               #
	# This config should work on Windows            #
	# or Linux/BSD systems.  Remember on            #
	# Windows to quote pathnames and use            #
	# double backslashes, e.g.:                     #
	# "C:\\Program Files\\OpenVPN\\config\\foo.key" #
	#                                               #
	# Comments are preceded with '#' or ';'         #
	#################################################
	
	# Which local IP address should OpenVPN
	# listen on? (optional)
	# OpenVPN服务器本地地址
	local 10.1.30.100
	
	# Which TCP/UDP port should OpenVPN listen on?
	# If you want to run multiple OpenVPN instances
	# on the same machine, use a different port
	# number for each one.  You will need to
	# open up this port on your firewall.
	# OpenVPN服务器端口
	port 1194
	
	# TCP or UDP server?
	;proto tcp
	proto udp
	
	# "dev tun" will create a routed IP tunnel,
	# "dev tap" will create an ethernet tunnel.
	# Use "dev tap0" if you are ethernet bridging
	# and have precreated a tap0 virtual interface
	# and bridged it with your ethernet interface.
	# If you want to control access policies
	# over the VPN, you must create firewall
	# rules for the the TUN/TAP interface.
	# On non-Windows systems, you can give
	# an explicit unit number, such as tun0.
	# On Windows, use "dev-node" for this.
	# On most systems, the VPN will not function
	# unless you partially or fully disable
	# the firewall for the TUN/TAP interface.
	# 申明使用的设备可选tap基于桥接模式和tun基于路由模式，tap是二层设备，支持链路层协议。
	;dev tap
	dev tun
	
	# Windows needs the TAP-Win32 adapter name
	# from the Network Connections panel if you
	# have more than one.  On XP SP2 or higher,
	# you may need to selectively disable the
	# Windows firewall for the TAP adapter.
	# Non-Windows systems usually don't need this.
	;dev-node MyTap
	
	# SSL/TLS root certificate (ca), certificate
	# (cert), and private key (key).  Each client
	# and the server must have their own cert and
	# key file.  The server and all clients will
	# use the same ca file.
	#
	# See the "easy-rsa" directory for a series
	# of scripts for generating RSA certificates
	# and private keys.  Remember to use
	# a unique Common Name for the server
	# Any X509 key management system can be used.
	# OpenVPN can also use a PKCS #12 formatted key file
	# (see "pkcs12" directive in man page).
	# ca证书，client1的证书和密钥
	ca ca.crt
	cert issued/server1.crt
	key private/server1.key
	# cert server.crt
	# key server.key  # This file should be kept secret
	
	# Diffie hellman parameters.
	# Generate your own with:
	#   openssl dhparam -out dh2048.pem 2048
	;dh dh2048.pem
	dh dh.pem
	
	# Network topology
	# Should be subnet (addressing via IP)
	# unless Windows clients v2.0.9 and lower have to
	# be supported (then net30, i.e. a /30 per client)
	# Defaults to net30 (not recommended)
	;topology subnet
	
	# Configure server mode and supply a VPN subnet
	# for OpenVPN to draw client addresses from.
	# The server will take 10.8.0.1 for itself,
	# the rest will be made available to clients.
	# Each client will be able to reach the server
	# on 10.8.0.1. Comment this line out if you are
	# ethernet bridging. See the man page for more info.
	# 指定OpenVPN子网地址（自己根据规划分配）
	server 10.8.0.0 255.255.255.0
	
	# Maintain a record of client <-> virtual IP address
	# associations in this file.  If OpenVPN goes down or
	# is restarted, reconnecting clients can be assigned
	# the same virtual IP address from the pool that was
	# previously assigned.
	ifconfig-pool-persist ipp.txt
	
	# Configure server mode for ethernet bridging.
	# You must first use your OS's bridging capability
	# to bridge the TAP interface with the ethernet
	# NIC interface.  Then you must manually set the
	# IP/netmask on the bridge interface, here we
	# assume 10.8.0.4/255.255.255.0.  Finally we
	# must set aside an IP range in this subnet
	# (start=10.8.0.50 end=10.8.0.100) to allocate
	# to connecting clients.  Leave this line commented
	# out unless you are ethernet bridging.
	;server-bridge 10.8.0.4 255.255.255.0 10.8.0.50 10.8.0.100
	
	# Configure server mode for ethernet bridging
	# using a DHCP-proxy, where clients talk
	# to the OpenVPN server-side DHCP server
	# to receive their IP address allocation
	# and DNS server addresses.  You must first use
	# your OS's bridging capability to bridge the TAP
	# interface with the ethernet NIC interface.
	# Note: this mode only works on clients (such as
	# Windows), where the client-side TAP adapter is
	# bound to a DHCP client.
	;server-bridge
	
	# Push routes to the client to allow it
	# to reach other private subnets behind
	# the server.  Remember that these
	# private subnets will also need
	# to know to route the OpenVPN client
	# address pool (10.8.0.0/255.255.255.0)
	# back to the OpenVPN server.
	# 自定义向客户端推送路由，需注释push "redirect-gateway def1 bypass-dhcp"
	push "route 10.1.0.0 255.255.0.0"
	# To assign specific IP addresses to specific
	# clients or if a connecting client has a private
	# subnet behind it that should also have VPN access,
	# use the subdirectory "ccd" for client-specific
	# configuration files (see man page for more info).
	
	# EXAMPLE: Suppose the client
	# having the certificate common name "Thelonious"
	# also has a small subnet behind his connecting
	# machine, such as 192.168.40.128/255.255.255.248.
	# First, uncomment out these lines:
	;client-config-dir ccd
	;route 192.168.40.128 255.255.255.248
	# Then create a file ccd/Thelonious with this line:
	#   iroute 192.168.40.128 255.255.255.248
	# This will allow Thelonious' private subnet to
	# access the VPN.  This example will only work
	# if you are routing, not bridging, i.e. you are
	# using "dev tun" and "server" directives.
	
	# EXAMPLE: Suppose you want to give
	# Thelonious a fixed VPN IP address of 10.9.0.1.
	# First uncomment out these lines:
	;client-config-dir ccd
	;route 10.9.0.0 255.255.255.252
	# Then add this line to ccd/Thelonious:
	#   ifconfig-push 10.9.0.1 10.9.0.2
	
	# Suppose that you want to enable different
	# firewall access policies for different groups
	# of clients.  There are two methods:
	# (1) Run multiple OpenVPN daemons, one for each
	#     group, and firewall the TUN/TAP interface
	#     for each group/daemon appropriately.
	# (2) (Advanced) Create a script to dynamically
	#     modify the firewall in response to access
	#     from different clients.  See man
	#     page for more info on learn-address script.
	;learn-address ./script
	
	# If enabled, this directive will configure
	# all clients to redirect their default
	# network gateway through the VPN, causing
	# all IP traffic such as web browsing and
	# and DNS lookups to go through the VPN
	# (The OpenVPN server machine may need to NAT
	# or bridge the TUN/TAP interface to the internet
	# in order for this to work properly).
	# 向客户端push网关,自定义push "route 后需注释此行
	;push "redirect-gateway def1 bypass-dhcp"
	
	# Certain Windows-specific network settings
	# can be pushed to clients, such as DNS
	# or WINS server addresses.  CAVEAT:
	# http://openvpn.net/faq.html#dhcpcaveats
	# The addresses below refer to the public
	# DNS servers provided by opendns.com.
	# 向客户端push DNS
	push "dhcp-option DNS 114.114.114.114"
	
	# Uncomment this directive to allow different
	# clients to be able to "see" each other.
	# By default, clients will only see the server.
	# To force clients to only see the server, you
	# will also need to appropriately firewall the
	# server's TUN/TAP interface.
	# 让客户端彼此可以互相访问
	client-to-client
	
	# Uncomment this directive if multiple clients
	# might connect with the same certificate/key
	# files or common names.  This is recommended
	# only for testing purposes.  For production use,
	# each client should have its own certificate/key
	# pair.
	#
	# IF YOU HAVE NOT GENERATED INDIVIDUAL
	# CERTIFICATE/KEY PAIRS FOR EACH CLIENT,
	# EACH HAVING ITS OWN UNIQUE "COMMON NAME",
	# UNCOMMENT THIS LINE OUT.
	# 定义openvpn一个证书在同一时刻是否允许多个客户端接入，默认没有启用
	duplicate-cn
	
	# The keepalive directive causes ping-like
	# messages to be sent back and forth over
	# the link so that each side knows when
	# the other side has gone down.
	# Ping every 10 seconds, assume that remote
	# peer is down if no ping received during
	# a 120 second time period.
	# 心跳检测
	keepalive 10 120
	
	# For extra security beyond that provided
	# by SSL/TLS, create an "HMAC firewall"
	# to help block DoS attacks and UDP port flooding.
	#
	# Generate with:
	#   openvpn --genkey --secret ta.key
	#
	# The server and each client must have
	# a copy of this key.
	# The second parameter should be '0'
	# on the server and '1' on the clients.
	# 此处客户端配置文件中该参数需要改为 1
	key-direction  0
	tls-auth ta.key 0 # This file is secret
	
	# Select a cryptographic cipher.
	# This config item must be copied to
	# the client config file as well.
	# Note that v2.4 client/server will automatically
	# negotiate AES-256-GCM in TLS mode.
	# See also the ncp-cipher option in the manpage
	cipher AES-256-CBC
	
	# Enable compression on the VPN link and push the
	# option to the client (v2.4+ only, for earlier
	# versions see below)
	;compress lz4-v2
	# For compression compatible with older clients use comp-lzo
	# If you enable it here, you must also
	# enable it in the client config file.
	comp-lzo
	
	# The maximum number of concurrently connected
	# clients we want to allow.
	# 并发连接最大数量，非必须，默认注释
	max-clients 100
	
	# It's a good idea to reduce the OpenVPN
	# daemon's privileges after initialization.
	#
	# You can uncomment this out on
	# non-Windows systems.
	;user nobody
	;group nobody
	
	# The persist options will try to avoid
	# accessing certain resources on restart
	# that may no longer be accessible because
	# of the privilege downgrade.
	persist-key
	persist-tun
	
	# Output a short status file showing
	# current connections, truncated
	# and rewritten every minute.
	# 状态文件
	status openvpn-status.log
	
	# By default, log messages will go to the syslog (or
	# on Windows, if running as a service, they will go to
	# the "\Program Files\OpenVPN\log" directory).
	# Use log or log-append to override this default.
	# "log" will truncate the log file on OpenVPN startup,
	# while "log-append" will append to it.  Use one
	# or the other (but not both).
	# 记录日志，每次重新启动openvpn后删除原有的log信息。也可以自定义log的位置。默认是在/etc/openvpn/目录下
	log         openvpn.log
	log-append  openvpn.log
	
	# Set the appropriate level of log
	# file verbosity.
	#
	# 0 is silent, except for fatal errors
	# 4 is reasonable for general usage
	# 5 and 6 can help to debug connection problems
	# 9 is extremely verbose
	# 日志级别
	verb 3
	
	# Silence repeating messages.  At most 20
	# sequential messages of the same message
	# category will be output to the log.
	;mute 20
	
	# Notify the client that when the server restarts so it
	# can automatically reconnect.
	explicit-exit-notify 1
	```
 6. 启动openvpn-server服务并设置开机自启动
 	`[root@slave1 server]#  systemctl start openvpn-server@server `
 	`[root@slave1 server]# systemctl enable openvpn-server@server`
 	```bash
 	[root@slave1 server]#  systemctl start openvpn-server@server 
	[root@slave1 server]# systemctl enable openvpn-server@server
	Created symlink from /etc/systemd/system/multi-user.target.wants/openvpn-server@server.service to /usr/lib/systemd/system/openvpn-server@.service.
 	```
7. 关闭linux安全子系统，关闭防火墙
	`[root@slave1 ~]# vim /etc/selinux/config`
	修改`SELINUX=disabled`
	关闭防火墙，停止防火墙自启动
	`[root@localhost ~]# systemctl stop firewalld`
	`[root@localhost ~]# systemctl disable firewalld`

 8. 内核参数中开启ipv4 forwarding
 	`[root@slave1 3]# vim /etc/sysctl.d/99-sysctl.conf `
 	追加`net.ipv4.ip_forward = 1`
 	```bash
 	[root@slave1 3]# vim /etc/sysctl.d/99-sysctl.conf 

	# sysctl settings are defined through files in
	# /usr/lib/sysctl.d/, /run/sysctl.d/, and /etc/sysctl.d/.
	#
	# Vendors settings live in /usr/lib/sysctl.d/.
	# To override a whole file, create a new file with the same in
	# /etc/sysctl.d/ and put new settings there. To override
	# only specific settings, add a file with a lexically later
	# name in /etc/sysctl.d/ and put new settings there.
	#
	# For more information, see sysctl.conf(5) and sysctl.d(5).
	net.ipv4.ip_forward = 1
 
9. 增加nat规则，并删除forward中的拒绝规则 
 	增加nat规则：将源地址为vpn网段10.8.0.0/24地址的源地址掩饰为内网地址10.1.30.100
 	`[root@localhost ~]# iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to-source 10.1.30.100`
	查看规则
	`[root@localhost ~]# iptables -nL --line-number `
	根据序号删除FORWARD中为REJECT的规则
	`[root@localhost ~]# iptables -D FORWARD 5`
	`[root@localhost ~]# iptables -D FORWARD 4`
	![在这里插入图片描述](https://img-blog.csdnimg.cn/2020020522453310.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2pheW1pZTEwMjM=,size_16,color_FFFFFF,t_70)
10. 映射内网1194端口至公网
	并在路由器或者核心交换机增加一条10.8.0.0/24出口为10.1.30.100的静态路由
	

# 二、客户端配置(Windows)

 1. 下载客户端并安装
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200205180409428.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2pheW1pZTEwMjM=,size_16,color_FFFFFF,t_70)
 2. 从服务器端下载以下证书秘钥并放入安装目录的config下，
 	默认安装目录为`C:\Program Files\OpenVPN`
 	`/etc/openvpn/server/ca.crt`
 	`/etc/openvpn/server/ta.key`
 	`/etc/openvpn/server/issued/client1.crt`
 	`/etc/openvpn/server/private/client1.key `
 	```bash
 	[root@slave1 server]# cd /etc/openvpn/server
	[root@slave1 server]# ll
	total 32
	-rw-------. 1 root root  1172 Feb  6 01:00 ca.crt
	-rw-------. 1 root root   424 Feb  6 01:25 dh.pem
	-rw-------. 1 root root     0 Feb  6 02:06 ipp.txt
	drwx------. 2 root root    44 Feb  6 01:19 issued
	-rw-------. 1 root root  1128 Feb  6 01:56 openvpn.log
	-rw-------. 1 root root   505 Feb  6 02:07 openvpn-status.log
	drwx------. 2 root root    58 Feb  6 01:19 private
	-rw-r--r--. 1 root root 12182 Feb  6 01:56 server.conf
	-rw-------. 1 root root   636 Feb  6 01:29 ta.key
 	```
 	`如下图所示`![在这里插入图片描述](https://img-blog.csdnimg.cn/20200205183932899.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2pheW1pZTEwMjM=,size_16,color_FFFFFF,t_70)
 3. 在`C:\Program Files\OpenVPN\config`下创建client1.ovpn并编辑
 	```bash
 	
	##############################################
	# Sample client-side OpenVPN 2.0 config file #
	# for connecting to multi-client server.     #
	#                                            #
	# This configuration can be used by multiple #
	# clients, however each client should have   #
	# its own cert and key files.                #
	#                                            #
	# On Windows, you might want to rename this  #
	# file so it has a .ovpn extension           #
	##############################################
	
	# Specify that we are a client and that we
	# will be pulling certain config file directives
	# from the server.
	# 申明指定为客户端
	client
	
	# Use the same setting as you are using on
	# the server.
	# On most systems, the VPN will not function
	# unless you partially or fully disable
	# the firewall for the TUN/TAP interface.
	# 申明使用的设备可选tap基于桥接模式和tun基于路由模式，tap是二层设备，支持链路层协议。
	;dev tap
	dev tun
	
	# Windows needs the TAP-Win32 adapter name
	# from the Network Connections panel
	# if you have more than one.  On XP SP2,
	# you may need to disable the firewall
	# for the TAP adapter.
	;dev-node MyTap
	
	# Are we connecting to a TCP or
	# UDP server?  Use the same setting as
	# on the server.
	# 申明使用的协议，默认使用UDP，如果使用HTTP proxy，必须使用TCP协议,如果采用了tcp,需要注释最后的--explicit-exit-notify     can only be used with --proto udp
	;proto tcp
	proto udp
	
	# The hostname/IP and port of the server.
	# You can have multiple remote entries
	# to load balance between the servers.
	# OpenVPN服务器的外网IP和端口
	remote *.*.*.* 1194
	
	# Choose a random host from the remote
	# list for load-balancing.  Otherwise
	# try hosts in the order specified.
	;remote-random
	
	# Keep trying indefinitely to resolve the
	# host name of the OpenVPN server.  Very useful
	# on machines which are not permanently connected
	# to the internet such as laptops.
	resolv-retry infinite
	
	# Most clients don't need to bind to
	# a specific local port number.
	nobind
	
	# Downgrade privileges after initialization (non-Windows only)
	;user nobody
	;group nobody
	
	# Try to preserve some state across restarts.
	persist-key
	persist-tun
	
	# If you are connecting through an
	# HTTP proxy to reach the actual OpenVPN
	# server, put the proxy server/IP and
	# port number here.  See the man page
	# if your proxy server requires
	# authentication.
	;http-proxy-retry # retry on connection failures
	;http-proxy [proxy server] [proxy port #]
	
	# Wireless networks often produce a lot
	# of duplicate packets.  Set this flag
	# to silence duplicate packet warnings.
	;mute-replay-warnings
	
	# SSL/TLS parms.
	# See the server config file for more
	# description.  It's best to use
	# a separate .crt/.key file pair
	# for each client.  A single ca
	# file can be used for all clients.
	# ca证书，client1的证书和密钥，默认在安装目录的connfig目录下
	ca ca.crt
	cert client1.crt
	key client1.key 
	
	# Verify server certificate by checking that the
	# certicate has the correct key usage set.
	# This is an important precaution to protect against
	# a potential attack discussed here:
	#  http://openvpn.net/howto.html#mitm
	#
	# To use this feature, you will need to generate
	# your server certificates with the keyUsage set to
	#   digitalSignature, keyEncipherment
	# and the extendedKeyUsage to
	#   serverAuth
	# EasyRSA can do this for you.
	remote-cert-tls server
	
	# If a tls-auth key is used on the server
	# then every client must also have the key.
	# 指定ta.key位置，此处服务器为0，客户端为1
	tls-auth ta.key 1
	key-direction  1 
	
	# Select a cryptographic cipher.
	# If the cipher option is used on the server
	# then you must also specify it here.
	# Note that v2.4 client/server will automatically
	# negotiate AES-256-GCM in TLS mode.
	# See also the ncp-cipher option in the manpage
	cipher AES-256-CBC
	
	# Enable compression on the VPN link.
	# Don't enable this unless it is also
	# enabled in the server config file.
	comp-lzo
	
	# Set log file verbosity.
	verb 3
	
	# Silence repeating messages
	;mute 20
 	```
 4. 打开OpenVPN GUI 连接VPN
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200205191441386.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2pheW1pZTEwMjM=,size_16,color_FFFFFF,t_70)
# 三、增加用户名密码验证实现秘钥+密码双重验证
 1. 修改服务器端server.conf
	`[root@localhost ~]# vim /etc/openvpn/server/server.conf`
	追加如下配置
	```bash
	# 用户名密码验证脚本
	auth-user-pass-verify /etc/openvpn/checkpsw.sh via-env
	# 让客户端输入用户名和密码如果正确才允许访问
	username-as-common-name
	script-security 3
	```
 2. 密码验证脚本
	`[root@localhost ~]# vim /etc/openvpn/checkpsw.sh`
	```bash
	[root@localhost ~]# vim /etc/openvpn/checkpsw.sh

	#!/bin/sh
	###########################################################
	# checkpsw.sh (C) 2004 Mathias Sundman <mathias@openvpn.se>
	#
	# This script will authenticate OpenVPN users against
	# a plain text file. The passfile should simply contain
	# one row per user with the username first followed by
	# one or more space(s) or tab(s) and then the password.
	PASSFILE="/etc/openvpn/psw-file"
	LOG_FILE="/var/log/openvpn-password.log"
	TIME_STAMP=`date "+%Y-%m-%d %T"`
	###########################################################
	if [ ! -r "${PASSFILE}" ]; then
	  echo "${TIME_STAMP}: Could not open password file \"${PASSFILE}\" for reading." >> ${LOG_FILE}
	  exit 1
	fi
	CORRECT_PASSWORD=`awk '!/^;/&&!/^#/&&$1=="'${username}'"{print $2;exit}' ${PASSFILE}`
	if [ "${CORRECT_PASSWORD}" = "" ]; then
	  echo "${TIME_STAMP}: User does not exist: username=\"${username}\", password=\"${password}\"." >> ${LOG_FILE}
	  exit 1
	fi
	if [ "${password}" = "${CORRECT_PASSWORD}" ]; then
	  echo "${TIME_STAMP}: Successful authentication: username=\"${username}\"." >> ${LOG_FILE}
	  exit 0
	fi
	echo "${TIME_STAMP}: Incorrect password: username=\"${username}\", password=\"${password}\"." >> ${LOG_FILE}
	exit 1
	```

 3. 创建用户和密码认证文件
 	`[root@localhost ~]# vim /etc/openvpn/psw-file`
 	```bash
 	[root@localhost ~]# vim /etc/openvpn/psw-file
	# 每行一条，用户名密码用空格隔开
	admin password
 	```
 4. 重启openvpn服务端
 	`[root@slave1 server]#  systemctl restart openvpn-server@server `
 	
 5. 客户端.ovpn文件配置增加密码验证框显示
 	配置文件追加如下
	```bash
	# 用户名密码显示框
	auth-user-pass
	```
 6. 用户名密码验证连接
![在这里插入图片描述](https://upload-images.jianshu.io/upload_images/16010551-0b635d20b3de1c70?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
