# NMAP Complete Scan
```
# Nmap 7.92 scan initiated Sun Jan 23 22:38:50 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/Symfonos-2/192.168.236.7/scans/_full_tcp_nmap.txt -oX /root/vulnHub/Symfonos-2/192.168.236.7/scans/xml/_full_tcp_nmap.xml 192.168.236.7
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.236.7
Host is up, received arp-response (0.00050s latency).
Scanned at 2022-01-23 22:38:51 +08 for 28s
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 64 ProFTPD 1.3.5
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:f8:5f:87:20:e5:8c:fa:68:47:7d:71:62:08:ad:b9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/Cvyjh+QnQHsoZt3FqnW8JazNn1CYvc7uuArLkDPM25xV8l4Jc7Xw9InhmSFKJJD0mXhLALt/9byLeH7CyBEjpKATbSsEIL1iQ7G7ETmuOdZPfZxRnLhmaf1cvUxLapJQ5B3z67VR0PxvjfDk/0ARPAhKu1CuPmZk/y4t2iu8RKHG86j5jzR0KO3o2Aqsb2j+7XOd4IDCSFuoFiP3Eic/Jydtv73pyo+2JxBUvTSLaEtqe1op8sLP8wBFRX4Tvmqz/6zO1/zivBjBph8XMlzuMkMC8la8/XJmPb8U5C/8zfogG+YwycTw6ul7616PIj2ogPP89uyrTX9dM3RuZ9/1
|   256 04:2a:bb:06:56:ea:d1:93:1c:d2:78:0a:00:46:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKXypIGuum1SlMddq/BrUwIZM1sRIgbzdijCa1zYunAAT+uKTwPGaKO7e9RxYu97+ygLgpuRMthojpUlOgOVGOA=
|   256 28:ad:ac:dc:7e:2a:1c:f6:4c:6b:47:f2:d6:22:5b:52 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILluhq57UWA4q/mo/h6CjqWMpMOYB9VjtvBrHc6JsEGk
80/tcp  open  http        syn-ack ttl 64 WebFS httpd 1.21
|_http-server-header: webfs/1.21
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:BB:18:ED (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/23%OT=21%CT=1%CU=%PV=Y%DS=1%DC=D%G=N%M=080027%TM=61E
OS:D6897%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=8
OS:)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B
OS:4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120
OS:)ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%
OS:Q=)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=N)IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.002 days (since Sun Jan 23 22:37:09 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: SYMFONOS2; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 9h59m59s, deviation: 3h27m50s, median: 7h59m59s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 57573/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 46951/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 30418/udp): CLEAN (Timeout)
|   Check 4 (port 19386/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: SYMFONOS2, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   SYMFONOS2<00>        Flags: <unique><active>
|   SYMFONOS2<03>        Flags: <unique><active>
|   SYMFONOS2<20>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-01-23T22:39:08
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos2
|   NetBIOS computer name: SYMFONOS2\x00
|   Domain name: \x00
|   FQDN: symfonos2
|_  System time: 2022-01-23T16:39:08-06:00

TRACEROUTE
HOP RTT     ADDRESS
1   0.50 ms 192.168.236.7

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan 23 22:39:19 2022 -- 1 IP address (1 host up) scanned in 29.66 seconds

```