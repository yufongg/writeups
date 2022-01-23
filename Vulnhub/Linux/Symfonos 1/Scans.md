# NMAP Complete Scan
```
# Nmap 7.92 scan initiated Fri Jan 14 00:34:21 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/Symfonos-1/192.168.236.8/scans/_full_tcp_nmap.txt -oX /root/vulnHub/Symfonos-1/192.168.236.8/scans/xml/_full_tcp_nmap.xml 192.168.236.8
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.236.8
Host is up, received arp-response (0.00051s latency).
Scanned at 2022-01-14 00:34:22 +08 for 29s
Not shown: 65530 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab:5b:45:a7:05:47:a5:04:45:ca:6f:18:bd:18:03:c2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEgzdI5IpQcFfjqrj7pPhaxTxIJaS0kXjIektEgJg0+jGfOGDi+uaG/pM0Jg5lrOh4BElQFIGDQmf10JrV5CPk/qcs8zPRtKxOspCVBgaQ6wdxjvXkJyDvxinDQzEsg6+uVY2t3YWgTeSPoUP+QC4WWTS/r1e2O2d66SIPzBYVKOP2+WmGMu9MS4tFY15cBTQVilprTBE5xjaO5ToZk+LkBA6mKey4dQyz2/u1ipJKdNBS7XmmjIpyqANoVPoiij5A2XQbCH/ruFfslpTUTl48XpfsiqTKWufcjVO08ScF46wraj1okRdvn+1ZcBV/I7n3BOrXvw8Jxdo9x2pPXkUF
|   256 a0:5f:40:0a:0a:1f:68:35:3e:f4:54:07:61:9f:c6:4a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD8/lJjmeqerC3bEL6MffHKMdTiYddhU4dOlT6jylLyyl/tEBwDRNfEhOfc7IZxlkpg4vmRwkU25WdqsTu59+WQ=
|   256 bc:31:f5:40:bc:08:58:4b:fb:66:17:ff:84:12:ac:1d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOinjerzzjSIgDxhdUgmP/i6nOtGHQq2ayeO1j1h5d5a
25/tcp  open  smtp        syn-ack ttl 64 Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Issuer: commonName=symfonos
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-06-29T00:29:42
| Not valid after:  2029-06-26T00:29:42
| MD5:   086e c75b c397 34d6 6293 70cd 6a76 c4f2
| SHA-1: e3dc 7293 d59b 3444 d39a 41ef 6fc7 2006 bde4 825f
| -----BEGIN CERTIFICATE-----
| MIICyzCCAbOgAwIBAgIJAJzTHaEY8CzbMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
| BAMMCHN5bWZvbm9zMB4XDTE5MDYyOTAwMjk0MloXDTI5MDYyNjAwMjk0MlowEzER
| MA8GA1UEAwwIc3ltZm9ub3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
| AQDMqUx7kERzGuX2GTokAv1cRHV81loI0yEE357TgkGOQEZUA9jpAkceEpjHGdu1
| PqfMxETG0TJYdajwYAxr01H5fJmLi04OhKHyKk+yKIRpOO0uU1tvIcpSx5A2QJky
| BY+q/82SZLhx/l2xyP2jrc63mz4FSrzav/oPpNT6rxLoPIvJ8z+vnUr3qp5Ea/DH
| WRePqBVoMqjqc9EGtwND1EMGJKlZb2KeDaqdJ02K3fZQmyR0+HyYoKq93+sKk34l
| 23Q7Tzuq07ZJXHheyN3G6V4uGUmJTGPKTMZlOVyeEo6idPjdW8abEq5ier1k8jWy
| IzwTU8GmPe4MR7csKR1omk8bAgMBAAGjIjAgMAkGA1UdEwQCMAAwEwYDVR0RBAww
| CoIIc3ltZm9ub3MwDQYJKoZIhvcNAQELBQADggEBAF3kiDg7BrB5xNV+ibk7GUVc
| 9J5IALe+gtSeCXCsk6TmEU6l2CF6JNQ1PDisZbC2d0jEEjg3roCeZmDRKFC+NdwM
| iKiqROMh3wPMxnHEKgQ2dwGU9UMb4AWdEWzNMtDKVbgf8JgFEuCje0RtGLKJiTVw
| e2DjqLRIYwMitfWJWyi6OjdvTWD3cXReTfrjYCRgYUaoMuGahUh8mmyuFjkKmHOR
| sMVCO/8UdLvQr7T8QO/682shibBd4B4eekc8aQa7xoEMevSlY8WjtJKbuPvUYsay
| slgPCkgga6SRw1X/loPYutfIvK7NQPqcEM8YrWTMokknp7EsJXDl85hRj6GghhE=
|_-----END CERTIFICATE-----
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:6A:94:16 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/14%OT=22%CT=1%CU=%PV=Y%DS=1%DC=D%G=N%M=080027%TM=61E
OS:054AB%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=8
OS:)OPS(O1=M5B4ST11NW6%O2=M5B4ST11NW6%O3=M5B4NNT11NW6%O4=M5B4ST11NW6%O5=M5B
OS:4ST11NW6%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120
OS:)ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%
OS:Q=)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=N)IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 198.047 days (since Tue Jun 29 23:26:34 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Hosts:  symfonos.localdomain, SYMFONOS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 9h59m58s, deviation: 3h27m51s, median: 7h59m58s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46050/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 54676/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 11022/udp): CLEAN (Timeout)
|   Check 4 (port 25141/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   SYMFONOS<00>         Flags: <unique><active>
|   SYMFONOS<03>         Flags: <unique><active>
|   SYMFONOS<20>         Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2022-01-13T18:34:39-06:00
| smb2-time: 
|   date: 2022-01-14T00:34:39
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE
HOP RTT     ADDRESS
1   0.51 ms 192.168.236.8

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan 14 00:34:51 2022 -- 1 IP address (1 host up) scanned in 29.89 seconds

```