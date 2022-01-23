# NMAP Complete Scan
```
# Nmap 7.92 scan initiated Fri Dec 24 01:07:44 2021 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/kioptrix2/192.168.1.102/scans/_full_tcp_nmap.txt -oX /root/vulnHub/kioptrix2/192.168.1.102/scans/xml/_full_tcp_nmap.xml 192.168.1.102
adjust_timeouts2: packet supposedly had rtt of -539313 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -539313 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -362256 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -362256 microseconds.  Ignoring time.
Nmap scan report for 192.168.1.102
Host is up, received arp-response (0.0014s latency).
Scanned at 2021-12-24 01:07:45 +08 for 37s
Not shown: 65528 closed tcp ports (reset)
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 64 OpenSSH 3.9p1 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
| 1024 35 149174282886581624883868648302761292182406879108668063702143177994710569161669502445416601666211201346192352271911333433971833283425439634231257314174441054335295864218587993634534355128377261436615077053235666774641007412196140534221696911370388178873572900977872600139866890316021962605461192127591516843621
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAOWJ2N2BPBPm0HxCi630ZxHtTNMh+uVkeYCkKVNxavZkcJdpfFTOGZp054sj27mVZVtCeNMHhzAUpvRisn/cH4k4plLd1m8HACAVPtcgRrshCzb7wzQikrP+byCVypE0RpkQcDya+ngDMVzrkA+9KQSR/5W6BjldLW60A5oZgyfvAAAAFQC/iRZe4LlaYXwHvYYDpjnoCPY3xQAAAIBKFGl/zr/u1JxCV8a9dIAMIE0rk0jYtwvpDCdBre450ruoLII/hsparzdJs898SMWX1kEzigzUdtobDVT8nWdJAVRHCm8ruy4IQYIdtjYowXD7hxZTy/F0xOsiTRWBYMQPe8lW1oA+xabqlnCO3ppjmBecVlCwEMoeefnwGWAkxwAAAIAKajcioQiMDYW7veV13Yjmag6wyIia9+V9aO8JmgMi3cNr04Vl0FF+n7OIZ5QYvpSKcQgRzwNylEW5juV0Xh96m2g3rqEvDd4kTttCDlOltPgP6q6Z8JI0IGzcIGYBy6UWdIxj9D7F2ccc7fAM2o22+qgFp+FFiLeFDVbRhYz4sg==
|   1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA4j5XFFw9Km2yphjpu1gzDBglGSpMxtR8zOvpH9gUbOMXXbCQeXgOK3rs4cs/j75G54jALm99Ky7tgToNaEuxmQmwnpYk9bntoDu9SkiT/hPZdOwq40yrfWIHzlUNWTpY3okTdf/YNUAdl4NOBOYbf0x/dsAdHHqSWnvZmruFA6M=
80/tcp   open  http     syn-ack ttl 64 Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.0.52 (CentOS)
111/tcp  open  rpcbind  syn-ack ttl 64 2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            617/udp   status
|_  100024  1            620/tcp   status
443/tcp  open  ssl/http syn-ack ttl 64 Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_ssl-date: 2021-12-23T14:58:43+00:00; -2h09m38s from scanner time.
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@localhost.localdomain/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--/emailAddress=root@localhost.localdomain/localityName=SomeCity/organizationalUnitName=SomeOrganizationalUnit
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2009-10-08T00:10:47
| Not valid after:  2010-10-08T00:10:47
| MD5:   01de 29f9 fbfb 2eb2 beaf e624 3157 090f
| SHA-1: 560c 9196 6506 fb0f fb81 66b1 ded3 ac11 2ed4 808a
| -----BEGIN CERTIFICATE-----
| MIIEDDCCA3WgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBuzELMAkGA1UEBhMCLS0x
| EjAQBgNVBAgTCVNvbWVTdGF0ZTERMA8GA1UEBxMIU29tZUNpdHkxGTAXBgNVBAoT
| EFNvbWVPcmdhbml6YXRpb24xHzAdBgNVBAsTFlNvbWVPcmdhbml6YXRpb25hbFVu
| aXQxHjAcBgNVBAMTFWxvY2FsaG9zdC5sb2NhbGRvbWFpbjEpMCcGCSqGSIb3DQEJ
| ARYacm9vdEBsb2NhbGhvc3QubG9jYWxkb21haW4wHhcNMDkxMDA4MDAxMDQ3WhcN
| MTAxMDA4MDAxMDQ3WjCBuzELMAkGA1UEBhMCLS0xEjAQBgNVBAgTCVNvbWVTdGF0
| ZTERMA8GA1UEBxMIU29tZUNpdHkxGTAXBgNVBAoTEFNvbWVPcmdhbml6YXRpb24x
| HzAdBgNVBAsTFlNvbWVPcmdhbml6YXRpb25hbFVuaXQxHjAcBgNVBAMTFWxvY2Fs
| aG9zdC5sb2NhbGRvbWFpbjEpMCcGCSqGSIb3DQEJARYacm9vdEBsb2NhbGhvc3Qu
| bG9jYWxkb21haW4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN4duNVEr4aL
| TUfsjacXKcCaRs1oTxsdNTIxkp7SV2PDD+mBY5shsXt/FMG7Upf4g605+W6ZEhfB
| WpLXonDFaRIxxn4AGSOLg8q20kUt9p2HZufaSLSwfSwJ+CTMwYtN8AU0jhf3r0y8
| jr+jjEU0HT4O4YXcnDRvbIUeHKedPPsTAgMBAAGjggEcMIIBGDAdBgNVHQ4EFgQU
| QAs+OwqZIYsWClQ2ZBav2uPP/mAwgegGA1UdIwSB4DCB3YAUQAs+OwqZIYsWClQ2
| ZBav2uPP/mChgcGkgb4wgbsxCzAJBgNVBAYTAi0tMRIwEAYDVQQIEwlTb21lU3Rh
| dGUxETAPBgNVBAcTCFNvbWVDaXR5MRkwFwYDVQQKExBTb21lT3JnYW5pemF0aW9u
| MR8wHQYDVQQLExZTb21lT3JnYW5pemF0aW9uYWxVbml0MR4wHAYDVQQDExVsb2Nh
| bGhvc3QubG9jYWxkb21haW4xKTAnBgkqhkiG9w0BCQEWGnJvb3RAbG9jYWxob3N0
| LmxvY2FsZG9tYWluggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEA
| Hvq7KPeUTn36Sz/Au95TmC7aSkhIkGVHMRGhWe7KTEflqQffYTqJOS4xsu/FxDRy
| 9IGOapsyILGEx57apuCYJW3tpwMUrpUXu/x9g3LM+VghiH0XxMOfbueVhqWZ+yP8
| LisROr5u+FeGOBBIINAmpWUX2xEdB4p97WYzP03rEQU=
|_-----END CERTIFICATE-----
|_http-server-header: Apache/2.0.52 (CentOS)
620/tcp  open  status   syn-ack ttl 64 1 (RPC #100024)
631/tcp  open  ipp      syn-ack ttl 64 CUPS 1.1
|_http-title: 403 Forbidden
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
3306/tcp open  mysql    syn-ack ttl 64 MySQL (unauthorized)
MAC Address: 00:0C:29:B9:F7:A5 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.9
OS details: Linux 2.6.9, Linux 2.6.9 - 2.6.30
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=12/24%OT=22%CT=1%CU=%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=61
OS:C4AD06%P=x86_64-pc-linux-gnu)SEQ(SP=C5%GCD=1%ISR=C6%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M5B4ST11NW2%O2=M5B4ST11NW2%O3=M5B4NNT11NW2%O4=M5B4ST11NW2%O5=M5B4
OS:ST11NW2%O6=M5B4ST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)
OS:ECN(R=Y%DF=Y%TG=40%W=16D0%O=M5B4NNSNW2%CC=N%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%TG=40%W=16A0%S=O%A=S+%F=AS%O=M5B4ST11N
OS:W2%RD=0%Q=)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%TG=4
OS:0%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=N)IE(R=Y%DFI=N%T
OS:G=40%CD=S)

Uptime guess: 0.002 days (since Fri Dec 24 01:05:30 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=197 (Good luck!)
IP ID Sequence Generation: All zeros

Host script results:
|_clock-skew: -2h09m38s

TRACEROUTE
HOP RTT     ADDRESS
1   1.37 ms 192.168.1.102

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 24 01:08:22 2021 -- 1 IP address (1 host up) scanned in 37.84 seconds

```