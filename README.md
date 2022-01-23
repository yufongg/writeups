# Writeups
The writeups are exported from Obsidian md, so the format looks kind of bad.

# Machines:

| # | Platform | Machines |
| --- | --- | --- |
| 1 | TryHackMe | bufferOverflowPrep, Brainstorm, brainpan, gatekeeper, dailyBugle, gameZone, internal, overpass2, skynet, theMarket, Alfred, Blue, HackPark, Relevant, Steelmountain |
| 2 | Buffer Overflow Practice | freeFloatFTP, dostackbufferoverflowgood, vulnserver-TRUN |

# Vulnhub TJ Null's List (Not Completed Yet)

  | Box                                                                                                                           | Steps/Hints to Root                                                                                                                                                                                                                                                                                                                                                                           |
  | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | [Symfonos 1 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Symfonos%201/Symfonos%201.md)                                                                                                               | <ol><li>SMB Fileshare Bruteforce</li><li>Wordpress (Plugin Exploit LFI)</li><li>SUID Binary (Path Hijacking)</li></ol>                                                                                                                                                                                                                                                                                                                                                 |
  | [Symfonos 2 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Symfonos%202/Symfonos%202.md)                                                                                                                | <ol><li>SMB + FTP Versin Exploit</li><li>CMS Exploit (RCE)</li><li>Sudo (GTFO Bin)</li></ol>                                                                                                                                                                                                                                                                                                                                                    |
  | [Symfonos 3 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Symfonos%203/Symfonos%203.md)                                                                                                               | <ol><li>Compile exploits to root</li></ol>                                                                                                                                                                                                                                                                                                                                                        |
  | [Symfonos 4 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Symfonos%204/Symfonos%204.md)                                                                                                                | <ol><li>Compile exploits to root</li></ol>                                                                                                                                                                                                                                                                                                                                                     |
  | [Symfonos 5.2 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Symfonos%205.2/Symfonos%205.2.md)                                                                                                              | <ol><li>Compile exploits to root</li></ol>                                                                                                                                                                                                                                                                                                                                                   |
  | [Kioptrix - L1 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/kioptrix%20-%20L1/Kioptrix%20-%20L1.md)          | <ol><li>Compile exploits to root</li></ol>                                                                                                                                                                                                                                                                                                                                                   |
  | [Kioptrix - L2 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/kioptrix%20-%20L2/Kioptrix%20-%20L2.md)          | <ol><li>SQLi Auth Bypass</li><li>Command Injection</li><li>Kernel Exploit</li></ol>                                                                                                                                                                                                                                                                                                           |
  | [Kioptrix - L3 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/kioptrix%20-%20L3/Kioptrix%20-%20L3.md)          | <ol><li>CMS Exploit</li><li>Creds Found in Linux</li><li>Buffer Overflow/Sudo/Kernel Exploit/</li></ol>                                                                                                                                                                                                                                                                                       |
  | [Kioptrix - L4 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/kioptrix%20-%20L4/Kioptrix%20-%20L4.md)          | <ol><li>SQLi Auth Bypass</li><li>Escape Jail Shell</li><li>SQL running as Root</li></ol>                                                                                                                                                                                                                                                                                                      |
  | [Kioptrix - L5 ](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/kioptrix%20-%20L5/Kioptrix%20-%20L5.md)          | <ol><li>CMS Exploit (LFI)</li><li>CMS Exploit (RCE)</li><li>Kernel Exploit</li></ol>                                                                                                                                                                                                                                                                                                          |
  | [DC 6](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/DC6.pdf)                                                   | <ol><li>Wordpress (Plugin)</li><li>Creds Found in Linux</li><li>Sudo</li><li>Sudo</li></ol>                                                                                                                                                                                                                                                                                                   |
  | [DC 9](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/DC9.pdf)                                                   | <ol><li>SQLi Database Enum</li><li>Bruteforce HTTP Form</li><li>LFI</li><li>Port Knocking</li><li>Bruteforce SSH</li><li>Sudo</li></ol>                                                                                                                                                                                                                                                       |
  | [Troll 1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Tr0ll.pdf)                                              | <ol><li>FTP anon</li><li>Wireshark</li><li>Bruteforce SSH</li><li>Cronjob/Kernel Exploit</li></ol>                                                                                                                                                                                                                                                                                            |
  | [Troll 2](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/tr0ll%202.pdf)                                          | <ol><li>FTP w/ Obvious Creds</li><li>Image Forensics</li><li>Bruteforce Zip</li><li>SSH + Jailshell</li><li>32 Bit Buffer Overflow</li> </ol>                                                                                                                                                                                                                                                 |
  | [Troll 3]()                                                                                                                   | <ol><li>FTP w/ Obvious Creds</li><li>Image Forensics</li><li>Bruteforce Zip</li><li>SSH + Jailshell</li><li>32 Bit Buffer Overflow</li> </ol>                                                                                                                                                                                                                                                 |
  | [PwnOSv2](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/pwnOSv2.pdf)                                            | <ol><li>SQLi Insert Webshell/CMS Exploit</li><li>Creds Found in Linux</li></ol>                                                                                                                                                                                                                                                                                                               |
  | [PwnLab](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/pwnlab.pdf)                                              | <ol><li>LFI</li><li>File Upload + Bypass</li><li>SUID Binary (Path Hijacking)</li><li>SUID Binary (Command Injection)</li></ol>                                                                                                                                                                                                                                                               |
  | [SickOS](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/sickOS%201.2.pdf)                                        | <ol><li>HTTP PUT</li><li>Vulnerable Binary</li></ol>                                                                                                                                                                                                                                                                                                                                          |
  | [Temple Of Doom](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/temple-of-DOOM.pdf)                              | <ol><li>Web App Exploit</li><li>Vulnerable Binary</li><li>Sudo (GTFO Bin)</li></ol>                                                                                                                                                                                                                                                                                                           |
  | [Vulnix](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/vulnix.pdf)                                              | <ol><li>SMTP Username Enum</li><li>SSH Bruteforce</li><li>NFS Fileshare</li><li>no_root_squash</li></ol>                                                                                                                                                                                                                                                                                      |
  | [Web Developer](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/webDeveloper.pdf)                                 | <ol><li>Wireshark</li><li>Wordpress (Upload Reverse Shell)</li><li>Creds Found in Linux</li><li>Sudo (GTFO Bin)</li></ol>                                                                                                                                                                                                                                                                     |
  | [Zico2](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/zico2.pdf)                                                | <ol><li>CMS Exploit</li><li>Creds Found in Linux</li><li>Creds Found in Linux</li><li>Sudo (GTFO Bin)</li></ol>                                                                                                                                                                                                                                                                               |
  | [SkyTower](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/SkyTower.pdf)                                          | <ol><li>SQLi Auth Bypass + WAF Bypass</li><li>Proxychains (Open up SSH)</li><li>Creds Found in Linux</li><li>Sudo</li></ol>                                                                                                                                                                                                                                                                   |
  | [Fristileaks](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/fristileaks.pdf)                                    | <ol><li>Hidden Dir (/fristi)</li><li>HTML Hidden Text</li><li>File Upload + Bypass</li><li>Cronjob</li><li>Reverse Engineering Password</li><li>Sudo</li></ol>                                                                                                                                                                                                                                |
  | [LinSecurity](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Lin%20Security.pdf)                                 | <ol><li>NFS Fileshare</li><li>Sudo (GTFO Bin)/SUID Binary (GTFO Bin)/Docker/systemd</li></ol>                                                                                                                                                                                                                                                                                                 |
  | [PinkysPalacev2](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Pinkys%20Palace%20v2.pdf)                        | <ol><li>Hidden Dir (/secret)</li><li>Port Knocking</li><li>Bruteforce (cewl wordlist)</li><li>Bruteforce SSH key </li><li>SUID Binary</li><li>Cronjob</li><li>64 Bit Buffer Overflow</li></ol>                                                                                                                                                                                                |
  | [Solid State 1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Solid%20State%201.pdf)                            | <ol><li>Service Exploit</li><li>Cronjob</li></ol>                                                                                                                                                                                                                                                                                                                                             |
  | [Escalate_Linux](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Escalate_Linux.pdf)                              | <ol><li>Enumerate Users (SMB)</li><li>HTTP RCE</li><li>no_root_squash/SUID Binary (Path Hijacking)/SUID Binary</li></ol>                                                                                                                                                                                                                                                                      |
  | [Wintermute](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Wintermute.pdf)                                      | <ol><li>Hidden Dir (/turing-bolo)</li><li>LFI</li><li>SUID Binary</li><li>Pivot</li><li>CMS Exploit</li><li>LXD/Kernel Exploit</li></ol>                                                                                                                                                                                                                                                      |
  | [Born2Root](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Born2Root.pdf)                                        | <ol><li>Hidden Dir (/icons)</li><li>Cronjob</li><li>Bruteforce SSH</li><li>Reused Creds</li></ol>                                                                                                                                                                                                                                                                                             |
  | [Stapler1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Stapler%201.pdf)                                       | <ol><li>Wordpress (Plugin)/(Bruteforce)/ Bruteforce FTP</li><li>Creds Found in Linux/Cronjob/Kernel Exploit</li></ol>                                                                                                                                                                                                                                                                         |
  | [Digitalworld.local(Bravery)](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Digitalworld.local%20(Bravery).pdf) | <ol><li>Enumerate Users (SMB)</li><li>Create Wordlist</li><li>Bruteforce SMB Fileshare</li><li>HTTP Dir Enum</li><li>CMS Exploit</li><li>no_root_squash/Cronjob/SUID Binary (GTFO Bin)</li></ol>                                                                                                                                                                                              |
  | [Digitalworld.local(Development)-notdone]()                                                                                   |                                                                                                                                                                                                                                                                                                                                                                                               |
  | [Digitalworld.local(FALL)-notdone]()                                                                                          |                                                                                                                                                                                                                                                                                                                                                                                               |
  | [Digitalworld.local(JOY)-notdone]()                                                                                           |                                                                                                                                                                                                                                                                                                                                                                                               |
  | [Digitalworld.local(Mercy v2)-notdonee]()                                                                                     |                                                                                                                                                                                                                                                                                                                                                                                               |
  | [DerpNStink](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/DerpNStink.pdf)                                      | <ol><li>Wordpress (Bruteforce + Plugin)</li><li>Creds Found in Linux</li><li>Wireshark</li><li>Sudo</li></ol>                                                                                                                                                                                                                                                                                 |
  | [RickdiculouslyEasy](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/RickdiculouslyEasy.pdf)                      | <ol><li>Hidden Dir (passwords)</li><li>Command Injection + Bypass Bash</li><li>Bruteforce SSH</li><li>Creds Found in Linux + additonal stuff</li></ol>                                                                                                                                                                                                                                        |
  | [Sar1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Sar1.pdf)                                                  | <ol><li>Web App Exploit</li><li>Cronjob</li></ol>                                                                                                                                                                                                                                                                                                                                             |
  | [Djinn](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Djinn.pdf)                                                | <ol><li>FTP anon</li><li>Command Injection + Bypass Bash</li><li>Creds Found in Linux</li><li>Sudo/Python2 Input Vuln/Decompile Python2 file </li></ol>                                                                                                                                                                                                                                       |
  | [EVM1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/EVM%201.pdf)                                               | <ol><li>Wordpress (Upload Reverse Shell)</li><li>Creds Found in Linux</li></ol>                                                                                                                                                                                                                                                                                                               |
  | [HackMe](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/hackme.pdf)                                              | <ol><li>SQLi Database Enum</li><li>SUID Binary</li></ol>                                                                                                                                                                                                                                                                                                                                      |
  | [Tommy Boy 1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Tommy%20Boy%201/Tommy%20Boy%201.md)                 | <ol><li>Hidden Web Dir (/prehistoricforest)</li><li>Image Forensic</li><li>Crack Hash</li><li>Hidden Web Dir (/spanky)</li><li>Bruteforce FTP</li><li>Hidden Web Dir (/NickIzL33t)</li><li>Edit User-Agent</li><li>Generate password word list</li><li>Bruteforce zip</li><li>Wordpress (Bruteforce)</li><li>Edit/Update mysql credentials</li><li>Wordpress (Upload Reverse Shell)</li></ol> |
  | [Breach 1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Breach%201/Breach%201.md)                              | <ol><li>Hidden text</li><li>Decode String</li><li>Crack Hash</li><li>Hidden Webpage (Click Image)</li><li>Image Forensic (exiftool)</li><li>Fuzz Search</li><li>Decrypt SSL traffic</li><li>Hidden Web Dir (/_M@nag3Me/html)</li><li>Upload reverse shell</li><li>Creds Found in Linux</li><li>Image Forensic From Earlier</li><li>Sudo (GTFO Bin)</li></ol>                                  |
  | [Tiki 1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Tiki%201/Tiki%201.md)                                    | <ol><li>SMB Fileshare Enum</li><li>CMS Exploit</li><li>Sudo</li></ol>                                                                                                                                                                                                                                                                                                                         |
  | [Prime 1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Prime%201/Prime%201.md)                                 | <ol><li>Hidden Web Dir (/secret.txt, /image.php, /index.php</li><li>Enumerate parameters in `.php` files</li><li>LFI</li><li>Wordpress (Upload Reverse Shell)</li><li>Sudo + Creds Found in Linux + Cryptography </li><li>Sudo/Kernel Exploit</li></ol>                                                                                                                                       |
  | [Bob 1.0.1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/Bob%201.0.1/Bob%201.0.1.md)                           | <ol>Command Injection + Bypass Bash<li></li><li>Creds Found in Linux</li><li>Sudo</li></ol>                                                                                                                                                                                                                                                                                                   |
  | [DevGuru 1](https://github.com/yufongg/writeups/blob/main/Vulnhub/Linux/DevGuru%201/DevGuru%201.md)                           | <ol><li>Hidden Web Dir (.git)</li><li>Creds Found in (.git)</li><li>CMS Exploit (RCE)</li><li>Creds Found in Linux (.bak)</li><li>CMS Exploit (RCE)</li><li>Sudo Version Exploit + Sudo (GTFO Bin)</li></ol>                                                                                                                                                                                  |
