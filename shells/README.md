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
