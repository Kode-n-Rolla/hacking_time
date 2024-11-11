<h1 align='center'>Active Directory</h1>
<ol>
  <li><a href='#recon'>Recon</a></li>
</ol>

<h2 align='center' id='recon'>Recon</h2>
<ol>
  <li>SPN scanning</li>
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
</ol>
