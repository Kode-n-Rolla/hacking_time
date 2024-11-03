<ol>
  <h1><li>Reconnaissance</h1>
    <ul><h2>Passive</h2>
      <li><a href='https://www.shodan.io/'>Shodan</a>
      <li><a href='https://search.censys.io/'>Censys</a>
        <p>Dork like this help to find subdomains and don`t forget check setting for include Virtual Hosts
          <p><code>(services.tls.certificates.leaf_data.names: &lt;TARGET_DOMAIN>) and services.http.response.status_code=”200"</code>
      <li><a href='https://crt.sh/'>crt.sh</a>
      <li><a href='https://web.archive.org/'>Web archive</a>
      <li><a href='https://www.whois.com/whois/'>Whois</a>
      <li><a href='https://whoisfreaks.com/'>Whois Freaks</a>
      <li><a href='https://viewdns.info/'>ViewDNS.info</a>
      <li><a href='https://www.yougetsignal.com/'>YouGetSignal.com</a>. Remote Address Lookup, Port Forwarding Tester, Whois Lookup, Visual Trace Route, Reverse IP Lookup, Network Location Tool and much more
      <li><a href='https://rapiddns.io/'>Rapiddns.io</a>. DNS data
      <li><a href='https://securitytrails.com/'>Securitytrails.com</a>
      <li><a href='https://dnsdumpster.com/'>Dnsdumpster.com</a>
      <li><a href='https://urlscan.io/'>Urlscan.io</a>
      <li><code>dig domain.com ANY</code> (<code>dig @ns1.domain.com domain AXFR</code>), <code>nslookup domain.com</code>, <code>host domain.com</code>
      <li><a href='https://github.com/laramies/theHarvester'>theHarvester</a>
      <li>Social Media
      <li><a href='https://github.com/'>GitHub</a>, <a href='https://about.gitlab.com/'>GitLab</a>
      <li>Google Dorking
      <li><a href='https://github.com/aboul3la/Sublist3r'>sublist3r</a>
      <li><a href='https://github.com/projectdiscovery/subfinder'>subfinder</a>
      <li><a href='https://github.com/tomnomnom/assetfinder'>assetfinder</a>
      <li><a href='https://github.com/gotr00t0day/spyhunt'>spyhunt</a>. Comprehensive network scanning and vulnerability assessment tool.
    </ul>
    <ul><h2>Active</h2>
      <li><a href='https://github.com/projectdiscovery/httpx'>httpx</a>. Check active subdomains
      <li><a href='https://github.com/robertdavidgraham/masscan'>masscan</a>
      <li><a href='https://github.com/nmap/nmap'>Nmap</a>
      <li><a href='https://github.com/RustScan/RustScan'>RustScan</a>
      <li><a href='https://github.com/ffuf/ffuf'>ffuf</a>
      <li><a href='https://github.com/OJ/gobuster'>gobuster</a>:
        <pre><code>gobuster dns -d &lt;TARGET_DOMAIN.com> -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt</code></pre>
        <pre><code>gobuster vhost -u &lt;TARGET_URL> -w /usr/share/SecLists/Discovery/Web-Content/common.txt --append-domain</code></pre>
      <li><a href='https://github.com/epi052/feroxbuster'>feroxbuster</a>
      <li><a href='https://github.com/v0re/dirb'>dirb</a>
      <li><a href='https://github.com/KajanM/DirBuster'>dirbuster</a>
      <li><a href='https://github.com/s0md3v/Arjun'>Arjun</a>
      <li><a href='https://github.com/fwaeytens/dnsenum'>dnsenum</a>, <a href='https://github.com/mschwager/fierce'>fierce</a>,
        <a href='https://github.com/darkoperator/dnsrecon'>dnsrecon</a>, <a href='https://github.com/d3mondev/puredns'>puredns</a>
      <li><a href='https://www.kali.org/tools/whatweb/'>WhatWeb</a>
      <li>/robots.txt
      <li>/sitemap.xml
      <li>/.well-known/openid-configuration and other /.well-known/... More <a href='https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml'>info</a>
      <li>View source code
      <li><a href='https://otx.alienvault.com/'>Otx.alienvault.com</a>
    </ul>
    <ul><h2>Both</h2>
      <li><a href='https://github.com/owasp-amass/amass'>amass</a>. <code>amass enum -d example.com</code> - active, <code>amass enum -passive -d example.com</code> - passive
    </ul>
    <ul> <h2>Fingerprinting</h2>
      <li>Wappalyzer (browser extension)
      <li>whatweb, wafw00f (CLI)
      <li><code>curl -I &lt;TARGET_HOST></code> - to get server banner
      <li><code>nikto -h &lt;TARGET_HOST> -Tuning b</code>
    </ul>
    <ul><h2>Crawlers</h2>
      <li><a href='https://github.com/jaeles-project/gospider'>Gospider</a> 
      <li><a href='https://portswigger.net/blog/burp-2-0-where-are-the-spider-and-scanner'>Burp Suite Spider</a>, <a href='https://www.zaproxy.org/'>OWASP ZAP (Zed Attack Proxy)</a>, 
      <li><a href='https://github.com/scrapy/scrapy'>Scrapy (Python Framework)</a>
      <li><a href='https://github.com/apache/nutch'>Apache Nutch (Scalable Crawler)</a>
    </ul>
    <ul><h2>Another Tools for Recon</h2>
      <li><a href='https://github.com/thewhiteh4t/FinalRecon'>FinalRecon</a>
      <li><a href='https://github.com/lanmaster53/recon-ng'>Recon-ng</a>
      <li><a href='https://github.com/smicallef/spiderfoot'>Spiderfoot</a>
      <li><a href='https://osintframework.com/'>OSINT Framework</a>
    </ul>
</ol>
