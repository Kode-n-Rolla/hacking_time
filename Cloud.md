<h1 align='center'>Cloud</h1>
<h3>There are:</h3>
  <li><a href='Tools'>Third-Party Tools</a></li>
  <li><a href='AWS'>Amazon Web Services</a></li>
  <li><a href='Azure'>Microsoft Azure</a></li>
  <li><a href='GCP'>Google Cloud Platform</a></li>

<h2 align='center' id='Tools'><em>Third-Party Tools</em></h2>
<ol>
  <li>For AWS:</li>
    <ul>
      <li>toniblyx`s <a href='https://github.com/toniblyx/my-arsenal-of-aws-security-tools#Offensive'>arsenal</a> of aws security</li>
      <li><a href='https://github.com/WithSecureLabs/awspx'>awspx</a>. Open source</li>
      <li><a href='https://www.acunetix.com/'>Acunetix</a>. Vulnerability Scanner. Commercial Software</li>
      <li><a href='https://github.com/carnal0wnage/weirdAAL'>weirdAAl</a>. AWS attack library. Open source</li>
      <li><a href='https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools/s3'>S3 bucket scanner</a>. Open source</li>
      <li><a href='https://github.com/RhinoSecurityLabs/pacu'>Pacu</a>. AWS pentesting framework. Open source</li>
      <li><a href='https://github.com/disruptops/cred_scanner'>Cred Scanner</a>. To find AWS credentials in files. Open source</li>
      <li><a href='https://github.com/MindPointGroup/cloudfrunt'>CloudFrunt</a>. To find misconfiguration in AWS CloudFront. Open source</li>
      <li><a href='https://github.com/ihamburglar/Redboto'>Redboto</a>. Collection of script to aid in AWS red team engagements</li>
      <li><a href='https://github.com/jordanpotti/AWSBucketDump'>AWSBucketDump</a>. Quickly enumerate AWS S3 buckets. Open source</li>
    </ul>
  <li>For Azure:</li>
    <ul>
      <li><a href='https://github.com/NetSPI/MicroBurst'>MicroBurst</a>. A PowerShell Toolkit. Open source</li>
      <li><a href='https://github.com/hausec/PowerZure'>PowerZure</a>. Created to assess and exploit resources within Microsoft’s cloud platform. Open source</li>
      <li><a href='https://github.com/FSecureLABS/Azurite'>Azurite</a>. Novel way to use PowerShellfor pentesting Azure. Open source</li>
      <li><a href='https://github.com/Azure/Cloud-Katana'>Cloud-Katana</a>. To automate the execution of simulation steps in multi-cloud and hybrid cloud environments. Open source</li>
      <li><a href='https://github.com/cyberark/SkyArk'>SkyArk</a>. Cloud security project with main scanning modules. Open source</li>
      <li><a href='https://github.com/dafthack/MFASweep'>MFASweep</a>. Help with MFA in Microsoft services. Open source</li>
      <li><a href='https://github.com/dirkjanm/adconnectdump'>Adconnectdump</a>. Exploit vulnerabilities in how AD is configured in Azure to extract passwords. Open source</li>
      <li><a href='https://github.com/cyberark/BlobHunter'>BlobHunter</a>. Helps to identify Azure blob storage poorly configured containers. Open source</li>
    </ul>
  <li>For GCP:</li>
    <ul>
      <li><a href='https://github.com/RhinoSecurityLabs/GCPBucketBrute'>GCPBucketBrute</a>. A script to enumerate Google Storage buckets. Open source</li>
      <li><a href='https://github.com/DenizParlak/hayat'>hayat</a>. Script to audit Cloud SQL, IAM, Cloud Storage, network configuration, VMs etc. Open source</li>
      <li><a href='https://github.com/dxa4481/gcploit'>gcploit</a>. Pentrsting tools to find vulnerabilities in GCP. Open source</li>
      <li><a href='https://github.com/darkbitio/gcp-iam-role-permissions'>gcp-iam-role-permissions</a>. Open source</li>
      <li><a href='https://github.com/google/gcp_scanner'>GCP Scanner</a>. Open source</li>
    </ul>
  <li>For three:</li>
    <ul>
      <li><a href='https://github.com/prowler-cloud/prowler'>Prowler</a>. Open source</li>
      <li><a href='https://www.intruder.io/'>Intruder</a>. Auromated scan. Montly or annual subscription</li>
      <li><a href='https://github.com/0xsha/CloudBrute'>CloudBrute</a>. A tool to find a company (target) infrastructure, files, and apps on the top cloud providers. Open source</li>
      <li><a href='https://github.com/nccgroup/ScoutSuite'>ScoutSuite</a>. Open source multi-cloud security-auditing tool</li>
      <li><a href='https://buckets.grayhatwarfare.com/'>buckets.grayhatwarfare.com</a></li>
      <li><a href='https://github.com/initstring/cloud_enum'>cloud_enum</a>. Multi-cloud OSINT tool. Open source</li>
    </ul>
</ol>

<h2 align='center' id='AWS'><em>AWS</em></h2>
<ol>
  <li>Prepare to pentest:</li>
  <ul>
    <li>AWS Customer Support <a href='https://aws.amazon.com/security/penetration-testing/'>Policy</a> for Penetration Testing</li>
    <li>Amazon EC2 Testing <a href='https://aws.amazon.com/ec2/testing/'>Policy</a></li>
    <li>DDoS Simulation Testing <a href='https://aws.amazon.com/security/ddos-simulation-testing/'>Policy</a></li>
    <li>AWS Security <a href='https://docs.aws.amazon.com/security/'>Documentation</a></li>
  </ul>
  <li>AWS own instruments:</li>
    <ul>
      <li><a href='https://aws.amazon.com/inspector/'>Amazon Inspector</a></li>
    </ul>
  <li>Help commands:</li>
    <ul>
      <li>Access to public S3 bucket:</li>
        <pre><code>aws s3 ls s3://target-bucket --no-sign-request</code></pre>
      <li>If bucket is open, find creds:</li>
        <pre><code>aws s3 cp s3://target-bucket/config.json . cat config.json | grep -i "key"</code></pre>
    </ul>
</ol>

<h2 align='center' id='Azure'><em>Azure</em></h2>
<ol>
  <li>Prepare to pentest:</li>
  <ul>
    <li>Microsoft Online Subscription <a href='https://azure.microsoft.com/en-us/support/legal/subscription-agreement'>Agreement</a></li>
    <li>Penetration Testing <a href='https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement/'>Rules</a> of Engagement</li>
  </ul>
    <li>Azure own instruments:</li>
    <ul>
      <li><a href='https://www.microsoft.com/en-ca/security/business/cloud-security/microsoft-defender-cloud'>Microsoft Defender for Cloud</a></li>
    </ul>
  <li>Help commands:</li>
    <ul>
      <li>Azure Blob Stogate leaks:</li>
      <pre><code>az storage blob list --container-name mycontainer --account-name mystorageaccount --output table</code></pre>
    </ul>
</ol>

<h2 align='center' id='GCP'><em>GCP</em></h2>
<ol>
  <li>Prepare to pentest:</li>
  <ul>
    <li>Google Cloud Platform/SecOps <a href='https://cloud.google.com/terms'>Terms</a> of Service</li>
    <li>Google Cloud Platform Acceptable Use <a href='https://cloud.google.com/terms/aup?hl=ru'>Policy</a></li>
  </ul>
  <li>Help commands:</li>
    <ul>
      <li>Searching for public Google Cloud buckets:</li>
        <pre><code>gcloud storage buckets list --public</code></pre>
    </ul>
</ol>
<h2 align='center'></h2>
<h3 align='center'><em>Feel free to check out my GitHub Stars for more cloud tools and resources!</em></h3>
