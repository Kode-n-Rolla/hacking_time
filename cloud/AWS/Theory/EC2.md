# EC2 (Elastic Compute Cloud)

**EC2 is Virtual machine in the cloud** 

From a *pentesting perspective*, explain how EC2s are prime targets: look for exposed SSH ports, accessible metadata endpoints, poorly configured user data, and attached IAM roles.

## Core

- **instances** (virtual machines)
- **security groups** (firewall rules)
- **key pairs** (SSH access)
- **Elastic IPs** (public IPs)

## User choose:

- OS
- Instance Type
- Network Config
- IAM role

## Used for:

- Apps
- Dev Enviroment
- Web Severs

## Some key word:

- Instances → different EC2 in AWS enviroment
- Security Groups → firewalls 🔥🧱
- Key Pairs → like SSH keys. Use without password, for example
- Elastic IPs → IP addresses assinged to EC2 to able to connect with them
- Instance Metadata Service → a critical resource for attackers to extract credentials or configurations if they gain access to an EC2. I emphasize the role of **IAM instance profiles** and how they can be abused for lateral movement or privilege escalation.
- IAM Instance Profile → just IAM profile but for EC2

## Tips

- Acces to an EC2 = Gold 🥇
    - Metadata
    - IAM Permissions
    - Secrets Exposed
- Look for:
    - SSH Ports
    - Metadata Endpoint (`http://169.254.169.254`)
    - User Data
- **When enumerating EC2s via the AWS Console, what critical mistake could cause you to miss resources? → Forgetting to check each region**
