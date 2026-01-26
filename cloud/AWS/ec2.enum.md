# Enumeration with AWS CLI

## **1. List EC2 Instances**

```
aws ec2 describe-instances --region [region]
```

> Shows instance IDs, public IPs, AMIs, key names, IAM roles, etc.
> 

Use JMESPath filters for cleaner output:

```
aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,PublicIpAddress,State.Name,KeyName,IamInstanceProfile.Arn]"
```

---

## **2. Get Detailed Info on a Specific Instance**

```
aws ec2 describe-instances --instance-ids [i-xxxxxxxxxxxxxxx]
```

---

## **3. Identify IAM Role Attached to the Instance**

```
aws ec2 describe-instances --query "Reservations[*].Instances[*].IamInstanceProfile.Arn" --region [region] --profile [profile_name]
```

Then grab role name and enumerate permissions:

```
aws iam get-instance-profile --instance-profile-name [name]
```

---

## **4. List Security Groups**

```
aws ec2 describe-security-groups --region [region] --profile [profile_name]
```

> Look for open ports, especially `0.0.0.0/0` on SSH (22), RDP (3389), or custom ports
> 

### **a. Check for overly permissive inbound rules:**

```
aws ec2 describe-security-groups --query "SecurityGroups[*].IpPermissions[*].{From:FromPort,To:ToPort,CIDR:IpRanges}"
```

---

## **5. Describe Network Interfaces**

```
aws ec2 describe-network-interfaces
```

> See public/private IPs, subnet info, VPC IDs, attachment info.
> 

---

## **6. List AMIs (Amazon Machine Images)**

```
aws ec2 describe-images --owners self
```

> Use this to find custom images that may contain secrets or sensitive software.
> 

---

## **7. Check EBS Volume Info**

```
aws ec2 describe-volumes
```

> Look for unencrypted volumes, large or attached volumes.
> 

### **a. Snapshot enumeration (potential data leaks):**

```
aws ec2 describe-snapshots --owner-ids self
```

---

## **8. Enumerate Key Pairs**

```
aws ec2 describe-key-pairs
```

> You can't get private keys from AWS, but public names may hint at user naming patterns or poor key hygiene.
> 

---

## **9. Describe Regions & Availability Zones**

```
aws ec2 describe-regions
aws ec2 describe-availability-zones
```

# Enumeration with Console

## **1. Log into AWS Console**

- Sign into your AWS Management Console using your lab credentials.
- Confirm you’re using the **correct region** (likely **us-east-1** unless specified otherwise). *Tip: The wrong region = missing instances! Always double-check.*

## **2. Navigate to EC2**

- Use the search bar at the top and type **EC2**.
- Click **EC2** to open the EC2 Dashboard.
- If needed, click **View Dashboard** to see instances.

## **3. Identify EC2 Instances**

- Under **Instances**, look for:
    - **Name** (can hint at its purpose)
    - **Instance ID**
    - **Public IP address** (important for scanning later)
    - **State** (Running or Stopped)
    - **Instance Type** (resource sizing)
    - **Security Group Name** (firewall rules)
    - **Key Name** (for SSH access if found)

> Add all this information to your notes. If doing a pentest, collecting public IPs for scanning (Nmap/Nessus) is critical.
> 

## **4. Check User Data for Secrets**

- Select the instance checkbox.
- Click **Actions → Instance Settings → Edit User Data**.
- Review the startup script (user data):
    - Look for **hardcoded usernames**, **passwords**, **database credentials**, **private keys**, etc.
    - Copy and save the user data into your notes (even if it’s just setup scripts).

## **5. Enumerate Attached IAM Role**

- In the instance details, click the linked **IAM Role** (if attached).
- View **attached policies**:
    - Check the **Policy Name**.
    - Click into the policy and view the **JSON** version.
    - Identify any important permissions like access to **S3**, **CloudWatch**, etc.

**Example:**

If the IAM role has `s3:*` permissions, and you compromise the instance, you could enumerate and exploit **S3 buckets**.

## **6. Add All Findings to Your Notes**

Suggested note structure:

- EC2 Instance Info
- User Data Content
- Attached IAM Role and Policy JSON
- Observations (e.g., Public IP exists, S3 access granted)
