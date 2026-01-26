# **1. List Buckets in the Authenticated Account**

```
aws s3 ls --profile [profile_name]
```

---

# **2. Check if a Bucket Exists (No Auth)**

```
aws s3 ls s3://[bucket-name] --no-sign-request
```

If you see a list of objects or folders, the bucket is accessible without credentials—this is a serious misconfiguration.

---

# **3. List Contents of a Public or Accessible Bucket**

```
aws s3 ls s3://[bucket-name]/shared/ --no-sign-request
```

This lists the contents of the `/shared/` path. Look for any downloadable files.

---

# **4. Download an Object**

```
aws s3 cp s3://[bucket-name]/shared/file.zip . --no-sign-request
```

This saves the file into your current working directory. If the command succeeds, that confirms open read access on the bucket.

---

# **5. Upload a File (Test Write Access)**

```
aws s3 cp test.txt s3://[bucket-name]/test.txt
```

> Only works if write access is allowed.
> 

---

# **6. Enumerate Bucket Permissions (Authenticated)**

## **a. Get bucket policy**

```
aws s3api get-bucket-policy --bucket [bucket-name]
```

## **b. Get bucket ACL (Access Control List)**

```
aws s3api get-bucket-acl --bucket [bucket-name]
```

## **c. Get Public Access Block settings**

```
aws s3api get-bucket-public-access-block --bucket [bucket-name]
```

## **d. Get CORS configuration (may hint at XSS vectors)**

```
aws s3api get-bucket-cors --bucket [bucket-name]
```

---

# **7. List All Buckets & Objects (If Compromised Creds)**

```
aws s3api list-buckets
aws s3api list-objects --bucket [bucket-name] --output table
```
