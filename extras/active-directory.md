# Active Directory preparation
========================================

Below are the steps, including many PowerShell commands to prepare an AD environment

1. Deploy Windows Server 2012 R2
1. Set hostname to your liking
1. Install AD services
1. Configure AD
1. Add self-signed certificate for AD's LDAPS to work
1. Populate sample containers, users & groups
1. Delegate control to appropriate users

****************************************

## 1. Deploy Windows Server 2012 R2
----------------------------------------

- Most Cloud providers will have this option
- On Google Cloud, they have a "one-click" option to deploy AD

## 2. Set hostname


## Change hostname, if needed, and restart

   ```
## this will restart the server
$new_hostname = "ad01"
Rename-Computer -NewName $new_hostname -Restart
   ```
   
****************************************

## Install AD
----------------------------------------

1. Open Powershell (right click and "open as Administrator)

2. Prepare your environment. Update these to your liking.

   ```
$domainname = "lab.hortonworks.net"
$domainnetbiosname = "LAB"
$password = "BadPass#1"
   ```

3. Install AD features & Configure AD. You have 2 options:
   1. Deploy AD without DNS (relying on /etc/hosts or a separate DNS)

   ```
Install-WindowsFeature AD-Domain-Services –IncludeManagementTools
Import-Module ADDSDeployment
$secure_string_pwd = convertto-securestring ${password} -asplaintext -force
Install-ADDSForest `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "Win2012R2" `
-DomainName ${domainname} `
-DomainNetbiosName ${domainnetbiosname} `
-ForestMode "Win2012R2" `
-InstallDns:$false `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-SafeModeAdministratorPassword:$secure_string_pwd `
-Force:$true
   ```

   2. Deploy AD with DNS

    ```
Install-WindowsFeature AD-Domain-Services –IncludeManagementTools
Import-Module ADDSDeployment
$secure_string_pwd = convertto-securestring ${password} -asplaintext -force
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "Win2012R2" `
-DomainName ${domainname} `
-DomainNetbiosName ${domainnetbiosname} `
-ForestMode "Win2012R2" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-SafeModeAdministratorPassword:$secure_string_pwd `
-Force:$true
    ```

****************************************

## Add UPN suffixes
----------------------------------------

If the domain of your Hadoop nodes is different than your AD domain:
https://technet.microsoft.com/en-gb/library/cc772007.aspx


****************************************

## Enable LDAPS
----------------------------------------

There are several methods to enable SSL for LDAP (aka LDAPS).

1. Use a certificate from a public respected certificate authority.
2. Generate a self-signed certificate from your AD server, or other Windows Certificate Authority.
3. Generate a self-signed certificate from your own certificate authority.


Instructions for each:

1. See Active Directory documentation.
2. Generate a self-signed certificate from your AD server, or other Windows Certificate Authority.
  - On your Windows Server: [Install Active Directory Certificate Services](https://technet.microsoft.com/en-us/library/jj717285.aspx)
    - Ensure to configure as "Enterprise CA" not "Standalone CA".
    - Once it's installed:
      - Server Manager -> Tools -> Certificate Authority
      - Action -> Properties
      - General Tab -> View Certificate -> Details -> Copy to File
      - Choose the format: "Base-64 encoded X.509 (.CER)"
      - Save as 'activedirectory.cer' (or whatever you like)
      - Open with Notepad -> Copy Contents
      - This is your public CA to be distributed to all of your client hosts.
      - Reboot the Active Directory server for it to load the certificate.

3. Generate a self-signed certificate however you like.
   - Many options for this. I prefer OpenSSL (run from wherever you like):
      ```
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
    -subj '/CN=lab.hortonworks.net/O=Hortonworks Testing/C=US'

openssl genrsa -out wildcard-lab-hortonworks-net.key 2048
openssl req -new -key wildcard-lab-hortonworks-net.key -out wildcard-lab-hortonworks-net.csr \
    -subj '/CN=*.lab.hortonworks.net/O=Hortonworks Testing/C=US'
openssl x509 -req -in wildcard-lab-hortonworks-net.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out wildcard-lab-hortonworks-net.crt -days 3650

openssl pkcs12 -export -name "PEAP Certificate" -CSP 'Microsoft RSA SChannel Cryptographic Provider' -LMK -inkey wildcard-lab-hortonworks-net.key -in wildcard-lab-hortonworks-net.crt -certfile ca.crt  -out wildcard-lab-hortonworks-net.p12
      ```
   - Copy wildcard-lab-hortonworks-net.p12 to the Active Directory server
   - On your Active Directory server:
      - Run "mmc"
      - Open the "Certificates snap-in".
      - Expand the "Certificates" node under "Personal".
      - Select "All Tasks" -> "Import...", and import the the "p12".
      - Reboot the Active Directory server for it to load the certificate.
   - Step by step instructions [here](https://www.trustico.com/install/import/iis7/iis7-pfx-installation.php)

****************************************

## Configure AD OUs, Groups, Users, ...
----------------------------------------

```
$my_base = "DC=lab,DC=hortonworks,DC=net"
$my_ous = "CorpUsers","HadoopNodes","HadoopServices","ServiceUsers"
$my_groups = "hadoop-users","ldap-users","legal","hr","sales","hadoop-admins"

$my_ous | ForEach-Object {
  NEW-ADOrganizationalUnit $_;
}

$my_groups | ForEach-Object {
    NEW-ADGroup –name $_ –groupscope Global –path "OU=CorpUsers,$my_base";
}

$UserCSV = @"
samAccountName,Name,ParentOU,Group
hadoopadmin,"hadoopadmin","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","hadoop-admins"
rangeradmin,"rangeradmin","OU=ServiceUsers,DC=lab,DC=hortonworks,DC=net","hadoop-users"
ambari,"ambari","OU=ServiceUsers,DC=lab,DC=hortonworks,DC=net","hadoop-users"
keyadmin,"keyadmin","OU=ServiceUsers,DC=lab,DC=hortonworks,DC=net","hadoop-users"
ldap-reader,"ldap-reader","OU=ServiceUsers,DC=lab,DC=hortonworks,DC=net","ldap-users"
registersssd,"registersssd","OU=ServiceUsers,DC=lab,DC=hortonworks,DC=net","ldap-users"
legal1,"Legal1 Legal","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","legal"
legal2,"Legal2 Legal","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","legal"
legal3,"Legal3 Legal","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","legal"
sales1,"Sales1 Sales","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","sales"
sales2,"Sales2 Sales","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","sales"
sales3,"Sales3 Sales","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","sales"
hr1,"Hr1 HR","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","hr"
hr2,"Hr2 HR","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","hr"
hr3,"Hr3 HR","OU=CorpUsers,DC=lab,DC=hortonworks,DC=net","hr"
"@

$UserCSV > Users.csv

$AccountPassword = "BadPass#1" | ConvertTo-SecureString -AsPlainText -Force
Import-Module ActiveDirectory
Import-Csv "Users.csv" | ForEach-Object {
    $userPrincinpal = $_."samAccountName" + "@lab.hortonworks.net"
    New-ADUser -Name $_.Name `
        -Path $_."ParentOU" `
        -SamAccountName  $_."samAccountName" `
        -UserPrincipalName  $userPrincinpal `
        -AccountPassword $AccountPassword `
        -ChangePasswordAtLogon $false  `
        -Enabled $true
    add-adgroupmember -identity $_."Group" -member (Get-ADUser $_."samAccountName")
    add-adgroupmember -identity "hadoop-users" -member (Get-ADUser $_."samAccountName")
}
```

- Delegate OU permissions to `hadoopadmin` for `OU=HadoopServices`. In 'Active Directory Users and Computers' app:
  - right click HadoopServices 
  - Delegate Control
  - Next
  - Add
  - hadoopadmin
  - checknames
  - OK 
  - Select "Create, delete, and manage user accounts"
  - OK


- Give registersssd user permissions to join workstations to OU=HadoopNodes (needed to run 'adcli join' successfully). In 'Active Directory Users and Computers' app:
  - Click on View > Advanced features
  - Right Click on HadoopNodes
    - Properties
    - Security
    - Advanced
    - Permissions 
  - Add > 'Select a principal' > registersssd > Check names > Ok > 
    - Set 'Applies to' to: 'This object and all descendant objects. Select below checkboxes > OK
      - Create Computer Objects
      - Delete Computer Objects
  - Add > 'Select a principal' > registersssd > Check names > Ok > 
    - Set 'Applies to' to: 'Descendant Computer Objects' > select below checkboxes > Ok > Apply
      - Read All Properties
      - Write All Properties
      - Read Permissions
      - Modify Permissions
      - Change Password
      - Reset Password
      - Validated write to DNS host name
      - Validated write to service principle name

For more details on steps above see reference material [here](https://jonconwayuk.wordpress.com/2011/10/20/minimum-permissions-required-for-account-to-join-workstations-to-the-domain-during-deployment/)


- create keytab for Ambari. This will be used later to kerborize Ambari before setting up views
```
ktpass -out ambari.keytab -princ ambari@LAB.HORTONWORKS.NET -pass BadPass#1 -mapuser ambari@LAB.HORTONWORKS.NET -mapop set -crypto All -ptype KRB5_NT_PRINCIPAL
```

- To test the LDAP connection from a Linux node
```
sudo yum install openldap-clients
ldapsearch -h ad01.lab.hortonworks.net -p 389 -D "ldap-reader@lab.hortonworks.net" -w BadPass#1 -b "OU=CorpUsers,DC=lab,DC=hortonworks,DC=net" "(&(objectclass=person)(sAMAccountName=sales1))"
```

