# Environment notes

## AD overview

- Active Directory will already be setup by the instructor. A basic structure of OrganizationalUnits will have been pre-created to look something like the below:
  - CorpUsers OU, which contains:
    - business users and groups (e.g. it1, hr1, legal1) and 
    - hadoopadmin: Admin user (for AD, Ambari, ...)
  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/AD-corpusers.png)
  
  - ServiceUsers OU: service users - that would not be created by Ambari  (e.g. rangeradmin, ambari etc)
  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/AD-serviceusers.png)
  
  - HadoopServices OU: hadoop service principals (will be created by Ambari)
  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/AD-hadoopservices.png)  
  
  - HadoopNodes OU: list of nodes registered with AD
  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/AD-hadoopnodes.png)

- In addition, the below steps would have been completed in advance [per doc](http://docs.hortonworks.com/HDPDocuments/Ambari-2.2.0.0/bk_Ambari_Security_Guide/content/_use_an_existing_active_directory_domain.html):
  - Ambari Server and cluster hosts have network access to, and be able to resolve the DNS names of, the Domain Controllers.
  - Active Directory secure LDAP (LDAPS) connectivity has been configured.
  - Active Directory User container for principals has been created and is on-hand. For example, "ou=HadoopServices,dc=lab,dc=hortonworks,dc=net"
  - Active Directory administrative credentials with delegated control of "Create, delete, and manage user accounts" on the previously mentioned User container are on-hand. e.g. hadoopadmin


- For general info on Active Directory refer to Microsoft website [here](https://technet.microsoft.com/en-us/library/cc780336(v=ws.10).aspx) 

## Accessing your Cluster

Credentials will be provided for these services by the instructor:

* SSH
* Ambari

## Use your Cluster

### To connect using Putty from Windows laptop

- Download ppk from [here](https://github.com/seanorama/masterclass/raw/master/security-advanced/training-keypair.ppk)
- Use putty to connect to your nodes

### To connect from Linux/MacOSX laptop

- SSH into Ambari node of your cluster using below steps:
  - Right click [this pem key](https://github.com/seanorama/masterclass/blob/master/security-advanced/training-keypair.pem)  > Save link as > save to Downloads folder
  - Copy pem key to ~/.ssh dir and correct permissions
  ```
  cp ~/Downloads/training-keypair.pem ~/.ssh/
  chmod 400 ~/.ssh/training-keypair.pem
  ```
 - Login to the Ambari node of the cluster you have been assigned by replacing IP_ADDRESS_OF_AMBARI_NODE below with Ambari node IP Address (your instructor will provide this)   
  ```
  ssh -i  ~/.ssh/training-keypair.pem centos@IP_ADDRESS_OF_AMBARI_NODE
  ```
  - To change user to root you can:
  ```
  sudo su -
  ```

  - From SSH terminal, how can I find internal hostname (aka FQDN) of the node I'm logged into?
  ```
  $ hostname -f
  ip-172-30-0-186.us-west-2.compute.internal  
  ```

  - From SSH terminal, how can I to find external (public) IP  of the node I'm logged into?
  ```
  $ curl icanhazip.com
  54.68.246.157  
  ```
  
  
### Why is security needed?

- On your unsecured cluster try to access a restricted dir in HDFS
```
hdfs dfs -ls /tmp/hive   
## this should fail with Permission Denied
```

- Now try again after setting HADOOP_USER_NAME env var
```
export HADOOP_USER_NAME=hdfs
hdfs dfs -ls /tmp/hive   
## this shows the file listing!
```
- Unset the env var
```
unset HADOOP_USER_NAME
hdfs dfs -ls /tmp/hive  
```
- This should tell you why kerberos is needed on Hadoop :)


##### Open Ambari and Manually install missing components

- Login to Ambari web UI by opening http://AMBARI_PUBLIC_IP:8080 and log in with admin/BadPass#1
- Use the 'Add Service' Wizard to install Knox (and Hbase, if not already installed)
  - When prompted for the Knox password, set it to `BadPass#1`

- From Ambari how can I find external hostname of node where a component (e.g. Resource Manager) is installed?
  - Click the parent service (e.g. YARN) and *hover over* the name of the component. The external hostname will appear.

- From Ambari how can I find internal hostname of node where a component (e.g. Resource Manager) is installed?
  - Click the parent service (e.g. YARN) and *click on* the name of the component. It will take you to hosts page of that node and display the internal hostname on the top.


### Configure name resolution & certificate to Active Directory

**Run below on all nodes**

1. Add your Active Directory to /etc/hosts (if not in DNS). Make sure you replace the IP address of your AD from your instructor.
  - **Change the IP to match your ADs internal IP**
   ```
ad_ip=GET_THE_AD_IP_FROM_YOUR_INSTRUCTOR
echo "${ad_ip} ad01.lab.hortonworks.net ad01" | sudo tee -a /etc/hosts
   ```

2. Add your CA certificate (if using self-signed & not already configured)
  - In this case we have pre-exported the CA cert from our AD and made available for download. 
   ```
cert_url=https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/extras/ca.crt
sudo yum -y install openldap-clients ca-certificates
sudo curl -sSL "${cert_url}" \
    -o /etc/pki/ca-trust/source/anchors/hortonworks-net.crt

sudo update-ca-trust force-enable
sudo update-ca-trust extract
sudo update-ca-trust check
   ```

3. Test certificate & name resolution with `ldapsearch`

   ```
## Update ldap.conf with our defaults
sudo tee -a /etc/openldap/ldap.conf > /dev/null << EOF
TLS_CACERT /etc/pki/tls/cert.pem
URI ldaps://ad01.lab.hortonworks.net ldap://ad01.lab.hortonworks.net
BASE dc=lab,dc=hortonworks,dc=net
EOF

## test by running below (LDAP password is: BadPass#1)
ldapsearch -W -D ldap-reader@lab.hortonworks.net

openssl s_client -connect ad01:636 </dev/null
   ```

**Now repeat above steps on all nodes**

## Secure Ambari

### Create Ambari Keystore

### Setup Ambari/AD sync

Run below on only Ambari node:

1. Add your AD properties as defaults for Ambari LDAP sync  

  ```
ad_dc="ad01.lab.hortonworks.net"
ad_root="ou=CorpUsers,dc=lab,dc=hortonworks,dc=net"
ad_user="cn=ldap-reader,ou=ServiceUsers,dc=lab,dc=hortonworks,dc=net"

sudo tee -a /etc/ambari-server/conf/ambari.properties > /dev/null << EOF
authentication.ldap.baseDn=${ad_root}
authentication.ldap.managerDn=${ad_user}
authentication.ldap.primaryUrl=${ad_dc}:389
authentication.ldap.bindAnonymously=false
authentication.ldap.dnAttribute=distinguishedName
authentication.ldap.groupMembershipAttr=member
authentication.ldap.groupNamingAttr=cn
authentication.ldap.groupObjectClass=group
authentication.ldap.useSSL=false
authentication.ldap.userObjectClass=user
authentication.ldap.usernameAttribute=sAMAccountName
EOF

  ```
  
2. Run Ambari LDAP sync. 
 - Press enter at each prompt to accept the default value being displayed
 - When prompted for 'Manager Password' at the end, enter password : BadPass#1
  ```
  sudo ambari-server setup-ldap
  ```

3. Reestart Ambari server and agents
  ```
   sudo ambari-server restart
   sudo ambari-agent restart
  ```
4. Run LDAPsync to sync only the groups we want
  - When prompted for user/password, use the *local* Ambari admin credentials (i.e. admin/BadPass#1)
  ```
  echo hadoop-users,hr,sales,legal,hadoop-admins > groups.txt
  sudo ambari-server sync-ldap --groups groups.txt
  ```

  - This should show a summary of what objects were created
  ```
  Completed LDAP Sync.
  Summary:
    memberships:
      removed = 0
      created = 25
    users:
      updated = 0
      removed = 0
      created = 15
    groups:
      updated = 0
      removed = 0
      created = 5
  ``` 
  
5. Give 'hadoop-admins' permissions to manage the cluster
  - Login to Ambari as your local 'admin' user (i.e. admin/BadPass#1)
  - Grant 'hadoopadmin' user permissions to manage the cluster:
    - Click the dropdown on top right of Ambari UI
    - Click 'Manage Ambari'
    - Under 'Users', select 'hadoopadmin'
    - Change 'Ambari Admin' to Yes 
  - Logout and log back into Ambari as 'hadoopadmin' and verify the user has rights to manage the cluster

6. (optional) Disable local 'admin' user
 
## Kerberize the Cluster

### Run Ambari Kerberos Wizard against Active Directory environment

Enable kerberos using Ambari security wizard (under 'Admin' tab > Kerberos). Enter the below details:

- KDC:
    - KDC host: ad01.lab.hortonworks.net
    - Realm name: LAB.HORTONWORKS.NET
    - LDAP url: ldaps://ad01.lab.hortonworks.net
    - Container DN: ou=HadoopServices,dc=lab,dc=hortonworks,dc=net
    - Domains: us-west-2.compute.internal,.us-west-2.compute.internal
- Kadmin:
    - Kadmin host: ad01.lab.hortonworks.net
    - Admin principal: hadoopadmin@LAB.HORTONWORKS.NET
    - Admin password: BadPass#1

- Then click Next on all the following screens to pick the default values

### Setup AD/OS integration via SSSD

- Why? 
  - Currently your hadoop nodes do not recognize users/groups defined in AD.
  - You can check this by running below:
  ```
  id it1
  groups it1
  ```
-  Pre-req for below steps: Your AD admin/instructor should have given 'registersssd' user permissions to add the workstation to OU=HadoopNodes (needed to run 'adcli join' successfully)

- Run below **on each node**
```
ad_user="registersssd"
ad_domain="lab.hortonworks.net"
ad_dc="ad01.lab.hortonworks.net"
ad_root="dc=lab,dc=hortonworks,dc=net"
ad_ou="ou=HadoopNodes,${ad_root}"
ad_realm=${ad_domain^^}

sudo kinit ${ad_user}
```

- Run below on each node
```
sudo yum makecache fast
sudo yum -y -q install epel-release ## epel is required for adcli
sudo yum -y -q install sssd oddjob-mkhomedir authconfig sssd-krb5 sssd-ad sssd-tools
sudo yum -y -q install adcli

sudo adcli join -v \
  --domain-controller=${ad_dc} \
  --domain-ou="${ad_ou}" \
  --login-ccache="/tmp/krb5cc_0" \
  --login-user="${ad_user}" \
  -v \
  --show-details

sudo tee /etc/sssd/sssd.conf > /dev/null <<EOF
[sssd]
## master & data nodes only require nss. Edge nodes require pam.
services = nss, pam, ssh, autofs, pac
config_file_version = 2
domains = ${ad_realm}
override_space = _

[domain/${ad_realm}]
id_provider = ad
ad_server = ${ad_dc}
#ad_server = ad01, ad02, ad03
#ad_backup_server = ad-backup01, 02, 03
auth_provider = ad
chpass_provider = ad
access_provider = ad
enumerate = False
krb5_realm = ${ad_realm}
ldap_schema = ad
ldap_id_mapping = True
cache_credentials = True
ldap_access_order = expire
ldap_account_expire_policy = ad
ldap_force_upper_case_realm = true
fallback_homedir = /home/%d/%u
default_shell = /bin/false
ldap_referrals = false

[nss]
memcache_timeout = 3600
override_shell = /bin/bash
EOF

sudo chmod 0600 /etc/sssd/sssd.conf
sudo service sssd restart
sudo authconfig --enablesssd --enablesssdauth --enablemkhomedir --enablelocauthorize --update

sudo chkconfig oddjobd on
sudo service oddjobd restart
sudo chkconfig sssd on
sudo service sssd restart

sudo kdestroy
```
- Test your nodes can recognize AD users
```
id sales1
groups sales1
```

### Refresh HDFS User-Group mappings

- Once the above is completed on all nodes you need to refresh the user group mappings in HDFS & YARN by running the below commands

- Execute the following on the Ambari node:
```
export PASSWORD=BadPass#1

#detect name of cluster
output=`curl -u hadoopadmin:$PASSWORD -i -H 'X-Requested-By: ambari'  http://localhost:8080/api/v1/clusters`
cluster=`echo $output | sed -n 's/.*"cluster_name" : "\([^\"]*\)".*/\1/p'`

#refresh user and group mappings
sudo sudo -u hdfs kinit -kt /etc/security/keytabs/hdfs.headless.keytab hdfs-${cluster}
sudo sudo -u hdfs hdfs dfsadmin -refreshUserToGroupsMappings
```

Execute the following on the node where the YARN ResourceManager is installed:
```
sudo sudo -u yarn kinit -kt /etc/security/keytabs/yarn.service.keytab yarn/$(hostname -f)@LAB.HORTONWORKS.NET
sudo sudo -u yarn yarn rmadmin -refreshUserToGroupsMappings
```

- kinit as a normal Hadoop user
```
kinit hr1
```

- check the users groups
```
hdfs groups
yarn rmadmin -getGroups hr1
```

- output should look like:
```
hr1@LAB.HORTONWORKS.NET : domain_users hadoop-users hr
```

### Test OS/AD integration and Kerberos security

- Login as sales1 user and try to access the same /tmp/hive HDFS dir
```
su - sales1

hdfs dfs -ls /tmp/hive   
## since we did not authenticate, this fails with GSSException: No valid credentials provided

#authenticate
kinit
##enter BadPass#1

klist
## shows the principal for sales1

hdfs dfs -ls /tmp/hive 
## fails with Permission denied

#Now try to get around security by setting the same env variable
export HADOOP_USER_NAME=hdfs
hdfs dfs -ls /tmp/hive 

```
- Notice that now that the cluster is kerborized, we were not able to circumvent security by setting the env var 

******************************

## Day two

Agenda:

  - LDAP tool demo
  - Ranger pre-reqs
    - Install any missing services i.e. Kafka
    - Setup MySQL
    - Setup Solr for Ranger audits
  - Ranger install
    - Configure MySQL/Solr/HDFS audits
    - Configure user/group sync with AD
    - Configure plugins
    - Auth via AD
  - Ambari views setup on secure cluster
    - Kerberos for Ambari 
    - Files
    - Hive
    - Others (Jobs/Capacity Scheduler...)
  - Using Hadoop components in secured mode. Audit excercises for:
    - HDFS
    - Hive
    - Hbase
    - YARN
    - Storm
    - Kafka
    - Knox
      - AD integration
      - WebHDFS
      - Hive
  - Access webUIs via SPNEGO 
  - Manually setup Solr Ranger plugin(?)



## Kerberos for Ambari

- Setup kerberos for Ambari. Below steps as based on doc: http://docs.hortonworks.com/HDPDocuments/Ambari-2.1.2.0/bk_Ambari_Security_Guide/content/_optional_set_up_kerberos_for_ambari_server.html

```
# run on Ambari node to start security setup guide
cd /etc/security/keytabs/
sudo wget https://github.com/seanorama/masterclass/raw/master/security-advanced/extras/ambari.keytab
sudo chown ambari:hadoop ambari.keytab
sudo chmod 400 ambari.keytab
sudo ambari-server stop
sudo ambari-server setup-security
```
- Enter below when prompted (sample output shown below):
  - choice: `3`
  - principal: `ambari@LAB.HORTONWORKS.NET`
  - keytab path: `/etc/security/keytabs/ambari.keytab`
```
Using python  /usr/bin/python2.7
Security setup options...
===========================================================================
Choose one of the following options:
  [1] Enable HTTPS for Ambari server.
  [2] Encrypt passwords stored in ambari.properties file.
  [3] Setup Ambari kerberos JAAS configuration.
  [4] Setup truststore.
  [5] Import certificate to truststore.
===========================================================================
Enter choice, (1-5): 3
Setting up Ambari kerberos JAAS configuration to access secured Hadoop daemons...
Enter ambari server's kerberos principal name (ambari@EXAMPLE.COM): ambari@LAB.HORTONWORKS.NET
Enter keytab path for ambari server's kerberos principal: /etc/security/keytabs/ambari.keytab
Ambari Server 'setup-security' completed successfully.
```

- Restart Ambari to changes to take affect
```
sudo ambari-server restart
sudo ambari-server restart
sudo ambari-agent restart
```

- SPNEGO: http://docs.hortonworks.com/HDPDocuments/Ambari-2.2.0.0/bk_Ambari_Security_Guide/content/_configuring_http_authentication_for_HDFS_YARN_MapReduce2_HBase_Oozie_Falcon_and_Storm.html
- Setup Ambari as non root http://docs.hortonworks.com/HDPDocuments/Ambari-2.2.0.0/bk_Ambari_Security_Guide/content/_configuring_ambari_for_non-root.html

- Ambari views setup on secure cluster details [here](https://github.com/seanorama/masterclass/tree/master/security-advanced#other-security-features-for-ambari)

## Ranger prereqs



##### Create & confirm MySQL user 'root'

Prepare MySQL DB for Ranger use. Run these steps on the node where MySQL is located
- `sudo mysql`
- Execute following in the MySQL shell. Change the password to your preference. 

    ```sql
CREATE USER 'root'@'%';
GRANT ALL PRIVILEGES ON *.* to 'root'@'%' WITH GRANT OPTION;
SET PASSWORD FOR 'root'@'%' = PASSWORD('BadPass#1');
SET PASSWORD = PASSWORD('BadPass#1');
FLUSH PRIVILEGES;
exit
```

- Confirm MySQL user: `mysql -u root -h $(hostname -f) -p -e "select count(user) from mysql.user;"`
  - Output should be a simple count. Check the last step if there are errors.

##### Prepare Ambari for MySQL *(or the database you want to use)*
- Run this on Ambari node
- Add MySQL JAR to Ambari:
  - `sudo ambari-server setup --jdbc-db=mysql --jdbc-driver=/usr/share/java/mysql-connector-java.jar`
    - If the file is not present, it is available on RHEL/CentOS with: `sudo yum -y install mysql-connector-java`

##### Install SolrCloud from HDPSearch for Audits


###### Option 1: Install Solr manually

- Manually install Solr *on each node where Zookeeper is running*
```
export JAVA_HOME=/usr/java/default   
sudo yum -y install lucidworks-hdpsearch
```

###### Option 2: Use Ambari service for Solr

- Install Ambari service for Solr
```
VERSION=`hdp-select status hadoop-client | sed 's/hadoop-client - \([0-9]\.[0-9]\).*/\1/'`
sudo git clone https://github.com/abajwa-hw/solr-stack.git /var/lib/ambari-server/resources/stacks/HDP/$VERSION/services/SOLR
sudo ambari-server restart
```
- Login to Ambari as hadoopadmin and wait for all the services to turn green
- Install Solr by starting the 'Add service' wizard (using 'Actions' dropdown) and choosing Solr. Pick the defaults in the wizard except:
  - On the screen where you choose where to put Solr, use the + button next to Solr to add Solr to *each host that runs a Zookeeper Server*
  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/solr-service-placement.png)
  
  - On the screen to Customize the Solr service
    - under 'Advanced solr-config':
      - set `solr.datadir` to `/opt/ranger_audit_server`    
      - set `solr.download.location` to `HDPSEARCH`
      - set `solr.znode` to `/ranger_audits`
    - under 'Advanced solr-env':
      - set `solr.port` to `6083`
  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/solr-service-configs.png)  

- Under Configure Identities page, you will have to enter your AD admin credentials:
  - Admin principal: hadoopadmin@LAB.HORTONWORKS.NET
  - Admin password: BadPass#1

- Then go through the rest of the install wizard by clicking Next to complete installation of Solr

- (Optional) In case of failure, run below from Ambari node to delete the service so you can try again:
```
export SERVICE=SOLR
export AMBARI_HOST=localhost
export PASSWORD=BadPass#1
output=`curl -u hadoopadmin:$PASSWORD -i -H 'X-Requested-By: ambari'  http://localhost:8080/api/v1/clusters`
CLUSTER=`echo $output | sed -n 's/.*"cluster_name" : "\([^\"]*\)".*/\1/p'`

#attempt to unregister the service
curl -u admin:$PASSWORD -i -H 'X-Requested-By: ambari' -X DELETE http://$AMBARI_HOST:8080/api/v1/clusters/$CLUSTER/services/$SERVICE

#in case the unregister service resulted in 500 error, run the below first and then retry the unregister API
#curl -u admin:$PASSWORD -i -H 'X-Requested-By: ambari' -X PUT -d '{"RequestInfo": {"context" :"Stop $SERVICE via REST"}, "Body": {"ServiceInfo": {"state": "INSTALLED"}}}' http://$AMBARI_HOST:8080/api/v1/clusters/$CLUSTER/services/$SERVICE

sudo service ambari-server restart

#restart agents on all nodes
sudo service ambari-agent restart
```

###### Setup Solr for Ranger audit 

- Once Solr is installed, run below to set it up for Ranger audits. Steps are based on http://docs.hortonworks.com/HDPDocuments/HDP2/HDP-2.3.2/bk_Ranger_Install_Guide/content/solr_ranger_configure_solrcloud.html

- Run on all nodes where Solr was installed
```
export JAVA_HOME=/usr/java/default
export host=$(curl -4 icanhazip.com)

sudo wget https://issues.apache.org/jira/secure/attachment/12761323/solr_for_audit_setup_v3.tgz -O /usr/local/solr_for_audit_setup_v3.tgz
cd /usr/local
sudo tar xvf solr_for_audit_setup_v3.tgz
cd /usr/local/solr_for_audit_setup
sudo mv install.properties install.properties.org

sudo tee install.properties > /dev/null <<EOF
#!/bin/bash
JAVA_HOME=$JAVA_HOME
SOLR_USER=solr
SOLR_INSTALL=false
SOLR_INSTALL_FOLDER=/opt/lucidworks-hdpsearch/solr
SOLR_RANGER_HOME=/opt/ranger_audit_server
SOLR_RANGER_PORT=6083
SOLR_DEPLOYMENT=solrcloud
SOLR_ZK=localhost:2181/ranger_audits
SOLR_HOST_URL=http://$host:\${SOLR_RANGER_PORT}
SOLR_SHARDS=1
SOLR_REPLICATION=2
SOLR_LOG_FOLDER=/var/log/solr/ranger_audits
SOLR_MAX_MEM=1g
EOF
sudo ./setup.sh

# create ZK dir - only needs to be run from one of the Solr nodes
sudo /opt/ranger_audit_server/scripts/add_ranger_audits_conf_to_zk.sh

# if you installed Solr via Ambari, skip this step that starts solr 
# otherwise, run on each Solr node to start it in Cloud mode
sudo /opt/ranger_audit_server/scripts/start_solr.sh

# create collection - only needs to be run from one of the Solr nodes
sudo sed -i 's,^SOLR_HOST_URL=.*,SOLR_HOST_URL=http://localhost:6083,' \
   /opt/ranger_audit_server/scripts/create_ranger_audits_collection.sh
sudo /opt/ranger_audit_server/scripts/create_ranger_audits_collection.sh 

```

- Now you should access Solr webui at http://publicIP:6083/solr
  - Click the Cloud > Graph tab to find the leader host (172.30.0.242 in below example)
  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/solr-cloud.png)   

- (Optional) - On the leader node, install SILK (banana) dashboard to visualize audits in Solr
```
sudo wget https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/scripts/default.json -O /opt/lucidworks-hdpsearch/solr/server/solr-webapp/webapp/banana/app/dashboards/default.json
export host=$(curl -4 icanhazip.com)
# replace host/port in this line::: "server": "http://sandbox.hortonworks.com:6083/solr/",
sudo sed -i "s,sandbox.hortonworks.com,$host," \
   /opt/lucidworks-hdpsearch/solr/server/solr-webapp/webapp/banana/app/dashboards/default.json
sudo chown solr:solr /opt/lucidworks-hdpsearch/solr/server/solr-webapp/webapp/banana/app/dashboards/default.json
# access banana dashboard at http://hostname:6083/solr/banana/index.html
```
- At this point you should be able to: 
  - access Solr webui at http://hostname:6083/solr
  - access banana dashboard (if installed earlier) at http://hostname:6083/solr/banana/index.html 
    - this will currently not have any audit data  


## Ranger install

##### Install Ranger via Ambari 2.2

- Using Amabris 'Add Service' wizard, install Ranger on any node you like. Set the below configs for below tabs:

1. Ranger Admin tab:
  - Ranger DB Host = FQDN of host where Mysql is running (e.g. ip-172-30-0-242.us-west-2.compute.internal)
  - Enter passwords
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-1.png)
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-2.png)

2. Ranger User info tab
  - 'Sync Source' = AD/LDAP 
  - Common configs subtab
    - Enter password
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-3.png)
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-3.5.png)

3. Ranger User info tab 
  - User configs subtab
    - User Search Base = `ou=CorpUsers,dc=lab,dc=hortonworks,dc=net`
    - User Search Filter = `(objectcategory=person)`
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-4.png)
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-5.png)

4. Ranger User info tab 
  - Group configs subtab
    - No changes needed
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-6.png)

5. Ranger plugins tab
  - Enable all plugins
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-7.png)

6. Ranger Audits tab 
  - SolrCloud = ON
  - enter password
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-8.png)
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-9.png)

7.Advanced tab
  - No changes needed
![Image](https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/screenshots/ranger-213-setup/ranger-213-10.png)

- On Configure Identities page, you will have to enter your AD admin credentials:
  - Admin principal: hadoopadmin@LAB.HORTONWORKS.NET
  - Admin password: BadPass#1
  
- Click Next > Deploy to install Ranger

- Once installed, restart components that require restart (e.g. HDFS, YARN, Hive etc)

- (Optional) In case of failure (usually caused by incorrectly entering the Mysql nodes FQDN in the config above), run below from Ambari node to delete the service so you can try again:
```
export SERVICE=RANGER
export AMBARI_HOST=localhost
export PASSWORD=BadPass#1
output=`curl -u hadoopadmin:$PASSWORD -i -H 'X-Requested-By: ambari'  http://localhost:8080/api/v1/clusters`
CLUSTER=`echo $output | sed -n 's/.*"cluster_name" : "\([^\"]*\)".*/\1/p'`

#attempt to unregister the service
curl -u admin:$PASSWORD -i -H 'X-Requested-By: ambari' -X DELETE http://$AMBARI_HOST:8080/api/v1/clusters/$CLUSTER/services/$SERVICE

#in case the unregister service resulted in 500 error, run the below first and then retry the unregister API
#curl -u admin:$PASSWORD -i -H 'X-Requested-By: ambari' -X PUT -d '{"RequestInfo": {"context" :"Stop $SERVICE via REST"}, "Body": {"ServiceInfo": {"state": "INSTALLED"}}}' http://$AMBARI_HOST:8080/api/v1/clusters/$CLUSTER/services/$SERVICE

sudo service ambari-server restart

#restart agents on all nodes
sudo service ambari-agent restart
```

##### Check Ranger

- Open Ranger UI at http://RANGERHOST_PUBLIC_IP:6080
- Confirm users/group sync from AD are working by clicking 'Settings' > 'Users/Groups tab' and noticing AD users/groups are present
- Confirm that repos for HDFS, YARN, Hive etc appear under 'Access Manager tab'
- Confirm that plugins for HDFS, YARN, Hive etc appear under 'Plugins' tab 
- Confirm that audits appear under 'Audit' tab
- Confirm HDFS audits working by querying the audits dir in HDFS:
```
sudo -u hdfs hdfs dfs -cat /ranger/audit/hdfs/*/*
```
- Confirm Solr audits working by querying Solr REST API
```
curl "http://localhost:6083/solr/ranger_audits/select?q=*%3A*&df=id&wt=csv"
```
- Confirm Banana dashboard has start to show HDFS audits
http://PUBLIC_IP_OF_BANANA_NODE:6083/solr/banana/index.html#/dashboard

## Ranger KMS/Data encryption setup


- Reference: [docs](http://docs.hortonworks.com/HDPDocuments/HDP2/HDP-2.3.4/bk_Ranger_KMS_Admin_Guide/content/ch_ranger_kms_overview.html):

- Open Ambari >> start 'Add service' wizard >> select 'Ranger KMS'.
- Keep the default configs except for below properties 
  - Advanced kms-properties
    - KMS_MASTER_KEY_PASSWORD = BadPass#1
    - REPOSIORY_CONFIG_USERNAME = keyadmin@LAB.HORTONWORKS.NET
    - REPOSIORY_CONFIG_PASSWORD = BadPass#1
    - db_host = Internal FQDN of MySQL node
    - db_password = BadPass#1
    - db_root_password = BadPass#1
  - advanced kms-site:
    - hadoop.kms.authentication.type=kerberos
    - hadoop.kms.authentication.kerberos.keytab=/etc/security/keytabs/spnego.service.keytab
    - hadoop.kms.authentication.kerberos.principal=*  
    
  - Custom kms-site (to avoid adding one at a time, you can use 'bulk add' mode):
      - hadoop.kms.proxyuser.hive.users=*
      - hadoop.kms.proxyuser.oozie.users=*
      - hadoop.kms.proxyuser.HTTP.users=*
      - hadoop.kms.proxyuser.ambari.users=*
      - hadoop.kms.proxyuser.yarn.users=*
      - hadoop.kms.proxyuser.hive.hosts=*
      - hadoop.kms.proxyuser.oozie.hosts=*
      - hadoop.kms.proxyuser.HTTP.hosts=*
      - hadoop.kms.proxyuser.ambari.hosts=*
      - hadoop.kms.proxyuser.yarn.hosts=*    
      - hadoop.kms.proxyuser.keyadmin.groups=*
      - hadoop.kms.proxyuser.keyadmin.hosts=*
      - hadoop.kms.proxyuser.keyadmin.users=*      
      
  - Advanced ranger-kms-audit:
    - Audit to Solr
    - Audit to HDFS
    - For xasecure.audit.destination.hdfs.dir, replace NAMENODE_HOSTNAME with FQDN of host where name node is running e.g.
      - xasecure.audit.destination.hdfs.dir = hdfs://ip-172-30-0-185.us-west-2.compute.internal:8020/ranger/audit

- Click Next to proceed with the wizard

- On Configure Identities page, you will have to enter your AD admin credentials:
  - Admin principal: hadoopadmin@LAB.HORTONWORKS.NET
  - Admin password: BadPass#1
  
- Click Next > Deploy to install RangerKMS
        
- Restart Ranger and RangerKMS via Ambari (hold off on restarting HDFS for now)

- On RangerKMS node, create symlink to core-site.xml
```
sudo ln -s /etc/hadoop/conf/core-site.xml /etc/ranger/kms/conf/core-site.xml
```

- Confirm these properties got populated to kms://http@<kmshostname>:9292/kms
  - HDFS > Configs > Advanced core-site:
    - hadoop.security.key.provider.path
  - HDFS > Configs > Advanced hdfs-site:
    - dfs.encryption.key.provider.uri  
    
- Set the KMS proxy user
  - HDFS > Configs > Custom core-site:
    - hadoop.proxyuser.kms.groups = *   

- Restart the HDFS and Ranger and RangerKMS service.


## Ranger KMS/Data encryption exercise

- Login to Ranger as admin/admin and 
  - add hadoopadmin to global HDFS policy     
  - create new user nn
    - Settings > Users/Groups > Add new user
      - username = nn
      - password = BadPass#1
      - First name = namenode
      - Role: User
      - Group: hadoop-admins
- Logout of Ranger
  - Top right > admin > Logout      
- Login to Ranger as keyadmin/keyadmin
- Confirm the KMS repo was setup correctly
  - Under Service Manager > KMS > Click the Edit icon (next to the trash icon)
  - Click 'Test connection' 
  - if it fails re-enter below fields and re-try:
    - Username: keyadmin@LAB.HORTONWORKS.NET
    - Password: BadPass#1
  - Click Save  
- Create a key called testkey - see [doc](http://docs.hortonworks.com/HDPDocuments/HDP2/HDP-2.3.4/bk_Ranger_KMS_Admin_Guide/content/ch_use_ranger_kms.html)
  - Select Encryption > Key Manager
  - Select KMS service > pick your kms > Add new Key
    - if an error is thrown, go back and test connection as described in previous step
  - Create a key called `testkey` > Save
  
- Add user hadoopadmin and nn to default key policy
  - Click Access Manager tab
  - Click Service Manager > KMS > (clustername)_kms link
  - Edit the default policy
  - Under 'Select User', Add hadoopadmin and nn users
  - click Save
  
  
- Run below to create a zone using the key and perform basic exercises 
```

#run kinit as different users: hdfs, hadoopadmin, sales1

export PASSWORD=BadPass#1

#detect name of cluster
output=`curl -u hadoopadmin:$PASSWORD -i -H 'X-Requested-By: ambari'  http://localhost:8080/api/v1/clusters`
cluster=`echo $output | sed -n 's/.*"cluster_name" : "\([^\"]*\)".*/\1/p'`

#then kinit using the keytab and the principal name
sudo -u hdfs kinit -kt /etc/security/keytabs/hdfs.headless.keytab hdfs-${cluster}

#kinit as hadoopadmin and sales using BadPass#1 
sudo -u hadoopadmin kinit
sudo -u sales1 kinit

#as hadoopadmin create dir
sudo -u hadoopadmin hdfs dfs -mkdir /zone_encr

#as hdfs create/list EZ
sudo -u hdfs hdfs crypto -createZone -keyName testkey -path /zone_encr
# if you get 'RemoteException' error it means you have not given namenode user permissions on testkey by creating a policy for KMS in Ranger

#check it got created
sudo -u hdfs hdfs crypto -listZones  

#create test file
sudo -u hadoopadmin echo "My test file1" > /tmp/test1.log
sudo -u hadoopadmin echo "My test file2" > /tmp/test2.log

#copy file to EZ
sudo -u hadoopadmin hdfs dfs -copyFromLocal /tmp/test1.log /zone_encr
sudo -u hadoopadmin hdfs dfs -copyFromLocal /tmp/test2.log /zone_encr

#Notice that hadoopadmin allowed to decrypt EEK but not sales user
sudo -u hadoopadmin hdfs dfs -cat /zone_encr/test1.log
#this should work

sudo -u sales1      hdfs dfs -cat /zone_encr/test1.log
## this should give you below error
## cat: User:sales1 not allowed to do 'DECRYPT_EEK' on 'testkey'

#delete a file from EZ - note the skipTrash option
sudo -u hadoopadmin hdfs dfs -rm -skipTrash /zone_encr/test2.log

#View contents of raw file in encrypted zone as hdfs super user. This should show some encrypted chacaters
sudo -u hdfs hdfs dfs -cat /.reserved/raw/zone_encr/test1.log

#Prevent user hdfs from reading the file by setting security.hdfs.unreadable.by.superuser attribute. Note that this attribute can only be set on files and can never be removed.
sudo -u hdfs hdfs dfs -setfattr -n security.hdfs.unreadable.by.superuser  /.reserved/raw/zone_encr/test1.log

# Now as hdfs super user, try to read the files or the contents of the raw file
sudo -u hdfs hdfs dfs -cat /.reserved/raw/zone_encr/test1.log

## You should get below error
##cat: Access is denied for hdfs since the superuser is not allowed to perform this operation.

```

#### HDFS Exercise

Simple exercise to show why to set dir permission to 000 for dirs whose authorization is to be managed be Ranger

- Import data
```
cd /tmp
wget https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/data/sample_07.csv
wget https://raw.githubusercontent.com/abajwa-hw/security-workshops/master/data/sample_08.csv
```
  - Create user dir for admin
  ```
   sudo -u hdfs hadoop fs  -mkdir /user/admin
   sudo -u hdfs hadoop fs  -chown admin:hadoop /user/admin

   sudo -u hdfs hadoop fs  -mkdir /user/sales1
   sudo -u hdfs hadoop fs  -chown sales1:hadoop /user/sales1
   
sudo -u hdfs hadoop fs  -mkdir /user/sales2
sudo -u hdfs hadoop fs  -chown sales2:hadoop /user/sales2
  ```
  
  - Now login to ambari as admin and run this via Hive view
```
CREATE TABLE `sample_07` (
`code` string ,
`description` string ,  
`total_emp` int ,  
`salary` int )
ROW FORMAT DELIMITED FIELDS TERMINATED BY '\t' STORED AS TextFile;

load data local inpath '/tmp/sample_07.csv' into table sample_07;


CREATE TABLE `sample_08` (
`code` string ,
`description` string ,  
`total_emp` int ,  
`salary` int )
ROW FORMAT DELIMITED FIELDS TERMINATED BY '\t' STORED AS TextFile;

load data local inpath '/tmp/sample_08.csv' into table sample_08;

```


- Create a file as sales1 
```
su - sales1
kinit
hdfs dfs -put /tmp/sample_07.csv /user/sales1
exit
```
- Access it as sales2
```
su - sales2
kinit
hdfs dfs -cat /user/sales1/sample_07.csv
```
- Notice that it works 

- Login to Ranger as admin/admin > Audit > check the audit for the event above

```
#still  as sales2
hdfs dfs -ls /user/sales1
```
- Notice that everyone has read permissions on this file
- Login to Ambari as admin. Under HDFS > Configs > Set below and restart HDFS
  - fs.permissions.umask-mode = 077
  
- Add a second file into the same dir after changing the umask
```
su - sales1
hdfs dfs -put /tmp/sample_08.csv /user/sales1
```

- Try to access it as sales2: this should fail now with `Permission denied` and permissions should reflect it
```
su - sales2
hdfs dfs -cat /user/sales1/sample_08.csv
hdfs dfs -ls /user/sales1
```
- Recommendation for application files in HDFS. e.g.
```
hdfs dfs -chown -R hdfs /apps/hive/warehouse
hdfs dfs -chmod -R 000 /apps/hive/warehouse
```


## Other Security features for Ambari

- Setup views: http://docs.hortonworks.com/HDPDocuments/Ambari-2.1.2.0/bk_ambari_views_guide/content/ch_configuring_views_for_kerberos.html
  - Automation to install views
```
sudo git clone https://github.com/seanorama/ambari-bootstrap
cd ambari-bootstrap/extras/
export ambari_pass=BadPass#1
source ambari_functions.sh
sudo ./ambari-views/create-views.sh
```

## Day 3

Agenda:
1. Architechture
2. Wire encryption overview
  - http://docs.hortonworks.com/HDPDocuments/HDP2/HDP-2.2.0/Wire_Encryption_v22/index.html#Item1.1
3. Knox/AD
4. Ranger KMS
5. Security training flow review
6. Roadmap/next steps
7. SME rules of engagement
  - Enabling regions
  - Contributing to training team
8. Ranger Logo


## Knox 
- Run these steps on the node where Knox was installed earlier
- Create keystore alias for the ldap manager user (which you set in 'systemUsername' in the topology) e.g. BadPass#1
   - Read password for use in following command (this will prompt you for a password and save it in knoxpass environment variable):
   ```
   read -s -p "Password: " knoxpass
   ```
  - This is a handy way to set an env var without storing the command in your history

   - Create password alias for Knox called knoxLdapSystemPassword
   ```
   sudo sudo -u knox /usr/hdp/current/knox-server/bin/knoxcli.sh create-alias knoxLdapSystemPassword --cluster default --value ${knoxpass}
   unset knoxpass
   ```
- Tell Hadoop to allow our users to access Knox from any node of the cluster. Make the below change in Ambari > HDFS > Config > Custom core-site 
  - hadoop.proxyuser.knox.groups=users,hadoop-admins,sales,hr,legal
  - hadoop.proxyuser.knox.hosts=*
    - (better would be to put a comma separated list of the FQDNs of the hosts)
  - Now restart HDFS
  
- Now lets configure Knox to use our AD for authentication. Replace below content in Ambari > Knox > Config > Advanced topology. Then restart Knox
  - How to tell what configs were changed from defaults? 
    - Default configs remain indented below
    - Configurations that were added/modified are not indented
```
        <topology>

            <gateway>

                <provider>
                    <role>authentication</role>
                    <name>ShiroProvider</name>
                    <enabled>true</enabled>
                    <param>
                        <name>sessionTimeout</name>
                        <value>30</value>
                    </param>
                    <param>
                        <name>main.ldapRealm</name>
                        <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm</value> 
                    </param>

<!-- changes for AD/user sync -->

<param>
    <name>main.ldapContextFactory</name>
    <value>org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory</value>
</param>

<!-- main.ldapRealm.contextFactory needs to be placed before other main.ldapRealm.contextFactory* entries  -->
<param>
    <name>main.ldapRealm.contextFactory</name>
    <value>$ldapContextFactory</value>
</param>

<!-- AD url -->
<param>
    <name>main.ldapRealm.contextFactory.url</name>
    <value>ldap://ad01.lab.hortonworks.net:389</value> 
</param>

<!-- system user -->
<param>
    <name>main.ldapRealm.contextFactory.systemUsername</name>
    <value>cn=ldap-reader,ou=ServiceUsers,dc=lab,dc=hortonworks,dc=net</value>
</param>

<!-- pass in the password using the alias created earlier -->
<param>
    <name>main.ldapRealm.contextFactory.systemPassword</name>
    <value>${ALIAS=knoxLdapSystemPassword}</value>
</param>

                    <param>
                        <name>main.ldapRealm.contextFactory.authenticationMechanism</name>
                        <value>simple</value>
                    </param>
                    <param>
                        <name>urls./**</name>
                        <value>authcBasic</value> 
                    </param>

<!--  AD groups of users to allow -->
<param>
    <name>main.ldapRealm.searchBase</name>
    <value>ou=CorpUsers,dc=lab,dc=hortonworks,dc=net</value>
</param>
<param>
    <name>main.ldapRealm.userObjectClass</name>
    <value>person</value>
</param>
<param>
    <name>main.ldapRealm.userSearchAttributeName</name>
    <value>sAMAccountName</value>
</param>

<!-- changes needed for group sync-->
<param>
    <name>main.ldapRealm.authorizationEnabled</name>
    <value>true</value>
</param>
<param>
    <name>main.ldapRealm.groupSearchBase</name>
    <value>ou=CorpUsers,dc=lab,dc=hortonworks,dc=net</value>
</param>
<param>
    <name>main.ldapRealm.groupObjectClass</name>
    <value>group</value>
</param>
<param>
    <name>main.ldapRealm.groupIdAttribute</name>
    <value>cn</value>
</param>


                </provider>

                <provider>
                    <role>identity-assertion</role>
                    <name>Default</name>
                    <enabled>true</enabled>
                </provider>

                <provider>
                    <role>authorization</role>
                    <name>XASecurePDPKnox</name>
                    <enabled>true</enabled>
                </provider>

            </gateway>

            <service>
                <role>NAMENODE</role>
                <url>hdfs://{{namenode_host}}:{{namenode_rpc_port}}</url>
            </service>

            <service>
                <role>JOBTRACKER</role>
                <url>rpc://{{rm_host}}:{{jt_rpc_port}}</url>
            </service>

            <service>
                <role>WEBHDFS</role>
                <url>http://{{namenode_host}}:{{namenode_http_port}}/webhdfs</url>
            </service>

            <service>
                <role>WEBHCAT</role>
                <url>http://{{webhcat_server_host}}:{{templeton_port}}/templeton</url>
            </service>

            <service>
                <role>OOZIE</role>
                <url>http://{{oozie_server_host}}:{{oozie_server_port}}/oozie</url>
            </service>

            <service>
                <role>WEBHBASE</role>
                <url>http://{{hbase_master_host}}:{{hbase_master_port}}</url>
            </service>

            <service>
                <role>HIVE</role>
                <url>http://{{hive_server_host}}:{{hive_http_port}}/{{hive_http_path}}</url>
            </service>

            <service>
                <role>RESOURCEMANAGER</role>
                <url>http://{{rm_host}}:{{rm_port}}/ws</url>
            </service>
        </topology>
```

- Setup a Knox policy for sales group for WEBHDFS by:
- Login to Ranger > Access Manager > KNOX > click the cluster name link > Add new policy
  - Policy name: webhdfs
  - Topology name: default
  - Service name: WEBHDFS
  - Group permissions: sales 
  - Permission: check Allow
  - Add

  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/Ranger-knox-webhdfs-policy.png)


- Now ensure WebHDFS working by opening terminal to host where Knox is running by sending curl request to 8443 port where Knox is running:
```
curl -ik -u sales1:BadPass#1 https://localhost:8443/gateway/default/webhdfs/v1/?op=LISTSTATUS
```

- Try the same request as hr1 and notice it fails with `Error 403 Forbidden` :
  - This is expected since in the policy above, we only allowed sales group to access WebHDFS over Knox
```
curl -ik -u sales1:BadPass#1 https://localhost:8443/gateway/default/webhdfs/v1/?op=LISTSTATUS
```

- Check in Ranger Audits to confirm the requests were audited:
  - Ranger > Audit > Service type: KNOX

  ![Image](https://raw.githubusercontent.com/seanorama/masterclass/master/security-advanced/screenshots/Ranger-knox-webhdfs-audit.png)



## Appendix

##### Install Ranger via Ambari 2.1.2 (current GA version)

1. Install Ranger using Amabris 'Add Service' wizard on the same node as MySQL. 
  - Ranger Admin
    - Ranger DB Host: mysqlnodeinternalhostname.us-west-2.compute.internal 
    - passwords


  - External URL: http://mysqlinternalhostname.compute.internal:6080
  - ranger-admin-site: 
    - ranger.audit.source.type solr
    - ranger.audit.solr.urls http://localhost:6083/solr/ranger_audits

**TODO** Need to fix focs for getting ranger.audit.solr.zookeepers working. For now don't change this property

##### Setup Ranger/AD user/group sync

1. Once Ranger is up, under Ambari > Ranger > Config, set the below and restart Ranger to sync AD users/groups
```
ranger.usersync.source.impl.class ldap
ranger.usersync.ldap.searchBase dc=lab,dc=hortonworks,dc=net
ranger.usersync.ldap.user.searchbase dc=lab,dc=hortonworks,dc=net
ranger.usersync.group.searchbase dc=lab,dc=hortonworks,dc=net
ranger.usersync.ldap.binddn cn=ldap-reader,ou=ServiceUsers,ou=lab,dc=hortonworks,dc=net
ranger.usersync.ldap.ldapbindpassword BadPass#1
ranger.usersync.ldap.url ldap://ad01.lab.hortonworks.net
ranger.usersync.ldap.user.nameattribute sAMAccountName
ranger.usersync.ldap.user.searchfilter (objectcategory=person)
ranger.usersync.ldap.user.groupnameattribute memberof, ismemberof, msSFU30PosixMemberOf
ranger.usersync.group.memberattributename member
ranger.usersync.group.nameattribute cn
ranger.usersync.group.objectclass group
```
2. Check the usersyc log and Ranger UI if users/groups got synced
```
tail -f /var/log/ranger/usersync/usersync.log
```

##### Setup Ranger/AD auth

1. Enable AD users to login to Ranger by making below changes in Ambari > Ranger > Config > ranger-admin-site
```
ranger.authentication.method ACTIVE_DIRECTORY
ranger.ldap.ad.domain lab.hortonworks.net
ranger.ldap.ad.url "ldap://ad01.lab.hortonworks.net:389"
ranger.ldap.ad.base.dn "dc=lab,dc=hortonworks,dc=net"
ranger.ldap.ad.bind.dn "cn=ldap-reader,ou=ServiceUsers,ou=lab,dc=hortonworks,dc=net"
ranger.ldap.ad.referral follow
ranger.ldap.ad.bind.password "BadPass#1"
```

##### Setup Ranger HDFS plugin

In Ambari > HDFS > Config > ranger-hdfs-audit:
```
xasecure.audit.provider.summary.enabled true
xasecure.audit.destination.hdfs.dir hdfs://yournamenodehostname:8020/ranger/audit
xasecure.audit.destination.db true
xasecure.audit.destination.hdfs true
xasecure.audit.destination.solr true
xasecure.audit.is.enabled true
```
**TODO** Need to update docs on xasecure.audit.destination.solr.zookeepers. For now don't change this property

In Ambari > HDFS > Config > ranger-hdfs-plugin-properties:
```
ranger-hdfs-plugin-enabled Yes
REPOSITORY_CONFIG_USERNAME "rangeradmin@lab.hortonworks.net"
REPOSITORY_CONFIG_PASSWORD "BadPass#1"
policy_user "rangeradmin"
common.name.for.certificate " "
hadoop.rpc.protection " "
```

##### Setup Ranger Hive plugin

- In Ambari > HIVE > Config > Settings
  - Under Security > 'Choose authorization' > Ranger
- In Ambari > HIVE > Config > Advanced > ranger-hdfs-audit
```
xasecure.audit.provider.summary.enabled true
xasecure.audit.destination.hdfs.dir hdfs://yournamenodehostname:8020/ranger/audit
xasecure.audit.destination.db true
xasecure.audit.destination.hdfs true
xasecure.audit.destination.solr true
xasecure.audit.is.enabled true
```
- In Ambari > Hive > Config > ranger-hive-plugin-properties:
```
ranger-hdfs-plugin-enabled Yes
REPOSITORY_CONFIG_USERNAME "rangeradmin@lab.hortonworks.net"
REPOSITORY_CONFIG_PASSWORD "BadPass#1"
policy_user "rangeradmin"
common.name.for.certificate " "
hadoop.rpc.protection " "
```
