# HDF 3.0 Active Directory Lab guide

## Install HDF 3.0 (plus Druid)

- First decide which node will be ambari-server

- Run on non-amabri nodes to install agents
```
export ambari_server=ip-172-30-0-206.us-west-2.compute.internal
curl -sSL https://raw.githubusercontent.com/seanorama/ambari-bootstrap/master/ambari-bootstrap.sh | sudo -E sh
```

- run on ambari node to install ambari-server
```
export install_ambari_server=true
curl -sSL https://raw.githubusercontent.com/seanorama/ambari-bootstrap/master/ambari-bootstrap.sh | sudo -E sh
```

- run remaining steps on ambari-server node

- install 
```
sudo yum localinstall -y https://dev.mysql.com/get/mysql57-community-release-el7-8.noarch.rpm
sudo yum install -y git python-argparse epel-release mysql-connector-java* mysql-community-server

# MySQL Setup to keep the new services separate from the originals
echo Database setup...
sudo systemctl enable mysqld.service
sudo systemctl start mysqld.service
```

- Run below to:
  - 1. reset Mysql password to temp value and create druid/superset/registry/streamline schemas and users
  - 2. sets passwords for druid/superset/registry/streamline users to StrongPassword
```
#extract system generated Mysql password
oldpass=$( grep 'temporary.*root@localhost' /var/log/mysqld.log | tail -n 1 | sed 's/.*root@localhost: //' )

#create sql file 
cat << EOF > mysql-setup.sql
ALTER USER 'root'@'localhost' IDENTIFIED BY 'Secur1ty!'; 
uninstall plugin validate_password;
CREATE DATABASE druid DEFAULT CHARACTER SET utf8; CREATE DATABASE superset DEFAULT CHARACTER SET utf8; CREATE DATABASE registry DEFAULT CHARACTER SET utf8; CREATE DATABASE streamline DEFAULT CHARACTER SET utf8; 
CREATE USER 'druid'@'%' IDENTIFIED BY 'StrongPassword'; CREATE USER 'superset'@'%' IDENTIFIED BY 'StrongPassword'; CREATE USER 'registry'@'%' IDENTIFIED BY 'StrongPassword'; CREATE USER 'streamline'@'%' IDENTIFIED BY 'StrongPassword'; 
GRANT ALL PRIVILEGES ON *.* TO 'druid'@'%' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON *.* TO 'superset'@'%' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON registry.* TO 'registry'@'%' WITH GRANT OPTION ; GRANT ALL PRIVILEGES ON streamline.* TO 'streamline'@'%' WITH GRANT OPTION ; 
commit; 
EOF

#run sql file
mysql -h localhost -u root -p"$oldpass" --connect-expired-password < mysql-setup.sql
```

- change Mysql password to StrongPassword
```
mysqladmin -u root -p'Secur1ty!' password StrongPassword

#test password and confirm dbs created
mysql -u root -pStrongPassword -e 'show databases;'

```

- Install mysql jar and HDF mpack and restart 
```
sudo ambari-server setup --jdbc-db=mysql --jdbc-driver=/usr/share/java/mysql-connector-java.jar
sudo ambari-server install-mpack --verbose --mpack=http://public-repo-1.hortonworks.com/HDF/centos7/3.x/updates/3.0.0.0/tars/hdf_ambari_mp/hdf-ambari-mpack-3.0.0.0-453.tar.gz
sudo ambari-server restart
```

- wait 30s then open ambari UI via browser on port 8080





- Screenshots
- Click Install Wizard
![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step1.png)

- clustername: hdf3
![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step2.png)

- Select Version
  - Click Next
![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step3.png)

- Add Services
  - select Storm, Kafka, NiFi, Registry, Streaming Analytics Manager, Druid
  
- Assign masters
  - keep SAM/registry/Druid on Ambari node (where Mysql was installed)
  - move Storm, Smartsense, Metrics related to seperate nodes 
  - add nifi on all nodes
![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step5.png)

- Assign slaves
  - keep default clients
![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step6.png)

- Customize Services (see screenshots below): 
  - Password/Secrets are 'StrongPassword' for all services
  - All Database types are MySql; 
  - All hostnames are FDQDN of node where mysql was installed (ambari node)
  - All mysql ports are 3306; 


  - AMS: replace password with StrongPassword
  - ![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step7-a.png)

  - Smartsense: replace password with StrongPassword
  - ![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step7-b.png)
  
  - Nifi: replace passwords with StrongPassword  
  - ![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step7-f.png)
  
  - In Schema registry
    - All Database types are MySql; 
    - All hostnames are FDQDN of node where mysql was installed (ambari node)
    - All mysql ports are 3306; 
  - ![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step7-g.png)
  - In SAM
    - All Database types are MySql; 
    - All hostnames are FDQDN of node where mysql was installed (ambari node)
    - All mysql ports are 3306; 
    - update streamline.dashboard.url to http://MYSQL_FQDN:9089  
    - update registry.url to http://MYSQL_FQDN:7788/api/v1; 
  - ![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step7-h.png)

  - Druid
    - All Database types are MySql; 
    - All hostnames are FDQDN of node where mysql was installed (ambari node)
    - All mysql ports are 3306;   
    - Change SUPERSET_WEBSERVER_PORT from 9088 to 9089
    - druid.storage.storageDirectory = /user/druid/data
    - druid.storage.type = local
    - Superset: email: a@b.c, firstname: admin, lastname: jones; 

  - ![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step7-i.png)
  - ![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step7-d.png)
  - ![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-step7-e.png)  

- Click deploy and wait until services installed 
![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/install-complete.png)


## Enable SSL for Nifi

![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/nifi-ssl-1.png)
![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/hdf3/nifi-ssl-2.png)

- Restart Nifi and wait for services to come up
