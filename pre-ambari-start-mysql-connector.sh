#!/bin/bash

#pre-ambari-start recipe to ensure that mysql client is installed on Ambari server for distribution to other node types

sudo yum install mysql-connector-java* -y
sudo ambari-server setup --jdbc-db=mysql --jdbc-driver=/usr/share/java/mysql-connector-java.jar
