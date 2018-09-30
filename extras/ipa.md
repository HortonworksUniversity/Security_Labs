## FreeIPA setup

### Sample script to setup FreeIPA on CentOS 7 on AWS

Based on steps [here](https://www.evernote.com/client/snv?noteGuid=f7eed2f9-5255-4f7c-b0d8-ecee1dba3c9f&noteKey=d2b6e968a783fd5e&var=b&sn=https%3A%2F%2Fwww.evernote.com%2Fshard%2Fs337%2Fsh%2Ff7eed2f9-5255-4f7c-b0d8-ecee1dba3c9f%2Fd2b6e968a783fd5e&exp=ENB3538), official docs [here](https://docs.hortonworks.com/HDPDocuments/HDP3/HDP-3.0.1/authentication-with-kerberos/content/kerberos_optional_use_an_existing_ipa.html)

```

#set name of instance to ipa.hortonworks.com
export vm_name=ipa
curl -sSL https://gist.github.com/abajwa-hw/9d7d06b8d0abf705ae311393d2ecdeec/raw | sudo -E sh

hostname -f
cat /etc/hosts

IP=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
echo "IP is ${IP}"

#install packages
sudo yum install ipa-server ipa-server-dns -y

#increase entropy
cat /proc/sys/kernel/random/entropy_avail
sudo yum install -y rng-tools
sudo systemctl start rngd
cat /proc/sys/kernel/random/entropy_avail

#sometimes needed to avoid server install failing
service dbus restart

#sudo ipa-server-install \
#--realm HORTONWORKS.COM --domain hortonworks.com \
#-a BadPass#1 -p BadPass#1 --unattended
#ipa-server-install --uninstall

#install IPA server
sudo ipa-server-install \
--realm HORTONWORKS.COM --domain hortonworks.com \
-a BadPass#1 -p BadPass#1 \
--setup-dns \
--forwarder=8.8.8.8 --allow-zone-overlap --no-host-dns \
--auto-forwarders --auto-reverse --unattended

#kinit as admin
echo BadPass#1 | kinit admin

# create a new principal to be used for ambari kerberos administration
ipa user-add hadoopadmin --first=Hadoop --last=Admin --shell=/bin/bash


# create a new principal to be used for read only ldab bind (whose password will expire in 90 days)
ipa user-add ldapbind --first=ldap --last=bind

# create a role and and give it privilege to manage users and services
ipa role-add hadoopadminrole 
ipa role-add-privilege hadoopadminrole --privileges="User Administrators" 
ipa role-add-privilege hadoopadminrole --privileges="Service Administrators"

#create users/groups
ipa group-add analyst --desc analyst
ipa group-add hr --desc hr
ipa group-add legal --desc legal
ipa group-add sales --desc sales
ipa group-add etl --desc etl
ipa group-add us_employee --desc us_employee
ipa group-add eu_employee --desc eu_employee
ipa group-add intern --desc intern
ipa group-add sudoers --desc sudoers

ipa user-add legal1 --first=legal1 --last=legal1 --shell=/bin/bash
ipa user-add legal2 --first=legal2 --last=legal2 --shell=/bin/bash
ipa user-add legal3 --first=legal3 --last=legal3 --shell=/bin/bash
ipa user-add hr1 --first=hr1 --last=hr1 --shell=/bin/bash
ipa user-add hr2 --first=hr2 --last=hr2 --shell=/bin/bash
ipa user-add hr3 --first=hr3 --last=hr3 --shell=/bin/bash
ipa user-add sales1 --first=sales1 --last=sales1 --shell=/bin/bash
ipa user-add sales2 --first=sales2 --last=sales2 --shell=/bin/bash
ipa user-add sales3 --first=sales3 --last=sales3 --shell=/bin/bash
ipa user-add joe_analyst --first=joe --last=analyst --shell=/bin/bash
ipa user-add ivanna_eu_hr --first=ivanna --last=hr --shell=/bin/bash
ipa user-add scott_intern --first=scott --last=intern --shell=/bin/bash
ipa user-add noobie --first=jon --last=snow --shell=/bin/bash

ipa group-add-member legal --users=legal1
ipa group-add-member legal --users=legal2
ipa group-add-member legal --users=legal3

ipa group-add-member hr --users=hr1
ipa group-add-member hr --users=hr2
ipa group-add-member hr --users=hr3
ipa group-add-member hr --users=ivanna_eu_hr

ipa group-add-member sales --users=sales1
ipa group-add-member sales --users=sales2
ipa group-add-member sales --users=sales3

ipa group-add-member analyst --users=joe_analyst
ipa group-add-member intern --users=scott_intern
ipa group-add-member us_employee --users=joe_analyst
ipa group-add-member eu_employee --users=ivanna_eu_hr

# create sudo rule
ipa sudorule-add admin_all_rule
ipa sudorule-mod admin_all_rule --cmdcat=all --hostcat=all
ipa sudorule-add-user admin_all_rule --groups=sudoers

# add noobie to the sudoers user, to enable sudo rules
ipa group-add-member sudoers --users=noobie


echo BadPass#1 > tmp.txt
echo BadPass#1 >> tmp.txt


ipa passwd hadoopadmin < tmp.txt
ipa passwd ldapbind < tmp.txt

ipa passwd legal1 < tmp.txt
ipa passwd legal2 < tmp.txt
ipa passwd legal3 < tmp.txt
ipa passwd hr1 < tmp.txt
ipa passwd hr2 < tmp.txt
ipa passwd hr3 < tmp.txt
ipa passwd sales1 < tmp.txt
ipa passwd sales2 < tmp.txt
ipa passwd sales3 < tmp.txt

ipa passwd joe_analyst < tmp.txt
ipa passwd ivanna_eu_hr < tmp.txt
ipa passwd scott_intern < tmp.txt

rm -f tmp.txt

```
