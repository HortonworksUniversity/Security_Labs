
## Rough instuctions for IPA Lab 

- Run below on all nodes of HDP cluster (replace $INTERNAL_IP_OF_IPA)
```
echo "$INTERNAL_IP_OF_IPA ipa.hortonworks.com ipa" >> /etc/hosts
```

- Install yum packages
```
sudo yum install -y ipa-client
```

- Update /etc/resolve.conf (replace INTERNAL_IP_OF_IPA)
```
mv /etc/resolv.conf /etc/resolv.conf.bak 
echo "search hortonworks.com" > /etc/resolv.conf
echo "nameserver $INTERNAL_IP_OF_IPA" >> /etc/resolv.conf
```
- Install IPA client
```
service dbus restart

sudo ipa-client-install \
--server=ipa.hortonworks.com \
--realm=HORTONWORKS.COM \
--domain=hortonworks.com \
--mkhomedir \
--principal=admin -w BadPass#1 \
--unattended

```

- Make sure you don't see below message from the output of previous command
```
Missing A/AAAA record(s) for host demo.hortonworks.com
```

- Note by changing the DNS the node will not be able to connect to public internet. When you need to do so (e.g. for yum install, you can temporarily revert back the /etc/resolv.conf.bak)
