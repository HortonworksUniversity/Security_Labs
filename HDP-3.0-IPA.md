
## Rough instuctions for IPA Lab 

- Run below on all nodes of HDP cluster (replace INTERNAL_IP_OF_IPA)
```
echo "INTERNAL_IP_OF_IPA ipa.hortonworks.com ipa" >> /etc/hosts
```

- Update /etc/resolve.conf
```
mv /etc/resolv.conf /etc/resolv.conf.bak (replace INTERNAL_IP_OF_IPA)
echo "search hortonworks.com" > /etc/resolv.conf
echo "nameserver INTERNAL_IP_OF_IPA" >> /etc/resolv.conf
```
- Install IPA client
```
sudo yum install ipa-client
sudo ipa-client-install \
--server=ipa.hortonworks.com \
--realm=HORTONWORKS.COM \
--domain=hortonworks.com \
--mkhomedir \
--principal=admin -w BadPass#1 \
--unattended

```
