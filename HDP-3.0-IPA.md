
## Rough instuctions for IPA Lab 

- Run below on all nodes of HDP cluster (replace INTERNAL_IP_OF_IPA)
```
echo "INTERNAL_IP_OF_IPA ipa.hortonworks.com" >> /etc/hosts
```

```
sudo yum install ipa-client
sudo ipa-client-install \
--server=ipa.hortonworks.com \
--realm=HORTONWORKS.COM \
--domain=hortonworks.com \
--mkhomedir \
--principal=admin -password BadPass#1 \
--unattended

```
