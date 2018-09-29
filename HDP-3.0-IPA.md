
## Rough instuctions for IPA Lab 

### Register cluster as IPA client
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

- To uninstall in case of issues:
```
sudo ipa-client-install --uninstall
```

- Note by changing the DNS, its possible the node may not be able to connect to public internet. When you need to do so (e.g. for yum install, you can temporarily revert back the /etc/resolv.conf.bak)


## Test

- By registering as a client of the IPA server, SSSD is automatically setup. So now the host recognizes users defined in IPA
```
id hadoopadmin
```

- You can also authenticate and get a kerberos ticket (password is BadPass#1)
```
kinit -V hadoopadmin
```

## Enable kerberos on the cluster

![Image](https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/screenshots/IPA-SecurityWizard.png)
  
