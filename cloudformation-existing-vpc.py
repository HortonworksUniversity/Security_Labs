#!/usr/bin/env python

# generates an AWS CloudFormation template for an
#   Apache Ambari & Hortonworks Data Platform cluster

import sys
import boto
import boto.cloudformation
import troposphere.ec2 as ec2
import troposphere.iam as iam
from troposphere import Base64, Select, FindInMap, GetAtt, Join
from troposphere import Template, Condition, Equals, And, Or, Not, If
from troposphere import Parameter, Ref, Tags, Output
from troposphere.autoscaling import LaunchConfiguration, AutoScalingGroup, Tag
from troposphere.policies import CreationPolicy, ResourceSignal
from troposphere.cloudformation import WaitCondition, WaitConditionHandle


# things you may want to change

# Don't touch these
ref_boot_disk_size = Ref('BootDiskSize')
ref_stack_id = Ref('AWS::StackId')
ref_region = Ref('AWS::Region')
ref_stack_name = Ref('AWS::StackName')
ref_ambariserver = GetAtt('AmbariNode',
                        'PrivateDnsName')
ref_java_provider = Ref('JavaProvider')
ref_java_version = Ref('JavaVersion')
ref_additional_instance_count = Ref('AdditionalInstanceCount')
ref_ambari_pass = Ref('AmbariPass')
ref_ambari_services = Ref('AmbariServices')
ref_deploy_cluster = Ref('DeployCluster')
ref_wait_ambari = Ref('waitHandleAmbari')

# now the work begins
t = Template()

t.add_version("2010-09-09")

t.add_description("""\
CloudFormation template to Deploy Hortonworks Data Platform on VPC with a public subnet""")

## Parameters

BootDiskSize = t.add_parameter(Parameter(
    "BootDiskSize",
    Type="Number",
    Default="80",
    MinValue=10,
    MaxValue=2000,
    Description="Size of boot disk.",
    ))

InstanceType = t.add_parameter(Parameter(
    "InstanceType",
    Default="m4.xlarge",
    ConstraintDescription="Must be a valid EC2 instance type.",
    Type="String",
    Description="Instance type for all hosts",
))



AmbariPass = t.add_parameter(Parameter(
    "AmbariPass",
    Type="String",
    Default="BadPass#1",
    NoEcho=True,
    MinLength=8,
    MaxLength=32,
    Description="Password for Ambari Server. Must be at least 8 characters containing letters, numbers and symbols",
    AllowedPattern="(?=^.{6,255}$)((?=.*\\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\\d)(?=.*[^A-Za-z0-9])(?=.*[a-z])|(?=.*[^A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z])|(?=.*\\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9]))^.*",
    ))


AmbariServices = t.add_parameter(Parameter(
    "AmbariServices",
    Type="String",
    Default="ACCUMULO AMBARI_METRICS FALCON FLUME HBASE HDFS HIVE KAFKA KNOX MAHOUT MAPREDUCE2 OOZIE PIG SLIDER SPARK SQOOP STORM TEZ YARN ZOOKEEPER",
    Description="HDP Services to deploy",
    ))


DeployCluster = t.add_parameter(Parameter(
    "DeployCluster",
    Type="String",
    Default="true",
    AllowedValues=['true','false'],
    Description="Deploy cluster with Ambari? If false, then Ambari is installed without cluster deployment.",
    ))


AdditionalInstanceCount = t.add_parameter(Parameter(
    "AdditionalInstanceCount",
    Default="2", Type="Number", MaxValue="99", MinValue="1",
    Description="Number of additional instances",
    ))

JavaProvider = t.add_parameter(Parameter(
    "JavaProvider",
    Default="open",
    Type="String",
    Description="Provider of Java packages: open or oracle",
    AllowedValues=['open','oracle'],
    ConstraintDescription="open or oracle",
))

JavaVersion = t.add_parameter(Parameter(
    "JavaVersion",
    Default="8",
    Type="String",
    Description="Version number of Java",
    AllowedValues=['7','8'],
    ConstraintDescription="7 or 8",
))

SubnetId = t.add_parameter(Parameter(
    "SubnetId",
    Description="SubnetId of an existing subnet (for the primary network) in "
                "your Virtual Private Cloud (VPC)" "access to the instance",
    Type="AWS::EC2::Subnet::Id",
))

SecurityGroups = t.add_parameter(Parameter(
    "SecurityGroups",
    Description="The Security Groups to launch the instance with",
    Type="List<AWS::EC2::SecurityGroup::Id>",
))

KeyName = t.add_parameter(Parameter(
    "KeyName",
    ConstraintDescription="Can contain only ASCII characters.",
    Type="AWS::EC2::KeyPair::KeyName",
    Description="Name of an existing EC2 KeyPair to enable SSH access to the instance",
))


t.add_mapping("CENTOS7", {
    "eu-west-1": {"AMI": "ami-33734044"},
    "ap-southeast-1": {"AMI": "ami-2a7b6b78"},
    "ap-southeast-2": {"AMI": "ami-d38dc6e9"},
    "eu-central-1": {"AMI": "ami-e68f82fb"},
    "ap-northeast-1": {"AMI": "ami-b80b6db8"},
    "us-east-1": {"AMI": "ami-61bbf104"},
    "sa-east-1": {"AMI": "ami-fd0197e0"},
    "us-west-1": {"AMI": "ami-f77fbeb3"},
    "us-west-2": {"AMI": "ami-d440a6e7"}
})



waitHandleAmbari = t.add_resource(WaitConditionHandle("waitHandleAmbari"))

waitConditionAmbari = t.add_resource(
    WaitCondition(
        "waitConditionAmbari",
        Handle=Ref(waitHandleAmbari),
        Timeout="2700",
    )
)

## Functions to generate blockdevicemappings
##   count: the number of devices to map
##   devicenamebase: "/dev/sd" or "/dev/xvd"
##   volumesize: "100"
##   volumetype: "gp2"
def my_block_device_mappings_root(devicenamebase,volumesize,volumetype):
    block_device_mappings_root = (ec2.BlockDeviceMapping(
        DeviceName=devicenamebase + "a1", Ebs=ec2.EBSBlockDevice(VolumeSize=volumesize, VolumeType=volumetype)
    ))
    return block_device_mappings_root
def my_block_device_mappings_ephemeral(diskcount,devicenamebase):
    block_device_mappings_ephemeral = []
    block_device_mappings_ephemeral.append(my_block_device_mappings_root("/dev/sd",ref_boot_disk_size,"gp2"))
    for i in xrange(diskcount):
        block_device_mappings_ephemeral.append(
            ec2.BlockDeviceMapping(
                DeviceName = devicenamebase + chr(i+98),
                VirtualName= "ephemeral" + str(i)
        ))
    return block_device_mappings_ephemeral


bootstrap_script_body = """
########################################################################
## trap errors
error_exit() {
  local line_no=$1
  local exit_code=$2
  cfn-signal -e ${exit_code} --region ${region} --stack ${stack} --resource ${resource}
  exit ${exit_code}
}
trap 'error_exit ${LINENO} ${?}' ERR

export TERM=xterm

########################################################################
## Install and Update CloudFormation
yum install -y epel-release
/usr/bin/easy_install https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz

########################################################################
## AWS specific system modifications

printf 'Defaults !requiretty\n' > /etc/sudoers.d/888-dont-requiretty

## swappiness to 0
sysctl -w vm.swappiness=0
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/50-swappiness.conf <<-'EOF'
## disable swapping
vm.swappiness=0
EOF

## Signal node is up
cfn-signal -e ${?} --region ${region} --stack ${stack} --resource ${resource}

## Remove existing mount points
if [ -e '/dev/xvdb' ]; then
    sed '/^\/dev\/xvd[b-z]/d' -i /etc/fstab

    ## Format ephemeral drives and create mounts
    for drv in /dev/xvd[b-z]; do
      umount ${drv} || true
      mkdir -p /mnt${drv}
      echo "${drv} /mnt${drv} ext4 defaults,noatime,nodiratime 0 0" >> /etc/fstab
      nohup mkfs.ext4 -m 0 -T largefile4 $drv &
    done
    wait

    for drv in /dev/xvd[b-z]; do
      mount ${drv}
    done
fi

export host_count=$((ref_additional_instance_count + 1))
curl -sSL https://raw.githubusercontent.com/HortonworksUniversity/Security_Labs/master/setup.sh | bash

if [ "${resource}" = "AmbariNode" ]; then
    echo ${ref_wait_ambari}
    cfn-signal -e ${?} --region ${region} --stack ${stack} -r "Ambari tasks are done" ${ref_wait_ambari}
fi

"""

def my_bootstrap_script(resource,install_ambari_agent,install_ambari_server,ambari_server):
    exports = [
        "#!/usr/bin/env bash\n",
        "exec &> >(tee -a /root/cloudformation.log)\n"
        "set -o nounset\n",
        "set -o errexit\n",
        "set -o xtrace\n",
        "export region='", ref_region, "'\n",
        "export stack='", ref_stack_name, "'\n",
        "export resource='", resource ,"'\n",
        "export ambari_server='", ambari_server ,"'\n",
        "export java_provider=", ref_java_provider ,"\n",
        "export java_version=", ref_java_version ,"\n",
        "export install_ambari_agent=", install_ambari_agent ,"\n",
        "export install_ambari_server=", install_ambari_server ,"\n",
        "export ref_wait_ambari='", ref_wait_ambari ,"'\n",
        "export ambari_services='", ref_ambari_services ,"'\n",
        "export ambari_pass=", ref_ambari_pass ,"\n",
        "export deploy=", ref_deploy_cluster ,"\n",
        "export ref_additional_instance_count=", ref_additional_instance_count ,"\n",
    ]
    return exports + bootstrap_script_body.splitlines(True)

AmbariNode = t.add_resource(ec2.Instance(
    "AmbariNode",
    UserData=Base64(Join("", my_bootstrap_script('AmbariNode','true','true','127.0.0.1'))),
    ImageId=FindInMap("CENTOS7", Ref("AWS::Region"), "AMI"),
    BlockDeviceMappings=my_block_device_mappings_ephemeral(24,"/dev/sd"),
    CreationPolicy=CreationPolicy(
        ResourceSignal=ResourceSignal(
          Count=1,
          Timeout="PT15M"
    )),
    Tags=Tags(
        Name=ref_stack_name,
    ),
    KeyName=Ref(KeyName),
    InstanceType=Ref(InstanceType),
    SubnetId=Ref(SubnetId),
    SecurityGroupIds=Ref(SecurityGroups),
    # NetworkInterfaces=[
    # ec2.NetworkInterfaceProperty(
        # DeleteOnTermination="true",
        # DeviceIndex="0",
        # SubnetId=Ref(SubnetId),
        # GroupSet=[Ref(SecurityGroups)],
        # AssociatePublicIpAddress="true",
    # ),
    # ],
))

AdditionalNodeLaunchConfig = t.add_resource(LaunchConfiguration(
    "AdditionalNodeLaunchConfig",
    UserData=Base64(Join("", my_bootstrap_script('AdditionalNodes','true','false',ref_ambariserver))),
    ImageId=FindInMap("CENTOS7", Ref("AWS::Region"), "AMI"),
    BlockDeviceMappings=my_block_device_mappings_ephemeral(24,"/dev/sd"),
    KeyName=Ref(KeyName),
    SecurityGroups=Ref(SecurityGroups),
    InstanceType=Ref(InstanceType),
    AssociatePublicIpAddress="true",
))

AdditionalNodes = t.add_resource(AutoScalingGroup(
    "AdditionalNodes",
    DesiredCapacity=Ref(AdditionalInstanceCount),
    MinSize=1,
    MaxSize=Ref(AdditionalInstanceCount),
    VPCZoneIdentifier=[Ref(SubnetId)],
    LaunchConfigurationName=Ref(AdditionalNodeLaunchConfig),
    DependsOn="AmbariNode",
    CreationPolicy=CreationPolicy(
        ResourceSignal=ResourceSignal(
          Count=Ref(AdditionalInstanceCount),
          Timeout="PT30M"
        ),
    ),
    Tags=[
            Tag("Name", ref_stack_name, True)
    ],
))

t.add_output([
    Output(
        "AmbariURL",
        Description="URL of Ambari UI",
        Value=Join("", [
            "http://", GetAtt('AmbariNode', 'PublicDnsName'), ":8080"
        ]),
    ),
    Output(
        "AmbariSSH",
        Description="SSH to the Ambari Node",
        Value=Join("", [
            "ssh ec2-user@", GetAtt('AmbariNode', 'PublicDnsName')
        ]),
    ),
    Output(
        "AmbariServiceInstanceId",
        Description="The Ambari Servers Instance-Id",
        Value=Ref('AmbariNode')
    ),
    Output(
        "Region",
        Description="AWS Region",
        Value=ref_region
    ),
])

if __name__ == '__main__':

    template_compressed="\n".join([line.strip() for line in t.to_json().split("\n")])

    try:
        cfcon = boto.cloudformation.connect_to_region('us-west-2')
        cfcon.validate_template(template_compressed)
    except boto.exception.BotoServerError, e:
        sys.stderr.write("FATAL: CloudFormation Template Validation Error:\n%s\n" % e.message)
    else:
        sys.stderr.write("Successfully validated template!\n")
        with open('cloudformation.json', 'w') as f:
            f.write(template_compressed)
        print('Compressed template written to cloudformation.json')
