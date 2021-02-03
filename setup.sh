#!/bin/sh

# Exit if any subcommand fails
set -e

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
NO_COLOR="\033[0m"
CLEAR_LINE="\r\033[K"

printf "[1/6]🔎   Checking dependencies\n"

if ! command -v aws &> /dev/null 
then
  printf "${CLEAR_LINE}⚠️${YELLOW}   AWS cli not installed.${NO_COLOR}\n"
  printf "ℹ️   go to ...\n"
  exit
fi

read -p "AWS Access Key ID: " accessKeyId
read -p "AWS Secret Access Key: " accessKey
read -p "Default region name [ap-southeast-2]: " region
region=${region:-"ap-southeast-2"}

# Pipe configuration options into aws cli
echo "$accessKeyId\n$accessKey\n$region\njson" | aws configure --profile wp-setup &> /dev/null

read -p "Project name: " project

##########################################
#                                        #
#           CREATE THE NETWORK           #
#                                        #
##########################################
printf "[2/6]    Creating network for '$project'\n"

printf "o creating vpc\n"
AWS_VPC_ID=$(aws --profile wp-setup ec2 create-vpc \
                 --cidr-block 10.0.0.0/16 \
                 --query "Vpc.{VpcId:VpcId}" \
                 --output text)

printf "o enabling dns\n"
aws --profile wp-setup ec2 modify-vpc-attribute \
    --vpc-id $AWS_VPC_ID \
    --enable-dns-hostnames "{\"Value\":true}" &> /dev/null

## Create a public subnet
printf "o creating public subnet\n"
AWS_SUBNET_PUBLIC_ID=$(aws --profile wp-setup ec2 create-subnet \
                           --vpc-id $AWS_VPC_ID --cidr-block 10.0.1.0/24 \
                           --availability-zone ${region}a --query "Subnet.{SubnetId:SubnetId}" \
                           --output text)
printf "o   created: $AWS_SUBNET_PUBLIC_ID\n"

printf "o enabling auto-assigned public ip\n"
aws --profile wp-setup ec2 modify-subnet-attribute \
    --subnet-id $AWS_SUBNET_PUBLIC_ID \
    --map-public-ip-on-launch &> /dev/null

printf "o creating internet gateway\n"
AWS_INTERNET_GATEWAY_ID=$(aws --profile wp-setup ec2 create-internet-gateway \
                              --query "InternetGateway.{InternetGatewayId:InternetGatewayId}" \
                              --output text)
printf "o   created: $AWS_INTERNET_GATEWAY_ID\n"

printf "o attaching internet gateway\n"
aws --profile wp-setup ec2 attach-internet-gateway \
    --vpc-id $AWS_VPC_ID \
    --internet-gateway-id $AWS_INTERNET_GATEWAY_ID &> /dev/null


printf "o creating custom routing table\n"
AWS_CUSTOM_ROUTE_TABLE_ID=$(aws --profile wp-setup ec2 create-route-table \
                                --vpc-id $AWS_VPC_ID \
                                --query "RouteTable.{RouteTableId:RouteTableId}" \
                                --output text )
printf "o   created: $AWS_CUSTOM_ROUTE_TABLE_ID\n"

printf "o creating routes\n"
aws --profile wp-setup ec2 create-route \
    --route-table-id $AWS_CUSTOM_ROUTE_TABLE_ID \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id $AWS_INTERNET_GATEWAY_ID &> /dev/null

printf "o creating route table association\n"
AWS_ROUTE_TABLE_ASSOID=$(aws --profile wp-setup ec2 associate-route-table  \
                             --subnet-id $AWS_SUBNET_PUBLIC_ID \
                             --route-table-id $AWS_CUSTOM_ROUTE_TABLE_ID \
                             --output text)
printf "o   created: $AWS_ROUTE_TABLE_ASSOID"


printf "o creating security groups\n"
aws --profile wp-setup ec2 create-security-group \
    --vpc-id $AWS_VPC_ID \
    --group-name "$project-sec-group" \
    --description "$project VPC non default security group" &> /dev/null


printf "o configuring security group\n"
AWS_DEFAULT_SECURITY_GROUP_ID=$(aws --profile wp-setup ec2 describe-security-groups \
--filters "Name=vpc-id,Values=$AWS_VPC_ID" \
--query "SecurityGroups[?GroupName == 'default'].GroupId" \
--output text) && AWS_CUSTOM_SECURITY_GROUP_ID=$(aws --profile wp-setup ec2 describe-security-groups \
--filters "Name=vpc-id,Values=$AWS_VPC_ID" \
--query "SecurityGroups[?GroupName == '$project-sec-group'].GroupId" \
--output text)
printf "o   configured: $AWS_CUSTOM_SECURITY_GROUP_ID"


printf "o adding ingress control\n"
aws --profile wp-setup ec2 authorize-security-group-ingress \
--group-id $AWS_CUSTOM_SECURITY_GROUP_ID \
--ip-permissions "[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Allow SSH"}]}]"  &> /dev/null && aws --profile wp-setup ec2 authorize-security-group-ingress \
--group-id $AWS_CUSTOM_SECURITY_GROUP_ID \
--ip-permissions "[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Allow HTTP"}]}]" &> /dev/null


printf "o assigning tags\n"
aws  --profile wp-setup ec2 create-tags \
--resources $AWS_VPC_ID \
--tags "Key=Name,Value=$project-vpc" &> /dev/null
 
## Add a tag to public subnet
aws --profile wp-setup ec2 create-tags \
--resources $AWS_SUBNET_PUBLIC_ID \
--tags "Key=Name,Value=$project-public-subnet" &> /dev/null
 
## Add a tag to the Internet-Gateway
aws --profile wp-setup ec2 create-tags \
--resources $AWS_INTERNET_GATEWAY_ID \
--tags "Key=Name,Value=$project-internet-gateway" &> /dev/null
 
## Add a tag to the default route table
AWS_DEFAULT_ROUTE_TABLE_ID=$(aws --profile wp-setup ec2 describe-route-tables \
--filters "Name=vpc-id,Values=$AWS_VPC_ID" \
--query "RouteTables[?Associations[0].Main != `flase`].RouteTableId" \
--output text)  &> /dev/null && aws --profile wp-setup ec2 create-tags \
--resources $AWS_DEFAULT_ROUTE_TABLE_ID \
--tags "Key=Name,Value=$project-default-route-table" &> /dev/null
 
## Add a tag to the public route table
aws --profile wp-setup ec2 create-tags \
--resources $AWS_CUSTOM_ROUTE_TABLE_ID \
--tags "Key=Name,Value=$project-public-route-table" &> /dev/null
 
## Add a tags to security groups
aws --profile wp-setup ec2 create-tags \
--resources $AWS_CUSTOM_SECURITY_GROUP_ID \
--tags "Key=Name,Value=$project-sec-group"  &> /dev/null && aws --profile wp-setup ec2 create-tags \
--resources $AWS_DEFAULT_SECURITY_GROUP_ID \
--tags "Key=Name,Value=$project-default-sec-group" &> /dev/null

printf "[2/6]    Network setup complete\n"

##########################################
#                                        #
#          CREATE THE INSTANCE           #
#                                        #
##########################################
printf "[3/6]    Creating ec2 instance for '$project'\n"

printf "o finding AMI image\n"
AWS_AMI_ID=$(aws --profile wp-setup ec2 describe-images \
                 --owners 'amazon' \
                 --filters 'Name=name,Values=amzn2-ami-hvm-2.0.????????-x86_64-gp2' 'Name=state,Values=available' \
                 --query 'sort_by(Images, &CreationDate)[-1].[ImageId]' \
                 --output 'text')


printf "o creating keypair\n"
aws --profile wp-setup ec2 create-key-pair \
--key-name "$project-keypair" \
--query 'KeyMaterial' \
--output text > "~/.ssh/$project-keypair.pem" &> /dev/null
printf "o   keypair saved to ~/.ssh/$project-keypair.pem\n"

printf "o starting instance\n"
AWS_EC2_INSTANCE_ID=$(aws --profile wp-setup ec2 run-instances \
--image-id $AWS_AMI_ID \
--instance-type t2.micro \
--key-name $project-keypair \
--monitoring "Enabled=false" \
--security-group-ids $AWS_CUSTOM_SECURITY_GROUP_ID \
--subnet-id $AWS_SUBNET_PUBLIC_ID \
--user-data file://ec2.startup.txt \
--private-ip-address 10.0.1.10 \
--query 'Instances[0].InstanceId' \
--output text) &> /dev/null
printf "o   instance started: $AWS_EC2_INSTANCE_ID\n"

printf "o assigning tags\n"
aws ec2 --profile wp-setup create-tags \
--resources $AWS_EC2_INSTANCE_ID \
--tags "Key=Name,Value=$project-ec2-instance" &> /dev/null

AWS_EC2_INSTANCE_PUBLIC_IP=$(aws ec2 describe-instances \
--query "Reservations[*].Instances[*].PublicIpAddress" \
--output=text) &> /dev/null

echo "EC2 Instance Public IP: $AWS_EC2_INSTANCE_PUBLIC_IP\n"

##########################################
#                                        #
#          CREATE THE DATABASE           #
#                                        #
##########################################
printf "[4/6]    Creating database for '$project'\n"
# create "$project-db-user"
# create the database
# import WP tables
# create a development replica
# prefill the details (ie. development IP address, live IP/domain etc)


##########################################
#                                        #
#         CREATE THE S3 BUCKET           #
#                                        #
##########################################
printf "[5/6]    Creating S3 bucket for '$project'\n"
# create "$project-s3-user"

# setup wordpress (admin, read / write) user/role policy
ADMIN_POLICY_ARN=$(aws --profile wp-setup iam create-policy 
                       --policy-name "$project-bucket-admin"
                       --policy-document file://./s3-admin-policy.json 
                       --query 'Policy.Arn' 
                       --output 'text') &> /dev/null

# setup bucket public access policy

# create a new service user with ADMIN_POLICY_ARN
# return $project-service accessKeyId:accessKey
#  or create a PHP file in the instance with the info
#  or automatically update the instance database


cleanup=false
if [ "$cleanup" = true ] then;
    printf "Starting cleanup\n"
    aws --profile wp-setup ec2 delete-security-group \
    --group-id $AWS_CUSTOM_SECURITY_GROUP_ID &> /dev/null
    
    ## Delete internet gateway
    aws --profile wp-setup ec2 detach-internet-gateway \
    --internet-gateway-id $AWS_INTERNET_GATEWAY_ID \
    --vpc-id $AWS_VPC_ID  &> /dev/null &&
    aws --profile wp-setup ec2 delete-internet-gateway \
    --internet-gateway-id $AWS_INTERNET_GATEWAY_ID &> /dev/null
    
    ## Delete the custom route table
    aws --profile wp-setup ec2 disassociate-route-table \
    --association-id $AWS_ROUTE_TABLE_ASSOID  &> /dev/null &&
    aws --profile wp-setup ec2 delete-route-table \
    --route-table-id $AWS_CUSTOM_ROUTE_TABLE_ID &> /dev/null
    
    ## Delete the public subnet
    aws --profile wp-setup ec2 delete-subnet \
    --subnet-id $AWS_SUBNET_PUBLIC_ID &> /dev/null
    
    ## Delete the vpc
    aws --profile wp-setup ec2 delete-vpc \
    --vpc-id $AWS_VPC_ID &> /dev/null

    aws ec2 terminate-instances \
    --instance-ids $AWS_EC2_INSTANCE_ID  &> /dev/null
    
    ## Delete key pair
    aws ec2 delete-key-pair \
    --key-name $project-keypair  &> /dev/null&&
    rm -f "~/.ssh/$project-keypair.pem" &> /dev/null
    
    ## Delete custom security group
    aws ec2 delete-security-group \
    --group-id $AWS_CUSTOM_SECURITY_GROUP_ID &> /dev/null
    
    ## Delete internet gateway
    aws ec2 detach-internet-gateway \
    --internet-gateway-id $AWS_INTERNET_GATEWAY_ID \
    --vpc-id $AWS_VPC_ID &> /dev/null &&
    aws ec2 delete-internet-gateway \
    --internet-gateway-id $AWS_INTERNET_GATEWAY_ID &> /dev/null
    
    ## Delete the custom route table
    aws ec2 disassociate-route-table \
    --association-id $AWS_ROUTE_TABLE_ASSOID &> /dev/null &&
    aws ec2 delete-route-table \
    --route-table-id $AWS_CUSTOM_ROUTE_TABLE_ID &> /dev/null
    
    ## Delete the public subnet
    aws ec2 delete-subnet \
    --subnet-id $AWS_SUBNET_PUBLIC_ID &> /dev/null
    
    ## Delete the vpc
    aws ec2 delete-vpc \
    --vpc-id $AWS_VPC_ID &> /dev/null
    printf "Cleanup complete\n"
fi