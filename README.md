# terraform-aws-wordpress

In this section, I am going to use Terraform to create AWS resources and automate WordPress installation using EC2 Userdata.

### What's this project:

Inorder to demonstartae this project we neeed to have a vpc with all its essential resources (described below),EC2,EIP and security groups. Here we are using a frontend server to host websites, a backend server to manage mysql and an another EC2 isntance which is bastion server mainy for accessing both of these servers. Therefor SSH access into both these instances are only possible though the bastion server. 

Here we are using terraform to provision infrastructure. we are creating following aws resources for this such as;

 -  VPC 
- Subnets -  we need three public and three private subnets based on the avaiablity zones in that region.
- Route Tables -  here we are using both  private and public  route tables for public and private subnets
- Internet Gateway
- Nat Gateway - used to  provide internet connectivity for instances under private network.
- Route table association - two table asscoiation needed for private as well as public

- EC2 instance
1. Frontend-webserver
2. Bastion server
3. DB-backend server
- EIP for NAT Gateway

- Security Groups to access EC2

1. Frontend-server Security Group;

allows SSH traffic from Bastion server and HTTP/S traffic from internet.

2. Bastion-server Security Group;

This security group allows inbound SSH traffic

3. Backend-server Security Group;

It allows the SSH connection originates Bastion server security group and MySQL connection originates from Frontend-server security group.

- AWS Keypair - a key-pair is generated locally using ssh-keygen and the public key is uploaded into the AWS using terraform.

- AWS Route53 - here we use both Public & Private Hosted Zone to create DNS records for Backend server and Frontend server



### Requirements

1. Terraform if you don't have it already you can Download it here
  https://developer.hashicorp.com/terraform/downloads
2.need to have an IAM user with programmatic access with AmazonEc2FullAccess and AmazonRoute53FullAccess, create security credentials(AccessKey, SecretKey)

## You will create the following AWS resources in this below section:

 - A VPC

- Three subnets

- An internet gateway

- A route table

- EC2 instances

## Steps required for the creation of this projcet;

### Step 1

 configure provider.tf file using a IAM user who having programmatic access and certain common tags that has been using in this entire project

```sh
 $provider "aws" {
  region     = var.region
  access_key = var.access_key
  secret_key = var.secret_key

  default_tags {

    tags = local.common_tags

  }

}
```

### Step 2
-creating esscential variables needed for this project and using this variables we are accesing most of the resources;

````
variable "project" {
  default     = "zomato"
  description = "project name"
}


variable "environment" {
  default     = "production"
  description = "project environemnt"
}


variable "region" {
  default = "ap-south-1"
}

variable "access_key" {
  default = "xxxxxxxxxxx"
}

variable "secret_key" {
  default = "xxxxxxxxxxx"
}

variable "vpc_cidr" {
  default = "172.16.0.0/16"

}

variable "instance_ami" {

  default = "ami-xxxxxxxxx"
}

variable "instance_type" {

  default = "t2.micro"
}

variable "private_domain" {
  default = "domai_name.local"
}

variable "public_domain" {
  default = "domain_name"
}

locals {

  subnets = length(data.aws_availability_zones.available.names)

}

locals {
  common_tags = {
    "project"     = var.project
    "environemnt" = var.environment
  }

}
````

### step 3

create a datasource.tf file to mention the datasources that we are apply in this project;

````
data "aws_availability_zones" "available" {
  state = "available"
}


data "aws_route53_zone" "mydomain" {
  name = "domain_name."
}

````

### Step 4

userdata script for both frontend-webserver and DB-backend server while lauching both EC2;
 1. For frontend-webserver
````
#!/bin/bash
 
        echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
        echo "LANG=en_US.utf-8" >> /etc/environment
        echo "LC_ALL=en_US.utf-8" >> /etc/environment
        service sshd restart
        hostnamectl set-hostname frontend
        amazon-linux-extras install php7.4 
        yum install httpd -y
        systemctl restart httpd
        systemctl enable httpd
        wget https://wordpress.org/latest.zip
        unzip latest.zip
        cp -rf wordpress/* /var/www/html/
        mv /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
        chown -R apache:apache /var/www/html/*
        cd  /var/www/html/
        sed -i 's/database_name_here/wpdb/g' wp-config.php
    sed -i 's/username_here/wpdbuser/g' wp-config.php
        sed -i 's/password_here/pass123/g' wp-config.php
        sed -i 's/localhost/db.angeldevops.local/g' wp-config.php
````
2. For backend-db server
````
#!/bin/bash
 
        echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
        echo "LANG=en_US.utf-8" >> /etc/environment
        echo "LC_ALL=en_US.utf-8" >> /etc/environment
        service sshd restart
        hostnamectl set-hostname backend
        amazon-linux-extras install php7.4 -y
        rm -rf /var/lib/mysql/*
        yum remove mysql -y
    yum install httpd mariadb-server -y
        systemctl restart mariadb.service
    systemctl enable mariadb.service
    mysqladmin -u root password 'mysql123'
        mysql -u root -pmysql123 -e "create database wpdb;"
        mysql -u root -pmysql123 -e "create user 'wpdbuser'@'%' identified by 'angel123';"
        mysql -u root -pmysql123 -e "grant all privileges on wpdb.* to 'wpdbuser'@'%'"
        mysql -u root -pmysql123 -e "flush privileges"
````
### Step 5

Creating VPC.

1. Create a VPC with a 172.16.0.0/16 CIDR block


```sh
resource "aws_vpc" "vpc" {

  cidr_block           = var.vpc_cidr
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "${var.project}-${var.environment}"
  }
}


resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "${var.project}-${var.environment}"
  }
}

resource "aws_subnet" "public" {
  count                   = local.subnets
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project}-${var.environment}-public${count.index + 1}"
  }
}

resource "aws_subnet" "private" {
  count                   = local.subnets
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, "${local.subnets + count.index}")
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.project}-${var.environment}-private${count.index + 1}"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.project}-${var.environment}"
  }

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_eip" "nat" {
  vpc = true

  tags = {
    Name = "${var.project}-${var.environment}-natgw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "${var.project}-${var.environment}-public"
  }
}


resource "aws_route_table" "private" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = {
    Name = "${var.project}-${var.environment}-private"
  }
}

resource "aws_route_table_association" "public" {
  count          = local.subnets
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = local.subnets
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_security_group" "bastion-traffic" {
  name_prefix = "${var.project}-${var.environment}-bastion-"
  description = "Allows ssh traffic only"
  vpc_id      = aws_vpc.vpc.id

  ingress {

    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.project}-${var.environment}-bastion"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "frontend-traffic" {
  name_prefix = "${var.project}-${var.environment}-frontend-"
  description = "Allow http,https,ssh traffic only"
  vpc_id      = aws_vpc.vpc.id

  ingress {

    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {

    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {

    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion-traffic.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.project}-${var.environment}-frontend"
  }
  lifecycle {
    create_before_destroy = true
  }

}

resource "aws_security_group" "backend-traffic" {
  name_prefix = "${var.project}-${var.environment}-backend-"
  description = "Allow mysql,ssh traffic only"
  vpc_id      = aws_vpc.vpc.id

  ingress {

    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.frontend-traffic.id]
  }
  ingress {

    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion-traffic.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.project}-${var.environment}-backend"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_key_pair" "ssh_key" {

  key_name   = "${var.project}-${var.environment}"
  public_key = file("mykey.pub")
  tags = {
    "Name" = "${var.project}-${var.environment}"
  }
}



resource "aws_instance" "bastion" {

  ami           = var.instance_ami
  instance_type = var.instance_type
  key_name      = aws_key_pair.ssh_key.key_name
  subnet_id     = aws_subnet.public.1.id

  vpc_security_group_ids = [aws_security_group.bastion-traffic.id]

  tags = {

    "Name" = "${var.project}-${var.environment}-bastion"
  }
}



resource "aws_instance" "frontend" {

  ami                         = var.instance_ami
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.ssh_key.key_name
  subnet_id                   = aws_subnet.public.0.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.frontend-traffic.id]
  user_data                   = file("setup_frontend.sh")
  user_data_replace_on_change = true

  tags = {

    "Name" = "${var.project}-${var.environment}-frontend"
  }
}

resource "aws_instance" "backend" {

  ami                         = var.instance_ami
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.ssh_key.key_name
  subnet_id                   = aws_subnet.private.0.id
  associate_public_ip_address = false
  user_data                   = file("setup_backend.sh")
  user_data_replace_on_change = true
  vpc_security_group_ids      = [aws_security_group.backend-traffic.id]

  # To ensure proper ordering, it is recommended to add an explicit dependency
  depends_on = [aws_nat_gateway.nat]

  tags = {

    "Name" = "${var.project}-${var.environment}-backend"
  }
}

resource "aws_route53_zone" "private" {
  name = var.private_domain

  vpc {
    vpc_id = aws_vpc.vpc.id
  }
}

resource "aws_route53_record" "db_a" {
  zone_id = aws_route53_zone.private.zone_id

  name    = "db.${var.private_domain}"
  type    = "A"
  ttl     = "30"
  records = [aws_instance.backend.private_ip]
}

resource "aws_route53_record" "wordpress_domain_name" {
  zone_id = data.aws_route53_zone.mydomain.zone_id
  name    = "wordpress.${var.public_domain}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.frontend.public_ip]
}
```
### Step 6

Deploy the infrastructure using Terraform

1. Initialize

>cd /to/your/project/root/parent/directory
>terraform init
>terraform validate
>terraform plan
>terraform apply

2. To terminate

When you are all done remove all the created resources using

>terraform destroy










