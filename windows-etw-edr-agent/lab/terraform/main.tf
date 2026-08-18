provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "edr_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "edr-lab-vpc"
    Project     = "windows-etw-edr-agent"
    Environment = "lab"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.edr_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"

  tags = {
    Name = "edr-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.edr_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "edr-private-subnet"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.edr_vpc.id

  tags = {
    Name = "edr-igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.edr_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "edr-public-rt"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_security_group" "windows_agent_sg" {
  name        = "windows-agent-sg"
  description = "Security group for Windows EDR agent endpoint"
  vpc_id      = aws_vpc.edr_vpc.id

  ingress {
    description = "RDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "WinRM HTTPS"
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "windows-agent-sg"
  }
}

resource "aws_security_group" "elk_sg" {
  name        = "elk-stack-sg"
  description = "Security group for ELK stack"
  vpc_id      = aws_vpc.edr_vpc.id

  ingress {
    description = "Elasticsearch HTTP"
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    security_groups = [aws_security_group.windows_agent_sg.id]
  }

  ingress {
    description = "Kibana"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "elk-stack-sg"
  }
}

data "aws_ami" "windows_2022" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_instance" "windows_agent" {
  ami                         = data.aws_ami.windows_2022.id
  instance_type               = "t3.medium"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.windows_agent_sg.id]
  associate_public_ip_address = true

  user_data = <<-EOF
    <powershell>
    Install-WindowsFeature -Name NET-Framework-45-Core
    Set-ExecutionPolicy Bypass -Scope Process -Force
    </powershell>
  EOF

  tags = {
    Name = "edr-windows-agent"
  }
}

data "aws_ami" "ubuntu_2204" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_instance" "elk_server" {
  ami                    = data.aws_ami.ubuntu_2204.id
  instance_type          = "t3.large"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.elk_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y docker.io docker-compose
    systemctl enable docker
    systemctl start docker
    EOF

  tags = {
    Name = "edr-elk-server"
  }
}

resource "aws_s3_bucket" "telemetry_archive" {
  bucket = "etw-edr-telemetry-archive"

  tags = {
    Name = "etw-telemetry-archive"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "archive_lifecycle" {
  bucket = aws_s3_bucket.telemetry_archive.id

  rule {
    id     = "archive-old-telemetry"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }
}

output "windows_agent_public_ip" {
  description = "Public IP of the Windows EDR agent instance"
  value       = aws_instance.windows_agent.public_ip
}

output "elk_server_private_ip" {
  description = "Private IP of the ELK stack server"
  value       = aws_instance.elk_server.private_ip
}

output "elk_kibana_url" {
  description = "Kibana access URL"
  value       = "http://${aws_instance.elk_server.public_ip}:5601"
}
