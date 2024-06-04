provider "aws" {
  region = "us-east-1"
  alias = "AccountA"
  profile = "default"
}

resource "aws_key_pair" "login" {
  key_name   = "login"
  public_key = file("C:/Users/vithalraddi/.ssh/id_rsa.pub")
}

resource "aws_instance" "server_a" {
  provider = aws.AccountA
  ami           = "ami-0d191299f2822b1fa" 
  instance_type = "t2.micro"
  key_name = aws_key_pair.login.key_name
  vpc_security_group_ids = [aws_security_group.ssh.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_role.name

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y python3
              pip3 install boto3

              cat << 'EOP' > /home/ec2-user/publish_message.py
              import boto3
              from datetime import datetime

              sns_client = boto3.client('sns', region_name='us-east-1')

              def publish_message():
                  timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M:%S')
                  message = f"hello world from Server A at {timestamp}"
                  sns_client.publish(
                      TopicArn='${aws_sns_topic.ServerA.arn}',
                      Message=message
                  )

              if __name__ == "__main__":
                  publish_message()
              EOP

              chown ec2-user:ec2-user /home/ec2-user/publish_message.py
              chmod +x /home/ec2-user/publish_message.py

              (crontab -l 2>/dev/null; echo "* * * * * /usr/bin/python3 /home/ec2-user/publish_message.py") | crontab -
              EOF

  tags = {
    Name = "Server A"
  }
}

resource "aws_security_group" "ssh" {
  name_prefix = "allow_ssh"

  ingress {
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
}

resource "aws_sns_topic" "ServerA" {
  provider = aws.AccountA
  name     = "ServerA"
}

resource "aws_iam_role" "ec2_role" {
  provider = aws.AccountA
  name     = "ec2_publish_to_sns_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com",
      },
    }],
  })
}

resource "aws_iam_role_policy" "ec2_role_policy" {
  provider = aws.AccountA
  name     = "ec2_publish_to_sns_policy"
  role     = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "sns:Publish",
        Resource = aws_sns_topic.ServerA.arn,
      },
    ],
  })
}

resource "aws_iam_instance_profile" "ec2_role" {
  provider = aws.AccountA
  name     = "ec2_role"
  role     = aws_iam_role.ec2_role.name
}

resource "aws_sns_topic_policy" "sns_policy" {
  provider = aws.AccountA
  arn      = aws_sns_topic.ServerA.arn

policy = jsonencode({
    "Version": "2008-10-17",
    "Id": "SNS",
    "Statement": [
      {
        "Sid": "__default_statement_ID",
        "Effect": "Allow",
        "Principal": {
          "AWS": "*"
        },
        "Action": [
          "SNS:Publish",
          "SNS:RemovePermission",
          "SNS:SetTopicAttributes",
          "SNS:DeleteTopic",
          "SNS:ListSubscriptionsByTopic",
          "SNS:GetTopicAttributes",
          "SNS:AddPermission",
          "SNS:Subscribe"
        ],
        "Resource": aws_sns_topic.ServerA.arn,
        "Condition": {
          "StringEquals": {
            "AWS:SourceOwner": "394953618631"
          }
        }
      },
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::590184045059:root"
        },
        "Action": "sns:Subscribe",
        "Resource": aws_sns_topic.ServerA.arn
      }
    ]
  })
}

resource "aws_s3_bucket" "sns-sqs-vk" {
  bucket = "sns-sqs-vk"
}

resource "aws_s3_bucket_public_access_block" "sns-sqs-vk" {
  bucket = aws_s3_bucket.sns-sqs-vk.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "sns-sqs" {
  bucket = aws_s3_bucket.sns-sqs-vk.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::590184045059:root"
      },
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::sns-sqs-vk/*"
    }
  ]
}
POLICY
}


output "sns_topic_arn" {
  value = aws_sns_topic.ServerA.arn
}
