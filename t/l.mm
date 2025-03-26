# AWS CLI Tool

This command-line interface (CLI) tool is designed to interact with Amazon Web Services (AWS) resources, providing functionalities such as assuming IAM roles and managing AWS services like Amazon RDS.

## Features

- **Assume IAM Roles:** Securely assume AWS IAM roles to perform actions with temporary security credentials.
- **Manage AWS Resources:** Perform operations on AWS services, such as adding tags to Amazon RDS instances.

## Prerequisites

Before using this CLI tool, ensure you have the following:

- **Go Programming Language:** Installed on your system. Download it from the [official Go website](https://golang.org/dl/).
- **AWS Account:** An active AWS account with appropriate permissions.
- **AWS SDK for Go:** Integrated into your project.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/aws-cli-tool.git
   ```


2. **Navigate to the Project Directory:**

   ```bash
   cd aws-cli-tool
   ```


3. **Build the Application:**

   ```bash
   go build -o aws-cli-tool main.go
   ```


## Configuration

This tool utilizes AWS credentials for authentication. Configure your AWS credentials using one of the following methods:

- **AWS Credentials File:** Located at `~/.aws/credentials`.

  
```ini
  [default]
  aws_access_key_id = YOUR_ACCESS_KEY_ID
  aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
  ```


- **Environment Variables:**

   ```bash
   export AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_ID
   export AWS_SECRET_ACCESS_KEY=YOUR_SECRET_ACCESS_KEY
   ```


For more detailed configuration options, refer to the [AWS CLI Configuration Variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html).

## Usage

After building the application, you can execute the CLI tool using the following syntax:


```bash
./aws-cli-tool [command] [flags]
```


### Commands

- **assume-role:** Assumes an AWS IAM role and retrieves temporary security credentials.

  
```bash
  ./aws-cli-tool assume-role --role-arn arn:aws:iam::123456789012:role/YourRoleName --session-name YourSessionName
  ```


- **tag-rds:** Adds tags to an Amazon RDS resource.

  
```bash
  ./aws-cli-tool tag-rds --resource-arn arn:aws:rds:us-west-2:123456789012:db:your-db-instance --tags Key=Environment,Value=Production
  ```


For a complete list of commands and their options, run:


```bash
./aws-cli-tool --help
```


## Examples

1. **Assuming an IAM Role:**

   ```bash
   ./aws-cli-tool assume-role --role-arn arn:aws:iam::123456789012:role/YourRoleName --session-name YourSessionName
   ```


2. **Adding Tags to an RDS Instance:**

   ```bash
   ./aws-cli-tool tag-rds --resource-arn arn:aws:rds:us-west-2:123456789012:db:your-db-instance --tags Key=Environment,Value=Production
   ```


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

This tool leverages the AWS SDK for Go. For more information and code examples, refer to the [AWS SDK for Go Code Examples](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/common-examples.html).

---

*Note: This README is a template and should be customized to fit the specific details and requirements of your CLI tool.* 
