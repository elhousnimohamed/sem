import json
import os
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
import requests

def lambda_handler(event, context):
    """
    Main Lambda handler for disaster recovery prechecks.
    Performs validation across Service Catalog, Amplify, DynamoDB, CloudFormation, and EC2.
    """
    try:
        # Load environment variables
        role_arn = os.environ['ROLE_ARN']
        region = os.environ['REGION']
        portfolio_name = os.environ['PORTFOLIO_NAME']
        product_name = os.environ['PRODUCT_NAME']
        account_role_map = json.loads(os.environ['ACCOUNT_ROLE_MAP'])
        dynamodb_table_name = os.environ['DYNAMODB_TABLE_NAME']
        terraform_token = os.environ.get('TERRAFORM_API_TOKEN', '')
        
        # Initialize result structure
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'SUCCESS',
            'service_catalog': {},
            'amplify': {},
            'ec2_instances': [],
            'errors': []
        }
        
        # Step 1: Assume role in Account B
        account_b_session = assume_role(role_arn, region)
        
        # Step 2 & 3: Service Catalog checks
        sc_client = account_b_session.client('servicecatalog', region_name=region)
        
        # Get portfolio ID
        portfolio_id = get_portfolio_id(sc_client, portfolio_name)
        if not portfolio_id:
            result['errors'].append(f"Portfolio '{portfolio_name}' not found")
            result['status'] = 'FAILED'
            return format_response(result)
        
        result['service_catalog']['portfolio_id'] = portfolio_id
        result['service_catalog']['portfolio_name'] = portfolio_name
        
        # Get product ID
        product_id = get_product_id(sc_client, portfolio_id, product_name)
        if not product_id:
            result['errors'].append(f"Product '{product_name}' not found in portfolio")
            result['status'] = 'FAILED'
            return format_response(result)
        
        result['service_catalog']['product_id'] = product_id
        result['service_catalog']['product_name'] = product_name
        
        # Get provisioned products
        provisioned_products = get_provisioned_products(sc_client, product_id)
        result['service_catalog']['provisioned_products'] = provisioned_products
        result['service_catalog']['provisioned_count'] = len(provisioned_products)
        
        # Step 4: Get AmplifyAppId from provisioned product outputs and check status
        amplify_app_ids = []
        for product in provisioned_products:
            outputs = get_provisioned_product_outputs(sc_client, product['id'])
            product['outputs'] = outputs
            
            # Extract AmplifyAppId from outputs
            amplify_app_id = None
            for output in outputs:
                if output.get('key') == 'AmplifyAppId':
                    amplify_app_id = output.get('value')
                    amplify_app_ids.append(amplify_app_id)
                    break
            
            product['amplify_app_id'] = amplify_app_id
        
        # Check Amplify applications using the extracted IDs
        amplify_status = check_amplify_apps_by_id(account_b_session, region, amplify_app_ids)
        result['amplify'] = amplify_status
        
        # Step 5: Query DynamoDB for EC2 instances
        dynamodb_client = account_b_session.client('dynamodb', region_name=region)
        ec2_records = query_dynamodb_instances(dynamodb_client, dynamodb_table_name)
        
        # Step 6: Validate EC2 instances across accounts
        for record in ec2_records:
            account_id = record.get('account_id')
            instance_id = record.get('instance_id')
            
            if not account_id or not instance_id:
                result['errors'].append(f"Invalid record in DynamoDB: {record}")
                continue
            
            # Assume role in target account
            target_role_arn = account_role_map.get(account_id)
            if not target_role_arn:
                result['errors'].append(f"No role mapping for account {account_id}")
                result['ec2_instances'].append({
                    'instance_id': instance_id,
                    'account_id': account_id,
                    'status': 'ROLE_NOT_FOUND'
                })
                continue
            
            try:
                target_session = assume_role(target_role_arn, region)
                ec2_client = target_session.client('ec2', region_name=region)
                
                instance_status = check_ec2_instance(ec2_client, instance_id)
                instance_status['account_id'] = account_id
                instance_status['dynamodb_record'] = record
                result['ec2_instances'].append(instance_status)
                
            except Exception as e:
                result['errors'].append(f"Error checking instance {instance_id} in account {account_id}: {str(e)}")
                result['ec2_instances'].append({
                    'instance_id': instance_id,
                    'account_id': account_id,
                    'status': 'CHECK_FAILED',
                    'error': str(e)
                })
        
        # Step 7: Check CloudFormation stacks
        cfn_status = check_cloudformation_stacks(account_b_session, region, provisioned_products)
        result['cloudformation'] = cfn_status
        
        # Step 8: Check Terraform Cloud (if applicable)
        if terraform_token:
            terraform_status = check_terraform_workspaces(terraform_token, ec2_records)
            result['terraform'] = terraform_status
        
        # Determine overall status
        if result['errors']:
            result['status'] = 'COMPLETED_WITH_ERRORS'
        
        return format_response(result)
        
    except Exception as e:
        return format_response({
            'status': 'FAILED',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }, status_code=500)


def assume_role(role_arn, region):
    """Assume an IAM role and return a boto3 session."""
    sts_client = boto3.client('sts', region_name=region)
    
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='DR-Precheck-Session',
            DurationSeconds=3600
        )
        
        credentials = response['Credentials']
        
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region
        )
    except ClientError as e:
        raise Exception(f"Failed to assume role {role_arn}: {str(e)}")


def get_portfolio_id(sc_client, portfolio_name):
    """Retrieve portfolio ID by name."""
    try:
        paginator = sc_client.get_paginator('list_portfolios')
        
        for page in paginator.paginate():
            for portfolio in page.get('PortfolioDetails', []):
                if portfolio['DisplayName'] == portfolio_name:
                    return portfolio['Id']
        
        return None
    except ClientError as e:
        raise Exception(f"Error listing portfolios: {str(e)}")


def get_product_id(sc_client, portfolio_id, product_name):
    """Retrieve product ID by name within a portfolio."""
    try:
        paginator = sc_client.get_paginator('search_products_as_admin')
        
        for page in paginator.paginate(PortfolioId=portfolio_id):
            for product in page.get('ProductViewDetails', []):
                product_view = product.get('ProductViewSummary', {})
                if product_view.get('Name') == product_name:
                    return product_view.get('ProductId')
        
        return None
    except ClientError as e:
        raise Exception(f"Error searching products: {str(e)}")


def get_provisioned_products(sc_client, product_id):
    """List all provisioned products for a given product ID."""
    provisioned = []
    
    try:
        paginator = sc_client.get_paginator('scan_provisioned_products')
        
        for page in paginator.paginate(
            AccessLevelFilter={'Key': 'Account', 'Value': 'self'}
        ):
            for product in page.get('ProvisionedProducts', []):
                if product.get('ProductId') == product_id:
                    provisioned.append({
                        'id': product.get('Id'),
                        'name': product.get('Name'),
                        'status': product.get('Status'),
                        'type': product.get('Type'),
                        'created_time': product.get('CreatedTime').isoformat() if product.get('CreatedTime') else None,
                        'last_record_id': product.get('LastRecordId'),
                        'physical_id': product.get('PhysicalId')
                    })
        
        return provisioned
    except ClientError as e:
        raise Exception(f"Error listing provisioned products: {str(e)}")


def get_provisioned_product_outputs(sc_client, provisioned_product_id):
    """Get outputs from a provisioned product."""
    outputs = []
    
    try:
        # Get the provisioned product details
        response = sc_client.describe_provisioned_product(
            Id=provisioned_product_id
        )
        
        provisioned_product = response.get('ProvisionedProductDetail', {})
        
        # Get the last successful record to retrieve outputs
        if provisioned_product.get('LastSuccessfulProvisioningRecordId'):
            record_response = sc_client.describe_record(
                Id=provisioned_product['LastSuccessfulProvisioningRecordId']
            )
            
            record_outputs = record_response.get('RecordOutputs', [])
            
            for output in record_outputs:
                outputs.append({
                    'key': output.get('OutputKey'),
                    'value': output.get('OutputValue'),
                    'description': output.get('Description')
                })
        
        return outputs
    except ClientError as e:
        return [{
            'error': str(e),
            'provisioned_product_id': provisioned_product_id
        }]


def check_amplify_apps_by_id(session, region, app_ids):
    """Check status of specific Amplify applications by their IDs."""
    amplify_client = session.client('amplify', region_name=region)
    
    apps = []
    errors = []
    
    for app_id in app_ids:
        if not app_id:
            continue
        
        try:
            response = amplify_client.get_app(appId=app_id)
            app = response.get('app', {})
            
            # Get branches for this app
            branches = []
            try:
                branches_response = amplify_client.list_branches(
                    appId=app_id,
                    maxResults=50
                )
                
                for branch in branches_response.get('branches', []):
                    branches.append({
                        'branch_name': branch.get('branchName'),
                        'stage': branch.get('stage'),
                        'display_name': branch.get('displayName'),
                        'enable_auto_build': branch.get('enableAutoBuild'),
                        'total_number_of_jobs': branch.get('totalNumberOfJobs'),
                        'active_job_id': branch.get('activeJobId')
                    })
            except ClientError as branch_error:
                errors.append(f"Error listing branches for app {app_id}: {str(branch_error)}")
            
            # Get latest deployment info
            backend_environments = []
            try:
                backend_response = amplify_client.list_backend_environments(
                    appId=app_id,
                    maxResults=50
                )
                
                for backend in backend_response.get('backendEnvironments', []):
                    backend_environments.append({
                        'environment_name': backend.get('environmentName'),
                        'stack_name': backend.get('stackName'),
                        'deployment_artifacts': backend.get('deploymentArtifacts'),
                        'create_time': backend.get('createTime').isoformat() if backend.get('createTime') else None
                    })
            except ClientError as backend_error:
                errors.append(f"Error listing backend environments for app {app_id}: {str(backend_error)}")
            
            apps.append({
                'app_id': app_id,
                'name': app.get('name'),
                'description': app.get('description'),
                'repository': app.get('repository'),
                'platform': app.get('platform'),
                'default_domain': app.get('defaultDomain'),
                'enable_branch_auto_build': app.get('enableBranchAutoBuild'),
                'enable_branch_auto_deletion': app.get('enableBranchAutoDeletion'),
                'enable_basic_auth': app.get('enableBasicAuth'),
                'production_branch': {
                    'branch_name': app.get('productionBranch', {}).get('branchName'),
                    'last_deploy_time': app.get('productionBranch', {}).get('lastDeployTime').isoformat() 
                        if app.get('productionBranch', {}).get('lastDeployTime') else None,
                    'status': app.get('productionBranch', {}).get('status'),
                    'thumbnail_url': app.get('productionBranch', {}).get('thumbnailUrl')
                } if app.get('productionBranch') else None,
                'create_time': app.get('createTime').isoformat() if app.get('createTime') else None,
                'update_time': app.get('updateTime').isoformat() if app.get('updateTime') else None,
                'custom_rules': app.get('customRules', []),
                'branches': branches,
                'backend_environments': backend_environments,
                'status': 'ACTIVE' if app.get('productionBranch') else 'NO_PRODUCTION_BRANCH'
            })
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NotFoundException':
                apps.append({
                    'app_id': app_id,
                    'status': 'NOT_FOUND',
                    'error': f"Amplify app {app_id} not found"
                })
            else:
                errors.append(f"Error getting app {app_id}: {str(e)}")
                apps.append({
                    'app_id': app_id,
                    'status': 'ERROR',
                    'error': str(e)
                })
    
    return {
        'total_apps': len(apps),
        'apps': apps,
        'errors': errors if errors else []
    }


def check_amplify_apps(session, region):
    """Check status of Amplify applications."""
    amplify_client = session.client('amplify', region_name=region)
    
    try:
        response = amplify_client.list_apps(maxResults=100)
        
        apps = []
        for app in response.get('apps', []):
            apps.append({
                'app_id': app.get('appId'),
                'name': app.get('name'),
                'status': 'ACTIVE' if app.get('productionBranch') else 'NO_PRODUCTION_BRANCH',
                'default_domain': app.get('defaultDomain'),
                'repository': app.get('repository'),
                'platform': app.get('platform'),
                'create_time': app.get('createTime').isoformat() if app.get('createTime') else None
            })
        
        return {
            'total_apps': len(apps),
            'apps': apps
        }
    except ClientError as e:
        return {
            'error': str(e),
            'total_apps': 0,
            'apps': []
        }


def query_dynamodb_instances(dynamodb_client, table_name):
    """Query DynamoDB table for provisioned EC2 instances."""
    records = []
    
    try:
        paginator = dynamodb_client.get_paginator('scan')
        
        for page in paginator.paginate(TableName=table_name):
            for item in page.get('Items', []):
                record = {}
                for key, value in item.items():
                    # Parse DynamoDB format
                    if 'S' in value:
                        record[key] = value['S']
                    elif 'N' in value:
                        record[key] = value['N']
                    elif 'BOOL' in value:
                        record[key] = value['BOOL']
                
                records.append(record)
        
        return records
    except ClientError as e:
        raise Exception(f"Error scanning DynamoDB table: {str(e)}")


def check_ec2_instance(ec2_client, instance_id):
    """Check the status of an EC2 instance."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response['Reservations']:
            return {
                'instance_id': instance_id,
                'status': 'NOT_FOUND'
            }
        
        instance = response['Reservations'][0]['Instances'][0]
        
        return {
            'instance_id': instance_id,
            'status': instance['State']['Name'],
            'instance_type': instance.get('InstanceType'),
            'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
            'private_ip': instance.get('PrivateIpAddress'),
            'public_ip': instance.get('PublicIpAddress'),
            'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
            'vpc_id': instance.get('VpcId'),
            'subnet_id': instance.get('SubnetId'),
            'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
            return {
                'instance_id': instance_id,
                'status': 'NOT_FOUND'
            }
        raise Exception(f"Error describing instance {instance_id}: {str(e)}")


def check_cloudformation_stacks(session, region, provisioned_products):
    """Check CloudFormation stacks associated with provisioned products."""
    cfn_client = session.client('cloudformation', region_name=region)
    stacks = []
    
    for product in provisioned_products:
        physical_id = product.get('physical_id')
        
        if not physical_id or not physical_id.startswith('arn:aws:cloudformation'):
            continue
        
        # Extract stack name from ARN
        try:
            stack_name = physical_id.split('/')[-2]
            
            response = cfn_client.describe_stacks(StackName=stack_name)
            
            if response.get('Stacks'):
                stack = response['Stacks'][0]
                stacks.append({
                    'stack_name': stack.get('StackName'),
                    'stack_id': stack.get('StackId'),
                    'status': stack.get('StackStatus'),
                    'creation_time': stack.get('CreationTime').isoformat() if stack.get('CreationTime') else None,
                    'last_updated_time': stack.get('LastUpdatedTime').isoformat() if stack.get('LastUpdatedTime') else None,
                    'provisioned_product_id': product.get('id')
                })
        except ClientError as e:
            stacks.append({
                'stack_name': physical_id,
                'status': 'ERROR',
                'error': str(e),
                'provisioned_product_id': product.get('id')
            })
    
    return {
        'total_stacks': len(stacks),
        'stacks': stacks
    }


def check_terraform_workspaces(token, ec2_records):
    """Check Terraform Cloud workspaces."""
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/vnd.api+json'
    }
    
    workspaces = []
    
    try:
        # List workspaces
        response = requests.get(
            'https://app.terraform.io/api/v2/organizations/YOUR_ORG/workspaces',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            for workspace in data.get('data', []):
                workspaces.append({
                    'id': workspace.get('id'),
                    'name': workspace['attributes'].get('name'),
                    'locked': workspace['attributes'].get('locked'),
                    'terraform_version': workspace['attributes'].get('terraform-version'),
                    'working_directory': workspace['attributes'].get('working-directory')
                })
        
        return {
            'total_workspaces': len(workspaces),
            'workspaces': workspaces
        }
    except Exception as e:
        return {
            'error': str(e),
            'total_workspaces': 0,
            'workspaces': []
        }


def format_response(body, status_code=200):
    """Format Lambda response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(body, indent=2, default=str)
    }
