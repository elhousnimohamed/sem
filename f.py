import json
import boto3
import logging
import requests
import os
from botocore.exceptions import ClientError
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Triggers Service Catalog product provisioning and manages state via /result endpoint
    """
    try:
        # Check if this is a status check or initial provisioning
        if event.get('source') == 'aws.events' or 'Records' in event:
            # This is a scheduled status check
            return handle_status_check(event, context)
        else:
            # This is initial provisioning request
            return handle_provisioning_request(event, context)
            
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        # Update result endpoint with error
        update_result_state('FAILED', str(e), event.get('request_id'))
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def handle_provisioning_request(event, context):
    """
    Handle initial Service Catalog provisioning request
    """
    # Extract configuration
    request_id = event.get('request_id', context.aws_request_id)
    product_id = event.get('product_id', os.environ.get('PRODUCT_ID'))
    artifact_id = event.get('artifact_id', os.environ.get('ARTIFACT_ID'))
    product_name = event.get('product_name', f"Product-{request_id}")
    parameters = event.get('parameters', {})
    
    # Update initial state
    update_result_state('INITIATING', 'Starting Service Catalog provisioning', request_id)
    
    try:
        # Get cross-account Service Catalog client
        sc_client = get_cross_account_client()
        
        # Start provisioning
        response = provision_product(
            client=sc_client,
            product_id=product_id,
            artifact_id=artifact_id,
            product_name=product_name,
            parameters=parameters
        )
        
        record_id = response['RecordId']
        
        # Update state with record ID
        update_result_state(
            'IN_PROGRESS', 
            f'Provisioning started. Record ID: {record_id}',
            request_id,
            record_id=record_id
        )
        
        # Schedule status monitoring
        schedule_status_monitoring(record_id, request_id)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Service Catalog provisioning initiated',
                'request_id': request_id,
                'record_id': record_id,
                'status': 'IN_PROGRESS',
                'estimated_duration': '45 minutes'
            })
        }
        
    except Exception as e:
        logger.error(f"Error during provisioning: {str(e)}")
        update_result_state('FAILED', f'Provisioning failed: {str(e)}', request_id)
        raise

def handle_status_check(event, context):
    """
    Handle scheduled status checks for ongoing provisioning
    """
    try:
        # Extract record_id and request_id from the event
        if 'Records' in event:
            # SQS message
            message = json.loads(event['Records'][0]['body'])
            record_id = message['record_id']
            request_id = message['request_id']
        else:
            # EventBridge scheduled event
            record_id = event['record_id']
            request_id = event['request_id']
        
        # Get cross-account Service Catalog client
        sc_client = get_cross_account_client()
        
        # Check current status
        status_info = check_provisioning_status(sc_client, record_id)
        
        # Update result endpoint
        update_result_state(
            status_info['status'],
            status_info['message'],
            request_id,
            record_id=record_id,
            details=status_info
        )
        
        # If still in progress, schedule next check
        if status_info['status'] == 'IN_PROGRESS':
            schedule_next_status_check(record_id, request_id)
        else:
            logger.info(f"Provisioning completed with status: {status_info['status']}")
        
        return {
            'statusCode': 200,
            'body': json.dumps(status_info)
        }
        
    except Exception as e:
        logger.error(f"Error during status check: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def get_cross_account_client():
    """
    Get Service Catalog client for cross-account access
    """
    cross_account_role_arn = os.environ.get('CROSS_ACCOUNT_ROLE_ARN')
    
    if not cross_account_role_arn:
        raise ValueError("CROSS_ACCOUNT_ROLE_ARN environment variable not set")
    
    # Assume cross-account role
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=cross_account_role_arn,
        RoleSessionName=f'ServiceCatalogAccess-{datetime.now().strftime("%Y%m%d%H%M%S")}'
    )
    
    credentials = response['Credentials']
    
    # Create Service Catalog client with assumed role credentials
    sc_client = boto3.client(
        'servicecatalog',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    return sc_client

def provision_product(client, product_id, artifact_id, product_name, parameters=None):
    """
    Provision Service Catalog product
    """
    provision_params = {
        'ProductId': product_id,
        'ProvisioningArtifactId': artifact_id,
        'ProvisionedProductName': product_name,
        'ProvisionToken': f"token-{product_name}-{int(datetime.now().timestamp())}"
    }
    
    # Add provisioning parameters if provided
    if parameters:
        provision_params['ProvisioningParameters'] = [
            {
                'Key': key,
                'Value': str(value)
            } for key, value in parameters.items()
        ]
    
    # Add tags
    provision_params['Tags'] = [
        {
            'Key': 'CreatedBy',
            'Value': 'CrossAccountLambda'
        },
        {
            'Key': 'RequestTime',
            'Value': datetime.now().isoformat()
        }
    ]
    
    try:
        response = client.provision_product(**provision_params)
        return {
            'RecordId': response['RecordDetail']['RecordId'],
            'ProvisionedProductId': response['RecordDetail'].get('ProvisionedProductId'),
            'Status': response['RecordDetail']['Status'],
            'CreatedTime': response['RecordDetail']['CreatedTime'].isoformat()
        }
    except ClientError as e:
        logger.error(f"AWS Service Catalog error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during provisioning: {e}")
        raise

def check_provisioning_status(client, record_id):
    """
    Check the current status of a provisioning operation
    """
    try:
        response = client.describe_record(Id=record_id)
        record_detail = response['RecordDetail']
        
        status = record_detail['Status']
        
        # Map Service Catalog status to our status
        if status == 'CREATED':
            mapped_status = 'SUCCEEDED'
            message = 'Product provisioned successfully'
        elif status == 'FAILED':
            mapped_status = 'FAILED'
            message = record_detail.get('StatusMessage', 'Provisioning failed')
        elif status in ['IN_PROGRESS', 'IN_PROGRESS_IN_ERROR']:
            mapped_status = 'IN_PROGRESS'
            message = f'Provisioning in progress: {record_detail.get("StatusMessage", "")}'
        else:
            mapped_status = status
            message = record_detail.get('StatusMessage', f'Status: {status}')
        
        return {
            'status': mapped_status,
            'message': message,
            'record_id': record_id,
            'updated_time': record_detail['UpdatedTime'].isoformat(),
            'raw_status': status,
            'outputs': record_detail.get('RecordOutputs', [])
        }
        
    except ClientError as e:
        logger.error(f"Error checking status: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error checking status: {e}")
        raise

def update_result_state(status, message, request_id, record_id=None, details=None):
    """
    Update the result endpoint with current state
    """
    result_endpoint = os.environ.get('RESULT_ENDPOINT_URL')
    
    if not result_endpoint:
        logger.warning("RESULT_ENDPOINT_URL not configured, skipping state update")
        return
    
    payload = {
        'request_id': request_id,
        'status': status,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'record_id': record_id
    }
    
    if details:
        payload['details'] = details
    
    try:
        response = requests.post(
            result_endpoint,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code == 200:
            logger.info(f"Successfully updated result state: {status}")
        else:
            logger.error(f"Failed to update result state: {response.status_code} - {response.text}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error calling result endpoint: {str(e)}")

def schedule_status_monitoring(record_id, request_id):
    """
    Schedule periodic status monitoring using SQS
    """
    sqs_queue_url = os.environ.get('STATUS_QUEUE_URL')
    
    if not sqs_queue_url:
        logger.warning("STATUS_QUEUE_URL not configured, status monitoring disabled")
        return
    
    sqs = boto3.client('sqs')
    
    message = {
        'record_id': record_id,
        'request_id': request_id,
        'check_count': 0
    }
    
    # Send first status check after 5 minutes
    sqs.send_message(
        QueueUrl=sqs_queue_url,
        MessageBody=json.dumps(message),
        DelaySeconds=300  # 5 minutes
    )
    
    logger.info(f"Scheduled status monitoring for record_id: {record_id}")

def schedule_next_status_check(record_id, request_id, check_count=0):
    """
    Schedule the next status check
    """
    sqs_queue_url = os.environ.get('STATUS_QUEUE_URL')
    
    if not sqs_queue_url:
        return
    
    # Stop checking after 60 attempts (5 hours)
    if check_count >= 60:
        logger.error(f"Max status checks reached for record_id: {record_id}")
        update_result_state('TIMEOUT', 'Status checking timed out', request_id, record_id)
        return
    
    sqs = boto3.client('sqs')
    
    message = {
        'record_id': record_id,
        'request_id': request_id,
        'check_count': check_count + 1
    }
    
    # Check every 5 minutes
    sqs.send_message(
        QueueUrl=sqs_queue_url,
        MessageBody=json.dumps(message),
        DelaySeconds=300
    )

# Example usage
if __name__ == "__main__":
    # Test event
    test_event = {
        'request_id': 'test-12345',
        'product_id': 'prod-xxxxxxxxx',
        'artifact_id': 'pa-xxxxxxxxx',
        'product_name': 'TestProduct-12345',
        'parameters': {
            'InstanceType': 't3.micro',
            'VpcId': 'vpc-xxxxxxxxx',
            'SubnetId': 'subnet-xxxxxxxxx'
        }
    }
    
    class MockContext:
        aws_request_id = 'test-request-id'
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2))
