import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    # Initialize the IAM client
    iam = boto3.client('iam')
    
    # Parse the AWS Config event
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    
    # Extract parameters with defaults
    excluded_users = rule_parameters.get('ExcludedUsers', '').split(',')
    excluded_users = [user.strip() for user in excluded_users if user.strip()]
    
    # Check if this is a scheduled notification or a configuration change
    if invoking_event['messageType'] == 'ScheduledNotification':
        return evaluate_compliance_scheduled(iam, excluded_users, event)
    else:
        configuration_item = invoking_event.get('configurationItem', {})
        return evaluate_compliance_change(iam, configuration_item, excluded_users, event)

def evaluate_compliance_change(iam, configuration_item, excluded_users, event):
    """Evaluate compliance based on a configuration change."""
    # Check if we're dealing with an IAM user resource
    if configuration_item['resourceType'] != 'AWS::IAM::User':
        evaluation = {
            'ComplianceResourceType': configuration_item['resourceType'],
            'ComplianceResourceId': configuration_item['resourceId'],
            'ComplianceType': 'NOT_APPLICABLE',
            'Annotation': 'Resource is not an IAM User',
            'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
        }
        
        config = boto3.client('config')
        config.put_evaluations(
            Evaluations=[evaluation],
            ResultToken=event['resultToken']
        )
        
        return [evaluation]
    
    user_name = configuration_item['resourceName']
    compliance_result = check_user_compliance(iam, user_name, excluded_users)
    
    evaluation = {
        'ComplianceResourceType': configuration_item['resourceType'],
        'ComplianceResourceId': configuration_item['resourceId'],
        'ComplianceType': compliance_result['compliance_type'],
        'Annotation': compliance_result['annotation'],
        'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
    }
    
    config = boto3.client('config')
    config.put_evaluations(
        Evaluations=[evaluation],
        ResultToken=event['resultToken']
    )
    
    return [evaluation]

def evaluate_compliance_scheduled(iam, excluded_users, event):
    """Evaluate compliance for all IAM users."""
    # Get all IAM users
    all_users = []
    marker = None
    
    while True:
        if marker:
            response = iam.list_users(Marker=marker)
        else:
            response = iam.list_users()
        
        all_users.extend(response['Users'])
        
        if response.get('IsTruncated', False):
            marker = response['Marker']
        else:
            break
    
    # Check compliance for each user
    evaluations = []
    for user in all_users:
        compliance_result = check_user_compliance(iam, user['UserName'], excluded_users)
        evaluations.append({
            'ComplianceResourceType': 'AWS::IAM::User',
            'ComplianceResourceId': user['UserName'],
            'ComplianceType': compliance_result['compliance_type'],
            'Annotation': compliance_result['annotation'],
            'OrderingTimestamp': datetime.now().isoformat()
        })
    
    # Return the evaluation results
    config = boto3.client('config')
    config.put_evaluations(
        Evaluations=evaluations,
        ResultToken=event['resultToken']
    )
    
    return evaluations

def check_user_compliance(iam, user_name, excluded_users):
    """Check if an IAM user has a console password."""
    # Check if the user is in the excluded list
    if user_name in excluded_users:
        return {
            'compliance_type': 'COMPLIANT',
            'annotation': f'IAM user {user_name} is excluded from this rule'
        }
    
    try:
        # Check if the user has a password
        response = iam.get_login_profile(UserName=user_name)
        # If we get here, the user has a password
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': f'IAM user {user_name} has a console password'
        }
    except iam.exceptions.NoSuchEntityException:
        # No login profile means no password
        return {
            'compliance_type': 'COMPLIANT',
            'annotation': f'IAM user {user_name} does not have a console password'
        }
    except Exception as e:
        # Handle other errors
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': f'Error checking IAM user {user_name}: {str(e)}'
        }
