import boto3
import json
from datetime import datetime

def lambda_handler(event, context):
    # Initialize the IAM client
    iam = boto3.client('iam')
    
    # Parse the AWS Config event
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    
    # Check if this is a scheduled notification or a configuration change
    if invoking_event['messageType'] == 'ScheduledNotification':
        return evaluate_compliance_scheduled(iam, rule_parameters)
    else:
        configuration_item = invoking_event.get('configurationItem', {})
        return evaluate_compliance_change(iam, configuration_item, rule_parameters)

def evaluate_compliance_change(iam, configuration_item, rule_parameters):
    """Evaluate compliance based on a configuration change."""
    # Check if we're dealing with an IAM user resource
    if configuration_item['resourceType'] != 'AWS::IAM::User':
        return {
            'compliance_type': 'NOT_APPLICABLE',
            'annotation': 'Resource is not an IAM User'
        }
    
    user_name = configuration_item['resourceName']
    return check_user_compliance(iam, user_name)

def evaluate_compliance_scheduled(iam, rule_parameters):
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
        compliance_result = check_user_compliance(iam, user['UserName'])
        evaluations.append({
            'ComplianceResourceType': 'AWS::IAM::User',
            'ComplianceResourceId': user['UserName'],
            'ComplianceType': compliance_result['compliance_type'],
            'Annotation': compliance_result['annotation'],
            'OrderingTimestamp': datetime.now().isoformat()
        })
    
    # Return the evaluation results
    put_evaluations_request = {
        'Evaluations': evaluations,
        'ResultToken': event['resultToken']
    }
    
    config = boto3.client('config')
    config.put_evaluations(**put_evaluations_request)
    
    return evaluations

def check_user_compliance(iam, user_name):
    """Check if an IAM user has a console password."""
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
