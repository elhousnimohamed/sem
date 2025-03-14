import boto3
import json

def enforce_mfa(events, context):
    iam = boto3.client('iam')
    username = events['ResourceId']
    
    # Create policy to deny all actions except MFA management & password change
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowViewAccountInfo",
                "Effect": "Allow",
                "Action": [
                    "iam:GetAccountPasswordPolicy",
                    "iam:GetAccountSummary",
                    "iam:ListVirtualMFADevices"
                ],
                "Resource": "*"
            },
            {
                "Sid": "AllowManageOwnPasswords",
                "Effect": "Allow",
                "Action": [
                    "iam:ChangePassword",
                    "iam:GetUser"
                ],
                "Resource": "arn:aws:iam::*:user/${aws:username}"
            },
            {
                "Sid": "AllowManageOwnMFA",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateVirtualMFADevice",
                    "iam:EnableMFADevice",
                    "iam:ResyncMFADevice",
                    "iam:ListMFADevices"
                ],
                "Resource": [
                    "arn:aws:iam::*:user/${aws:username}",
                    "arn:aws:iam::*:mfa/${aws:username}"
                ]
            },
            {
                "Sid": "DenyAllExceptMFAManagement",
                "Effect": "Deny",
                "NotAction": [
                    "iam:ChangePassword",
                    "iam:CreateVirtualMFADevice",
                    "iam:EnableMFADevice",
                    "iam:GetUser",
                    "iam:ListMFADevices",
                    "iam:ListVirtualMFADevices",
                    "iam:ResyncMFADevice",
                    "iam:GetAccountPasswordPolicy",
                    "iam:GetAccountSummary"
                ],
                "Resource": "*",
                "Condition": {
                    "BoolIfExists": {
                        "aws:MultiFactorAuthPresent": "false"
                    }
                }
            }
        ]
    }
    
    policy_name = f"EnforceMFA-{username}"
    
    try:
        # Check if policy already exists
        try:
            iam.get_user_policy(UserName=username, PolicyName=policy_name)
            # Policy exists, update it
            iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
        except iam.exceptions.NoSuchEntityException:
            # Policy doesn't exist, create it
            iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
        
        return {
            'Status': 'Success',
            'Message': f'MFA enforcement policy applied to user {username}'
        }
    except Exception as e:
        return {
            'Status': 'Failed',
            'Message': f'Error applying MFA policy: {str(e)}'
        }
