#!/usr/bin/env python3
import boto3
import pandas as pd
import argparse
from datetime import datetime
import os
from botocore.exceptions import ClientError

def check_iam_users_with_console_access(session):
    """Check IAM users in an account and identify those with console access."""
    iam_client = session.client('iam')
    account_id = session.client('sts').get_caller_identity().get('Account')
    
    users_with_console_access = []
    
    try:
        # Get all IAM users
        paginator = iam_client.get_paginator('list_users')
        users = []
        
        for page in paginator.paginate():
            users.extend(page['Users'])
        
        # Check each user for console access
        for user in users:
            username = user['UserName']
            user_detail = {
                'AccountID': account_id,
                'Username': username,
                'CreateDate': user['CreateDate'],
                'HasConsoleAccess': False,
                'PasswordLastUsed': 'Never' if 'PasswordLastUsed' not in user else user['PasswordLastUsed'],
                'MFAEnabled': False
            }
            
            # Check if user has console password
            try:
                login_profile = iam_client.get_login_profile(UserName=username)
                user_detail['HasConsoleAccess'] = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    pass
                else:
                    print(f"Error checking login profile for {username}: {e}")
            
            # Check if MFA is enabled
            try:
                mfa_devices = iam_client.list_mfa_devices(UserName=username)
                user_detail['MFAEnabled'] = len(mfa_devices['MFADevices']) > 0
            except ClientError as e:
                print(f"Error checking MFA for {username}: {e}")
            
            users_with_console_access.append(user_detail)
    
    except Exception as e:
        print(f"Error processing account {account_id}: {e}")
    
    return users_with_console_access

def assume_role(account_id, role_name):
    """Assume a role in another account."""
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='IAMConsolePasswordCheck'
        )
        credentials = response['Credentials']
        
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        return session
    except Exception as e:
        print(f"Error assuming role in account {account_id}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Check IAM users with console access across multiple AWS accounts')
    parser.add_argument('--accounts-file', required=True, help='Path to CSV file with account IDs')
    parser.add_argument('--role-name', default='OrganizationAccountAccessRole', help='Role name to assume in target accounts')
    parser.add_argument('--output', default=f'iam_console_access_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx', help='Output Excel file name')
    
    args = parser.parse_args()
    
    # Read account IDs from file
    try:
        accounts_df = pd.read_csv(args.accounts_file)
        if 'AccountID' not in accounts_df.columns:
            print("Error: CSV file must contain 'AccountID' column")
            return
        account_ids = accounts_df['AccountID'].astype(str).tolist()
    except Exception as e:
        print(f"Error reading accounts file: {e}")
        return
    
    all_users = []
    
    # Process each account
    for account_id in account_ids:
        print(f"Processing account: {account_id}")
        session = assume_role(account_id, args.role_name)
        
        if session:
            users = check_iam_users_with_console_access(session)
            all_users.extend(users)
        else:
            print(f"Skipping account {account_id} due to role assumption failure")
    
    # Create DataFrame and save to Excel
    if all_users:
        df = pd.DataFrame(all_users)
        
        # Format dates for better readability
        for date_col in ['CreateDate', 'PasswordLastUsed']:
            if date_col in df.columns:
                df[date_col] = df[date_col].apply(lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if isinstance(x, datetime) else x)
        
        # Create summary sheet
        summary_data = {
            'TotalAccountsChecked': len(account_ids),
            'TotalUsers': len(df),
            'UsersWithConsoleAccess': df['HasConsoleAccess'].sum(),
            'UsersWithoutMFA': (df['HasConsoleAccess'] & ~df['MFAEnabled']).sum()
        }
        summary_df = pd.DataFrame([summary_data])
        
        # Export to Excel with multiple sheets
        with pd.ExcelWriter(args.output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='IAM Users', index=False)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        print(f"Report generated successfully: {args.output}")
        print(f"Summary: Found {summary_data['UsersWithConsoleAccess']} IAM users with console access across {summary_data['TotalAccountsChecked']} accounts")
        print(f"         {summary_data['UsersWithoutMFA']} users have console access without MFA enabled")
    else:
        print("No IAM users found with console access")

if __name__ == "__main__":
    main()
