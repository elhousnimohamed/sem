#!/usr/bin/env python3
"""
AWS Amplify Deployment Status Checker with CodeCommit Integration
Checks the deployment status and compares with the latest CodeCommit commit.
"""

import boto3
import sys
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError

def get_codecommit_latest_commit(repository_name, branch_name, region='us-east-1'):
    """
    Get the latest commit ID from a CodeCommit repository branch.
    
    Args:
        repository_name (str): CodeCommit repository name
        branch_name (str): Branch name
        region (str): AWS region
    
    Returns:
        dict: Latest commit information
    """
    try:
        client = boto3.client('codecommit', region_name=region)
        
        # Get the branch information
        response = client.get_branch(
            repositoryName=repository_name,
            branchName=branch_name
        )
        
        commit_id = response['branch']['commitId']
        
        # Get commit details
        commit_response = client.get_commit(
            repositoryName=repository_name,
            commitId=commit_id
        )
        
        commit = commit_response['commit']
        
        return {
            'commit_id': commit_id,
            'message': commit.get('message', 'N/A'),
            'author': commit.get('author', {}).get('name', 'N/A'),
            'date': commit.get('author', {}).get('date')
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'RepositoryDoesNotExistException':
            print(f"  Error: Repository '{repository_name}' not found")
        elif error_code == 'BranchDoesNotExistException':
            print(f"  Error: Branch '{branch_name}' not found in repository")
        else:
            print(f"  Error fetching CodeCommit data: {e}")
        return None
    except Exception as e:
        print(f"  Unexpected error fetching CodeCommit data: {e}")
        return None


def extract_repo_name_from_url(repository_url):
    """
    Extract repository name from CodeCommit URL.
    
    Args:
        repository_url (str): Full CodeCommit repository URL
    
    Returns:
        str: Repository name
    """
    # CodeCommit URLs can be in formats like:
    # https://git-codecommit.us-east-1.amazonaws.com/v1/repos/my-repo
    # or ssh://git-codecommit.us-east-1.amazonaws.com/v1/repos/my-repo
    
    if '/repos/' in repository_url:
        return repository_url.split('/repos/')[-1].rstrip('/')
    
    # If it's just the repo name
    return repository_url


def check_amplify_status(app_id, region='us-east-1'):
    """
    Check the deployment status of an Amplify app and compare with CodeCommit.
    
    Args:
        app_id (str): The Amplify App ID
        region (str): AWS region (default: us-east-1)
    
    Returns:
        dict: Status information about the app and its branches
    """
    try:
        # Initialize Amplify client
        client = boto3.client('amplify', region_name=region)
        
        # Get app details
        print(f"Fetching details for Amplify App: {app_id}")
        print("=" * 80)
        
        app_response = client.get_app(appId=app_id)
        app = app_response['app']
        
        print(f"App Name: {app['name']}")
        print(f"Default Domain: {app['defaultDomain']}")
        
        repository_url = app.get('repository', 'N/A')
        print(f"Repository: {repository_url}")
        print(f"Platform: {app.get('platform', 'N/A')}")
        
        # Check if it's a CodeCommit repository
        is_codecommit = 'codecommit' in repository_url.lower()
        repo_name = None
        
        if is_codecommit:
            repo_name = extract_repo_name_from_url(repository_url)
            print(f"CodeCommit Repository Name: {repo_name}")
        
        print("=" * 80)
        
        # List all branches
        branches_response = client.list_branches(appId=app_id)
        branches = branches_response['branches']
        
        if not branches:
            print("No branches found for this app.")
            return {'app': app, 'branches': [], 'is_codecommit': is_codecommit}
        
        print(f"\nFound {len(branches)} branch(es):\n")
        
        branch_statuses = []
        
        for branch in branches:
            branch_name = branch['branchName']
            print(f"Branch: {branch_name}")
            print("-" * 80)
            print(f"  Stage: {branch.get('stage', 'N/A')}")
            print(f"  Auto Build: {branch.get('enableAutoBuild', False)}")
            
            # Get CodeCommit latest commit for this branch
            codecommit_commit = None
            if is_codecommit and repo_name:
                print(f"\n  Checking CodeCommit for latest commit...")
                codecommit_commit = get_codecommit_latest_commit(repo_name, branch_name, region)
                
                if codecommit_commit:
                    print(f"  Latest CodeCommit Commit: {codecommit_commit['commit_id'][:8]}")
                    print(f"  Author: {codecommit_commit['author']}")
                    print(f"  Message: {codecommit_commit['message'][:60]}...")
                    if codecommit_commit['date']:
                        print(f"  Date: {codecommit_commit['date']}")
            
            # Get latest Amplify deployment job for this branch
            try:
                jobs_response = client.list_jobs(
                    appId=app_id,
                    branchName=branch_name,
                    maxResults=1
                )
                
                if jobs_response['jobSummaries']:
                    latest_job = jobs_response['jobSummaries'][0]
                    status = latest_job['status']
                    deployed_commit_id = latest_job.get('commitId', 'N/A')
                    commit_message = latest_job.get('commitMessage', 'N/A')
                    start_time = latest_job.get('startTime')
                    end_time = latest_job.get('endTime')
                    
                    print(f"\n  Latest Amplify Deployment:")
                    print(f"  Status: {status}")
                    print(f"  Deployed Commit: {deployed_commit_id[:8] if deployed_commit_id != 'N/A' else 'N/A'}")
                    print(f"  Message: {commit_message[:60]}...")
                    
                    if start_time:
                        print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    if end_time:
                        print(f"  Ended: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    # Compare commits if we have both
                    is_up_to_date = False
                    if codecommit_commit and deployed_commit_id != 'N/A':
                        is_up_to_date = codecommit_commit['commit_id'] == deployed_commit_id
                        
                        print(f"\n  🔍 Commit Comparison:")
                        if is_up_to_date:
                            print(f"  ✅ DEPLOYED is UP-TO-DATE with CodeCommit")
                        else:
                            print(f"  ⚠️  DEPLOYED is OUT-OF-SYNC with CodeCommit")
                            print(f"     CodeCommit has: {codecommit_commit['commit_id'][:8]}")
                            print(f"     Deployed has:   {deployed_commit_id[:8]}")
                    
                    # Get detailed job info if deployment is in progress
                    if status in ['PENDING', 'PROVISIONING', 'RUNNING']:
                        job_detail = client.get_job(
                            appId=app_id,
                            branchName=branch_name,
                            jobId=latest_job['jobId']
                        )
                        steps = job_detail['job'].get('steps', [])
                        print(f"\n  Deployment Steps:")
                        for step in steps:
                            step_status = step['status']
                            step_name = step['stepName']
                            status_icon = "⏳" if step_status == "RUNNING" else "✓" if step_status == "SUCCEED" else "○"
                            print(f"    {status_icon} {step_name}: {step_status}")
                    
                    branch_statuses.append({
                        'branch': branch_name,
                        'status': status,
                        'stage': branch.get('stage', 'N/A'),
                        'deployed_commit': deployed_commit_id,
                        'codecommit_commit': codecommit_commit['commit_id'] if codecommit_commit else None,
                        'is_up_to_date': is_up_to_date,
                        'job': latest_job
                    })
                else:
                    print(f"\n  No deployments found")
                    branch_statuses.append({
                        'branch': branch_name,
                        'status': 'NO_DEPLOYMENTS',
                        'stage': branch.get('stage', 'N/A'),
                        'codecommit_commit': codecommit_commit['commit_id'] if codecommit_commit else None,
                        'is_up_to_date': False
                    })
                    
            except ClientError as e:
                print(f"  Error fetching jobs: {e}")
            
            print("\n")
        
        return {
            'app': app,
            'branches': branch_statuses,
            'is_codecommit': is_codecommit,
            'repo_name': repo_name
        }
        
    except NoCredentialsError:
        print("Error: AWS credentials not found.")
        print("Please configure your AWS credentials using:")
        print("  - AWS CLI: aws configure")
        print("  - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
        sys.exit(1)
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NotFoundException':
            print(f"Error: Amplify app '{app_id}' not found in region '{region}'")
        elif error_code == 'AccessDeniedException':
            print("Error: Access denied. Check your IAM permissions for Amplify.")
        else:
            print(f"Error: {e}")
        sys.exit(1)
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


def main():
    """Main function to run the status checker."""
    if len(sys.argv) < 2:
        print("Usage: python amplify_status.py <app-id> [region]")
        print("\nExample:")
        print("  python amplify_status.py d2a3b4c5d6e7f8 us-east-1")
        sys.exit(1)
    
    app_id = sys.argv[1]
    region = sys.argv[2] if len(sys.argv) > 2 else 'us-east-1'
    
    result = check_amplify_status(app_id, region)
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    if result['branches']:
        in_progress = sum(1 for b in result['branches'] 
                         if b['status'] in ['PENDING', 'PROVISIONING', 'RUNNING'])
        succeeded = sum(1 for b in result['branches'] if b['status'] == 'SUCCEED')
        failed = sum(1 for b in result['branches'] if b['status'] == 'FAILED')
        
        print(f"Total Branches: {len(result['branches'])}")
        print(f"Deployments In Progress: {in_progress}")
        print(f"Recent Successful Deployments: {succeeded}")
        print(f"Recent Failed Deployments: {failed}")
        
        # Check sync status
        if result['is_codecommit']:
            up_to_date = sum(1 for b in result['branches'] if b.get('is_up_to_date', False))
            out_of_sync = sum(1 for b in result['branches'] 
                            if b.get('codecommit_commit') and not b.get('is_up_to_date', False))
            
            print(f"\nCodeCommit Sync Status:")
            print(f"  ✅ Up-to-date branches: {up_to_date}")
            print(f"  ⚠️  Out-of-sync branches: {out_of_sync}")
            
            # List out-of-sync branches
            if out_of_sync > 0:
                print(f"\n  Branches needing deployment:")
                for b in result['branches']:
                    if b.get('codecommit_commit') and not b.get('is_up_to_date', False):
                        print(f"    - {b['branch']}")
    else:
        print("No branches found")


if __name__ == '__main__':
    main()
