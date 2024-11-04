import os
import time
import requests
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, Any

class TerraformRunStatus(Enum):
    """Enum for Terraform run statuses"""
    PENDING = "pending"
    PLAN_QUEUED = "plan_queued"
    PLANNING = "planning"
    PLANNED = "planned"
    COST_ESTIMATING = "cost_estimating"
    COST_ESTIMATED = "cost_estimated"
    POLICY_CHECKING = "policy_checking"
    POLICY_OVERRIDE = "policy_override"
    POLICY_SOFT_FAILED = "policy_soft_failed"
    POLICY_CHECKED = "policy_checked"
    CONFIRMED = "confirmed"
    PLANNED_AND_FINISHED = "planned_and_finished"
    APPLY_QUEUED = "apply_queued"
    APPLYING = "applying"
    APPLIED = "applied"
    DISCARDED = "discarded"
    ERRORED = "errored"
    CANCELED = "canceled"
    FORCE_CANCELED = "force_canceled"

class TerraformStatusChecker:
    """Class to check Terraform run status in Terraform Cloud"""
    
    def __init__(self, api_token: str, workspace_name: str, commit_sha: str, max_wait_minutes: int = 30):
        self.api_token = api_token
        self.workspace_name = workspace_name
        self.commit_sha = commit_sha
        self.max_wait_minutes = max_wait_minutes
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/vnd.api+json'
        }
        self.base_url = "https://app.terraform.io/api/v2"
        self.wait_interval = 10  # seconds between checks

    def get_latest_run(self) -> Optional[Dict[str, Any]]:
        """Fetch the latest run for the given commit SHA"""
        url = f"{self.base_url}/workspaces/{self.workspace_name}/runs"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            
            runs = response.json()['data']
            return next(
                (run for run in runs if run['attributes']['commit-sha'] == self.commit_sha),
                None
            )
        except requests.exceptions.RequestException as e:
            print(f"Error fetching run status: {str(e)}")
            return None

    def wait_for_run(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Wait for the run to appear in Terraform Cloud"""
        print(f"Waiting for Terraform run for commit {self.commit_sha}...")
        
        while datetime.now() < end_time:
            run = self.get_latest_run()
            if run:
                print("✅ Found Terraform run!")
                return run
            
            # Calculate and display remaining wait time
            elapsed = datetime.now() - start_time
            remaining = self.max_wait_minutes - (elapsed.total_seconds() / 60)
            print(f"Run not found yet. Waiting... ({remaining:.1f} minutes remaining)")
            
            time.sleep(self.wait_interval)
        
        raise TimeoutError(
            f"⏰ No Terraform run found for commit {self.commit_sha} within {self.max_wait_minutes} minutes"
        )

    def check_run_status(self) -> None:
        """
        Check the status of a Terraform run (plan and apply) for the given commit SHA.
        Waits for the run to appear and then monitors its status until completion.
        """
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=self.max_wait_minutes)
        
        # Wait for the run to appear first
        run = self.wait_for_run(start_time, end_time)
        
        # Now monitor the run status
        last_status = None
        while datetime.now() < end_time:
            current_status = TerraformRunStatus(run['attributes']['status'])
            
            # Print status update only if it changed
            if current_status != last_status:
                print(f"Current status: {current_status.value}")
                last_status = current_status

            # Check for final states
            if current_status == TerraformRunStatus.APPLIED:
                print(f"✅ Terraform run for commit {self.commit_sha} completed successfully!")
                return
            elif current_status in [
                TerraformRunStatus.ERRORED,
                TerraformRunStatus.CANCELED,
                TerraformRunStatus.FORCE_CANCELED,
                TerraformRunStatus.DISCARDED
            ]:
                raise RuntimeError(
                    f"❌ Terraform run for commit {self.commit_sha} failed with status: {current_status.value}"
                )

            # Get updated run status
            time.sleep(self.wait_interval)
            run = self.get_latest_run()
            if not run:
                print("⚠️ Warning: Lost connection to run. Attempting to reconnect...")
                run = self.wait_for_run(datetime.now(), end_time)

        raise TimeoutError(
            f"⏰ Terraform run for commit {self.commit_sha} did not complete within {self.max_wait_minutes} minutes"
        )

def run_action() -> None:
    """Main function to run the GitHub Action"""
    # Get required input variables
    required_inputs = {
        'workspace_name': 'INPUT_WORKSPACE_NAME',
        'commit_sha': 'INPUT_COMMIT_SHA',
        'api_token': 'INPUT_TFC_API_TOKEN'
    }
    
    inputs = {}
    for key, env_var in required_inputs.items():
        value = os.getenv(env_var)
        if not value:
            raise ValueError(f"Missing required input: {key}")
        inputs[key] = value

    # Get optional inputs
    max_wait_minutes = int(os.getenv('INPUT_MAX_WAIT_MINUTES', '30'))

    # Initialize and run the status checker
    try:
        checker = TerraformStatusChecker(
            api_token=inputs['api_token'],
            workspace_name=inputs['workspace_name'],
            commit_sha=inputs['commit_sha'],
            max_wait_minutes=max_wait_minutes
        )
        checker.check_run_status()
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    run_action()
