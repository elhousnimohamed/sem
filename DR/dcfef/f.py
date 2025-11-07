"""
AWS Lambda Function A: VPC Worker (Main Coordinator)
Runs inside private VPC, coordinates workflow, handles VPC-specific operations
"""
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
import requests
from botocore.exceptions import ClientError
from boto3.session import Session

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
log_levels = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARN,
    "ERROR": logging.ERROR,
}
LOGGER = logging.getLogger()
LOGGER.setLevel(log_levels[LOG_LEVEL])

# Custom certificate handling
CERT_PATH = '/tmp/cert.pem'
CERT_CONTENT = """ 
cert content
"""

try:
    if not os.path.exists(CERT_PATH):
        with open(CERT_PATH, 'w') as cert_file:
            cert_file.write(CERT_CONTENT)
        LOGGER.info("Certificate written successfully")
except IOError as e:
    LOGGER.error(f"Failed to write certificate: {e}")

def _get_required_env(key: str) -> str:
    """Get required environment variable or raise clear error"""
    value = os.environ.get(key)
    if not value:
        raise ValueError(f"Missing required environment variable: {key}")
    return value

try:
    ROLE_ARN = _get_required_env("ROLE_ARN")
    REGION = _get_required_env("REGION")
    DYNAMODB_TABLE_NAME = _get_required_env("DYNAMODB_TABLE_NAME")
    DYNAMODB_CONFIG_TABLE_NAME = _get_required_env("DYNAMODB_CONFIG_TABLE_NAME")
    TFE_HOST = _get_required_env("TFE_HOST")
    SHARED_TFE_ORG = _get_required_env("SHARED_TFE_ORG")
    TERRAFORM_MODULE_NAME = _get_required_env("TERRAFORM_MODULE_NAME")
    TERRAFORM_PROVIDER = _get_required_env("TERRAFORM_PROVIDER")
    ENTITY_NAME = _get_required_env("ENTITY_NAME")
    FUNCTION_B_NAME = _get_required_env("FUNCTION_B_NAME")  # New: Lambda Function B name
except ValueError as e:
    LOGGER.error(f"Configuration error: {e}")

def get_configuration():
    """Get global configuration from DynamoDB table"""
    config = {}
    dynamodb_resource = boto3.resource("dynamodb")
    ddb_config_table = dynamodb_resource.Table(DYNAMODB_CONFIG_TABLE_NAME)
    ddb_res = ddb_config_table.scan()
    ddb_data = ddb_res["Items"]
    while "LastEvaluatedKey" in ddb_res:
        ddb_res = ddb_config_table.scan(ExclusiveStartKey=ddb_res["LastEvaluatedKey"])
        ddb_data.extend(ddb_res["Items"])
    for item in ddb_data:
        config[item["name"]] = item["value"]
    LOGGER.info(f"Running with configuration: {config}")
    return config

CONFIG = get_configuration()

AWS_CLIENT_CONFIG = boto3.session.Config(
    connect_timeout=5,
    read_timeout=30,
    retries={'max_attempts': 3, 'mode': 'standard'}
)

HTTP_TIMEOUT = 15

def _get_tfe_token() -> str:
    """Retrieve TFE token from Secrets Manager"""
    LOGGER.info("Retrieving TFE token from secrets manager...")
    sm_client = boto3.client("secretsmanager", region_name=REGION, config=AWS_CLIENT_CONFIG)
    try:
        value = sm_client.get_secret_value(SecretId=CONFIG["TFE_TOKEN_SECRET_ARN"])
        secret_json = json.loads(value["SecretString"])
        return secret_json["TFE_TOKEN"]
    except Exception as e:
        LOGGER.error(f"Error retrieving TFE token: {e}")
        raise

try:
    TFE_TOKEN = _get_tfe_token()
except Exception as e:
    LOGGER.error(f"Error retrieving TFE token: {e}")

# Reusable HTTP session for Terraform Enterprise API
TFE_SESSION = requests.Session()
TFE_SESSION.headers.update({
    "Authorization": f"Bearer {TFE_TOKEN}",
    "Content-Type": "application/vnd.api+json"
})
TFE_SESSION.verify = CERT_PATH

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class DRCheckResult:
    """Encapsulates the complete DR check results"""
    timestamp: str
    status: str = "SUCCESS"
    dr_tool: Dict[str, Any] = field(default_factory=dict)
    ec2_instances: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add_error(self, msg: str, component: str = "") -> None:
        """Add error and update status"""
        error_msg = f"[{component}] {msg}" if component else msg
        self.errors.append(error_msg)
        if self.status == "SUCCESS":
            self.status = "PARTIAL"
        LOGGER.warning(error_msg)

# ============================================================================
# LAMBDA HANDLER - Main entry point
# ============================================================================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for DR pre-check validation
    Coordinates between VPC operations and public API calls via Function B
    """
    
    LOGGER.info('## EVENT')
    LOGGER.info(f"## Received event: {json.dumps(event, default=str)}")
    
    LOGGER.info('## ENVIRONMENT VARIABLES')
    LOGGER.info(json.dumps(dict(os.environ)))
    
    LOGGER.info('## CALLER')
    LOGGER.info(json.dumps(boto3.client('sts').get_caller_identity()))
    
    result = DRCheckResult(timestamp=datetime.now(timezone.utc).isoformat())
    
    try:
        base_session = boto3.Session()
        
        # Step 0: Get latest Terraform module version (uses TFE API - VPC accessible)
        latest_tf_version = _get_latest_terraform_version(result)
        
        # Step 1: Assume role in Tool Account
        tool_session = _assume_tool_role(base_session, result)
        if not tool_session:
            return _format_response(result, status_code=500)
        
        # Step 2: Query Service Catalog via Function B (public API)
        service_catalog_data = _invoke_function_b_service_catalog(tool_session, result)
        if service_catalog_data:
            result.dr_tool.update(service_catalog_data)
        
        # Step 3: Amplify App Check via Function B (public API)
        if result.dr_tool.get("provisioned_product_id"):
            amplify_status = _invoke_function_b_amplify_check(
                tool_session, 
                result.dr_tool["provisioned_product_id"],
                result
            )
            if amplify_status:
                result.dr_tool["amplify_app"] = amplify_status
                LOGGER.info(f"Amplify application status: {amplify_status.get('status')}")
        
        # Step 4: Query DynamoDB for EC2 records (VPC operation)
        ec2_records = _query_dynamodb_records(tool_session, result)
        
        # Step 5: Process EC2 instances per account
        _process_ec2_instances(tool_session, ec2_records, latest_tf_version, result)
        
        # Determine final status
        if result.errors:
            if result.ec2_instances or result.dr_tool:
                result.status = "PARTIAL"
            else:
                result.status = "FAILED"
        
        LOGGER.info(f"DR check completed - Status: {result.status}, "
                   f"Instances: {len(result.ec2_instances)}, "
                   f"Errors: {len(result.errors)}")
        
        return _format_response(result)
        
    except Exception as e:
        LOGGER.exception("Unhandled exception in lambda_handler")
        result.add_error(f"Critical failure: {str(e)}", "Lambda")
        result.status = "FAILED"
        return _format_response(result, status_code=500)

# ============================================================================
# FUNCTION B INVOCATION - Public API operations
# ============================================================================

def _invoke_function_b(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Invoke Function B (public handler) with given payload
    
    Args:
        payload: Request payload for Function B
        
    Returns:
        Response from Function B or None on error
    """
    try:
        lambda_client = boto3.client('lambda', region_name=REGION, config=AWS_CLIENT_CONFIG)
        
        LOGGER.info(f"Invoking Function B: {FUNCTION_B_NAME}")
        response = lambda_client.invoke(
            FunctionName=FUNCTION_B_NAME,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        
        response_payload = json.loads(response['Payload'].read())
        
        # Check for errors in response
        if response.get('FunctionError'):
            LOGGER.error(f"Function B returned error: {response_payload}")
            return None
        
        return response_payload
        
    except ClientError as e:
        LOGGER.error(f"Failed to invoke Function B: {e}")
        return None
    except Exception as e:
        LOGGER.error(f"Unexpected error invoking Function B: {e}")
        return None


def _invoke_function_b_service_catalog(
    tool_session: Session, 
    result: DRCheckResult
) -> Optional[Dict[str, Any]]:
    """
    Invoke Function B to query Service Catalog
    
    Args:
        tool_session: Boto3 session with tool account credentials
        result: Result object to record errors
        
    Returns:
        Service Catalog data or None on error
    """
    LOGGER.info("Querying Service Catalog via Function B")
    
    try:
        # Get credentials from tool session
        credentials = tool_session.get_credentials()
        frozen_creds = credentials.get_frozen_credentials()
        
        payload = {
            "operation": "query_service_catalog",
            "credentials": {
                "access_key_id": frozen_creds.access_key,
                "secret_access_key": frozen_creds.secret_key,
                "session_token": frozen_creds.token
            },
            "region": REGION,
            "portfolio_name": os.environ.get("PORTFOLIO_NAME"),
            "product_name": os.environ.get("PRODUCT_NAME")
        }
        
        response = _invoke_function_b(payload)
        
        if not response or response.get("status") == "error":
            error_msg = response.get("error", "Unknown error") if response else "No response"
            result.add_error(f"Service Catalog query failed: {error_msg}", "ServiceCatalog")
            return None
        
        return response.get("data")
        
    except Exception as e:
        result.add_error(f"Service Catalog invocation failed: {str(e)}", "ServiceCatalog")
        return None


def _invoke_function_b_amplify_check(
    tool_session: Session,
    provisioned_product_id: str,
    result: DRCheckResult
) -> Optional[Dict[str, Any]]:
    """
    Invoke Function B to check Amplify app status
    
    Args:
        tool_session: Boto3 session with tool account credentials
        provisioned_product_id: Service Catalog provisioned product ID
        result: Result object to record errors
        
    Returns:
        Amplify status data or None on error
    """
    LOGGER.info("Checking Amplify app via Function B")
    
    try:
        credentials = tool_session.get_credentials()
        frozen_creds = credentials.get_frozen_credentials()
        
        payload = {
            "operation": "check_amplify_app",
            "credentials": {
                "access_key_id": frozen_creds.access_key,
                "secret_access_key": frozen_creds.secret_key,
                "session_token": frozen_creds.token
            },
            "region": REGION,
            "provisioned_product_id": provisioned_product_id
        }
        
        response = _invoke_function_b(payload)
        
        if not response or response.get("status") == "error":
            error_msg = response.get("error", "Unknown error") if response else "No response"
            result.add_error(f"Amplify check failed: {error_msg}", "Amplify")
            return None
        
        return response.get("data")
        
    except Exception as e:
        result.add_error(f"Amplify check invocation failed: {str(e)}", "Amplify")
        return None


def _invoke_function_b_elb_operations(
    target_session: Session,
    ip_addresses: List[str]
) -> Dict[str, List[Dict]]:
    """
    Invoke Function B to get ELB target group information for IPs
    
    Args:
        target_session: Boto3 session with target account credentials
        ip_addresses: List of IP addresses to check
        
    Returns:
        Dictionary mapping IPs to their target groups
    """
    LOGGER.info(f"Checking ELB target groups for {len(ip_addresses)} IPs via Function B")
    
    try:
        credentials = target_session.get_credentials()
        frozen_creds = credentials.get_frozen_credentials()
        
        payload = {
            "operation": "find_target_groups",
            "credentials": {
                "access_key_id": frozen_creds.access_key,
                "secret_access_key": frozen_creds.secret_key,
                "session_token": frozen_creds.token
            },
            "region": REGION,
            "ip_addresses": ip_addresses
        }
        
        response = _invoke_function_b(payload)
        
        if not response or response.get("status") == "error":
            LOGGER.error(f"ELB operations failed: {response.get('error') if response else 'No response'}")
            return {ip: [] for ip in ip_addresses}
        
        return response.get("data", {})
        
    except Exception as e:
        LOGGER.error(f"ELB operations invocation failed: {e}")
        return {ip: [] for ip in ip_addresses}

# ============================================================================
# MAIN WORKFLOW FUNCTIONS (VPC Operations)
# ============================================================================

def _get_latest_terraform_version(result: DRCheckResult) -> str:
    """Fetch latest Terraform module version from TFE (accessible from VPC)"""
    LOGGER.info("Fetching latest Terraform module version")
    try:
        url = (f"https://{TFE_HOST}/api/v2/organizations/{SHARED_TFE_ORG}/"
               f"registry-modules/private/{SHARED_TFE_ORG}/{TERRAFORM_MODULE_NAME}/"
               f"{TERRAFORM_PROVIDER}")
        
        resp = TFE_SESSION.get(url, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        
        versions = resp.json().get("data", {}).get("attributes", {}).get("version-statuses", [])
        if versions:
            version = versions[0].get("version", "UNKNOWN")
            LOGGER.info(f"Latest Terraform module version: {version}")
            return version
        
        result.add_error("No Terraform module versions found", "TFE")
        return "UNKNOWN"
        
    except requests.RequestException as e:
        result.add_error(f"TFE API request failed: {str(e)}", "TFE")
        return "UNKNOWN"
    except (KeyError, IndexError) as e:
        result.add_error(f"Unexpected TFE API response format: {str(e)}", "TFE")
        return "UNKNOWN"


def _assume_tool_role(base_session: Session, result: DRCheckResult) -> Optional[Session]:
    """Assume role in Tool Account (VPC accessible via STS endpoint)"""
    LOGGER.info(f"Assuming role: {ROLE_ARN}")
    try:
        sts_client = base_session.client("sts", config=AWS_CLIENT_CONFIG)
        response = sts_client.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName=f"DR-Precheck-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            DurationSeconds=3600
        )
        
        creds = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=REGION
        )
        
        LOGGER.info("Successfully assumed tool account role")
        return session
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        result.add_error(f"Role assumption failed ({error_code}): {str(e)}", "IAM")
        return None
    except Exception as e:
        result.add_error(f"Unexpected error assuming role: {str(e)}", "IAM")
        return None


def _query_dynamodb_records(tool_session: Session, result: DRCheckResult) -> List[Dict]:
    """Query DynamoDB for EC2 instance records (VPC accessible via DynamoDB endpoint)"""
    LOGGER.info(f"Querying DynamoDB table: {DYNAMODB_TABLE_NAME}")
    try:
        dynamodb_client = tool_session.client("dynamodb", region_name=REGION, config=AWS_CLIENT_CONFIG)
        records = _scan_dynamodb_instances(dynamodb_client, DYNAMODB_TABLE_NAME)
        LOGGER.info(f"Found {len(records)} EC2 records in DynamoDB")
        return records
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        result.add_error(f"DynamoDB query failed ({error_code}): {str(e)}", "DynamoDB")
        return []
    except Exception as e:
        result.add_error(f"DynamoDB query failed: {str(e)}", "DynamoDB")
        return []


def _scan_dynamodb_instances(client, table_name: str) -> List[Dict[str, str]]:
    """Scan DynamoDB table for EC2 instance records"""
    records = []
    try:
        paginator = client.get_paginator("scan")
        for page in paginator.paginate(TableName=table_name):
            for item in page.get("Items", []):
                record = {k: v.get("S", "") for k, v in item.items() if "S" in v}
                if "account_id" in record and "provisioned_product_id" in record:
                    records.append(record)
        return records
        
    except ClientError as e:
        LOGGER.error(f"DynamoDB scan failed: {e}")
        return []


def _process_ec2_instances(
    tool_session: Session,
    ec2_records: List[Dict],
    latest_tf_version: str,
    result: DRCheckResult
) -> None:
    """Process EC2 instances grouped by account"""
    if not ec2_records:
        LOGGER.warning("No EC2 records to process")
        return
    
    grouped_by_account = _group_by_account_id(ec2_records)
    LOGGER.info(f"Processing {len(grouped_by_account)} accounts")
    
    for account_id, records in grouped_by_account.items():
        # TODO: Remove this filter in production
        if account_id != "864899851412":
            LOGGER.debug(f"Skipping account {account_id} (filtered)")
            continue
        
        try:
            LOGGER.info(f"Processing account: {account_id} ({len(records)} instances)")
            
            role_arn = f"arn:aws:iam::{account_id}:role/awscc/{ENTITY_NAME}.ENTITYTOOL_Provisioning"
            target_session = _assume_cross_account_role(tool_session, role_arn, result)
            
            if not target_session:
                _add_account_error(result, account_id, records, "Failed to assume account role")
                continue
            
            account_report = _validate_account_instances(
                session=target_session,
                records=records,
                latest_tf_version=latest_tf_version
            )
            
            result.ec2_instances.extend(account_report)
            LOGGER.info(f"Completed account {account_id}: {len(account_report)} instances processed")
            
        except Exception as e:
            LOGGER.exception(f"Failed processing account {account_id}")
            _add_account_error(result, account_id, records, str(e))


def _assume_cross_account_role(tool_session: Session, role_arn: str, result: DRCheckResult) -> Optional[Session]:
    """Assume role in target account"""
    try:
        sts_client = tool_session.client("sts", config=AWS_CLIENT_CONFIG)
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"DR-Target-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            DurationSeconds=3600
        )
        
        creds = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=REGION
        )
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        LOGGER.error(f"Failed to assume role {role_arn} ({error_code}): {str(e)}")
        return None
    except Exception as e:
        LOGGER.error(f"Unexpected error assuming role {role_arn}: {str(e)}")
        return None


def _add_account_error(result: DRCheckResult, account_id: str, records: List[Dict], error: str) -> None:
    """Add account-level error to result"""
    result.ec2_instances.append({
        "account_id": account_id,
        "overall_instance_status": "ERROR",
        "issues": [f"Account-level failure: {error}"]
    })


def _group_by_account_id(records: List[Dict]) -> Dict[str, List[Dict]]:
    """Group records by account_id"""
    grouped = {}
    for record in records:
        account_id = record.get("account_id")
        if account_id:
            grouped.setdefault(account_id, []).append(record)
    return grouped

# ============================================================================
# INSTANCE VALIDATION (VPC Operations with EC2)
# ============================================================================

def _validate_account_instances(
    session: Session,
    records: List[Dict],
    latest_tf_version: str
) -> List[Dict]:
    """Validate all instances in a single account"""
    ec2_client = session.client("ec2", region_name=REGION, config=AWS_CLIENT_CONFIG)
    
    # Collect all IPs that need ELB lookups
    ips_to_check = []
    for record in records:
        # We'll extract IPs during validation, store them for batch lookup
        pass
    
    report = []
    
    for record in records:
        try:
            instance_report = _validate_single_instance(
                record=record,
                session=session,
                ec2_client=ec2_client,
                latest_tf_version=latest_tf_version
            )
            report.append(instance_report)
            
        except Exception as e:
            LOGGER.exception(f"Instance validation failed for {record.get('hostname', 'N/A')}")
            report.append({
                "account_id": record.get("account_id"),
                "hostname": record.get("hostname", "N/A"),
                "overall_instance_status": "ERROR",
                "issues": [f"Validation error: {str(e)}"]
            })
    
    return report


def _validate_single_instance(
    record: Dict,
    session: Session,
    ec2_client,
    latest_tf_version: str
) -> Dict:
    """Validate a single EC2 instance"""
    # Get Service Catalog details via Function B
    sc_data = _get_service_catalog_instance_data(session, record["provisioned_product_id"])
    
    if not sc_data:
        return {
            "account_id": record.get("account_id"),
            "hostname": record.get("hostname", "N/A"),
            "overall_instance_status": "ERROR",
            "issues": ["Failed to retrieve Service Catalog data"]
        }
    
    # Get EC2 instance details (VPC operation)
    instance_id = sc_data.get("instance_id")
    ec2_info = _check_ec2_instance(ec2_client, instance_id) if instance_id else {}
    
    # Get Terraform workspace health
    tf_module_ver = ec2_info.get("tags", {}).get("local.module_version")
    tf_slug = ec2_info.get("tags", {}).get("local.workspace_slug")
    ws_health = _get_workspace_health_safe(tf_slug)
    
    # Collect IPs for ELB lookup
    primary_ip = sc_data.get("primary_eni_ip")
    secondary_ip = sc_data.get("secondary_eni_ip")
    ips_to_check = [ip for ip in [primary_ip, secondary_ip] if ip]
    
    # Get target group info via Function B (batch operation)
    target_groups_by_ip = {}
    if ips_to_check:
        target_groups_by_ip = _invoke_function_b_elb_operations(session, ips_to_check)
    
    # Check capacity reservations (VPC operation)
    primary_cr_status = _check_capacity_reservation(ec2_client, sc_data.get("primary_cr_id"))
    secondary_cr_status = _check_capacity_reservation(ec2_client, sc_data.get("secondary_cr_id"))
    
    # Check ENIs (VPC operation)
    primary_eni = _check_eni_by_ip(ec2_client, primary_ip) if primary_ip else {}
    secondary_eni = _check_eni_by_ip(ec2_client, secondary_ip) if secondary_ip else {}
    
    # Build comprehensive report
    return _build_instance_report(
        record=record,
        sc_data=sc_data,
        ec2_info=ec2_info,
        tf_module_ver=tf_module_ver,
        ws_health=ws_health,
        latest_tf_version=latest_tf_version,
        primary_cr_status=primary_cr_status,
        secondary_cr_status=secondary_cr_status,
        primary_eni=primary_eni,
        secondary_eni=secondary_eni,
        primary_ip=primary_ip,
        secondary_ip=secondary_ip,
        target_groups_by_ip=target_groups_by_ip
    )


def _get_service_catalog_instance_data(session: Session, pp_id: str) -> Optional[Dict]:
    """Get Service Catalog instance data via Function B"""
    try:
        credentials = session.get_credentials()
        frozen_creds = credentials.get_frozen_credentials()
        
        payload = {
            "operation": "get_provisioned_product_details",
            "credentials": {
                "access_key_id": frozen_creds.access_key,
                "secret_access_key": frozen_creds.secret_key,
                "session_token": frozen_creds.token
            },
            "region": REGION,
            "provisioned_product_id": pp_id
        }
        
        response = _invoke_function_b(payload)
        
        if not response or response.get("status") == "error":
            LOGGER.error(f"Failed to get SC data for {pp_id}")
            return None
        
        return response.get("data")
        
    except Exception as e:
        LOGGER.error(f"Error getting SC instance data: {e}")
        return None


def _build_instance_report(
    record: Dict,
    sc_data: Dict,
    ec2_info: Dict,
    tf_module_ver: str,
    ws_health: Dict,
    latest_tf_version: str,
    primary_cr_status: str,
    secondary_cr_status: str,
    primary_eni: Dict,
    secondary_eni: Dict,
    primary_ip: str,
    secondary_ip: str,
    target_groups_by_ip: Dict
) -> Dict:
    """Build comprehensive instance validation report"""
    report = {
        "account_id": record.get("account_id"),
        "hostname": record.get("hostname", "N/A"),
        "overall_instance_status": "OK",
        "issues": []
    }
    
    # Service Catalog validation
    mpi_version = ec2_info.get("tags", {}).get("mpiversion")
    supported_versions = sc_data.get("supported_mpi_versions", [])
    
    if mpi_version and mpi_version not in supported_versions:
        report["issues"].append(
            f"MPI version {mpi_version} is no longer supported. "
            f"Supported versions: {', '.join(supported_versions)}"
        )
        report["overall_instance_status"] = "WARNING"
    
    report["service_catalog"] = {
        "name": sc_data.get("name"),
        "provisioned_product_id": record.get("provisioned_product_id"),
        "status": sc_data.get("status"),
        "mpi_version": mpi_version,
        "supported_mpi_versions": supported_versions,
        "flow_type": sc_data.get("flow_type")
    }
    
    if sc_data.get("flow_type", "").lower() != "standard":
        report["issues"].append("FlowType parameter must be 'standard'")
        report["overall_instance_status"] = "WARNING"
    
    # Terraform validation
    up_to_date_tf = tf_module_ver == latest_tf_version
    if tf_module_ver and not up_to_date_tf:
        report["issues"].append(
            f"Terraform module outdated: {tf_module_ver} (latest: {latest_tf_version})"
        )
        report["overall_instance_status"] = "WARNING"
    
    report["terraform"] = {
        "module_version": tf_module_ver or "UNKNOWN",
        "latest_module_version": latest_tf_version,
        "up_to_date": up_to_date_tf,
        "workspace": {
            "slug": ec2_info.get("tags", {}).get("local.workspace_slug", ""),
            "locked": ws_health.get("locked"),
            "terraform_version": ws_health.get("terraform_version", "Unknown"),
            "latest_run_status": ws_health.get("latest_run_status", "No runs"),
            "assessment_results": ws_health.get("assessment_results")
        }
    }
    
    # EC2 validation
    report["ec2"] = {
        "instance_id": ec2_info.get("instance_id"),
        "state": ec2_info.get("status"),
        "instance_type": ec2_info.get("instance_type")
    }
    
    # Capacity reservations
    report["capacity_reservations"] = {
        "type": sc_data.get("cr_type") or "none",
        "primary": _format_cr_entry(sc_data.get("primary_cr_id"), primary_cr_status),
        "secondary": _format_cr_entry(sc_data.get("secondary_cr_id"), secondary_cr_status)
    }
    
    if sc_data.get("secondary_cr_id") and secondary_cr_status != "AVAILABLE":
        report["issues"].append("Secondary capacity reservation not available")
        report["overall_instance_status"] = "ERROR"
    
    # Network ENIs
    report["network_enis"] = {
        "primary": {
            "private_ip": primary_ip,
            "eni_id": primary_eni.get("NetworkInterfaceId", "NOT FOUND"),
            "attachment": primary_eni.get("Status", "NOT FOUND"),
            "target_groups": target_groups_by_ip.get(primary_ip, [])
        },
        "secondary": {
            "private_ip": secondary_ip,
            "eni_id": secondary_eni.get("NetworkInterfaceId", "NOT FOUND") if secondary_ip else "N/A",
            "attachment": secondary_eni.get("Status", "NOT FOUND") if secondary_ip else "N/A",
            "target_groups": target_groups_by_ip.get(secondary_ip, []) if secondary_ip else []
        }
    }
    
    # Final status check
    if report["overall_instance_status"] == "OK" and report["issues"]:
        report["overall_instance_status"] = "WARNING"
    
    return report


def _format_cr_entry(cr_id: str, status: str) -> Dict:
    """Format capacity reservation entry"""
    entry = {
        "id": cr_id,
        "available": status == "AVAILABLE"
    }
    if not entry["available"]:
        entry["reason"] = status
    return entry

# ============================================================================
# EC2 HELPERS (VPC Operations)
# ============================================================================

def _check_ec2_instance(ec2_client, instance_id: str) -> Dict:
    """Get EC2 instance details including tags"""
    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        
        if not reservations or not reservations[0].get("Instances"):
            return {"instance_id": instance_id, "status": "NOT_FOUND"}
        
        inst = reservations[0]["Instances"][0]
        return {
            "instance_id": instance_id,
            "status": inst.get("State", {}).get("Name", "unknown"),
            "instance_type": inst.get("InstanceType"),
            "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        }
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "InvalidInstanceID.NotFound":
            return {"instance_id": instance_id, "status": "NOT_FOUND"}
        LOGGER.error(f"Error checking EC2 instance {instance_id}: {e}")
        return {"instance_id": instance_id, "status": "ERROR"}


def _check_capacity_reservation(ec2_client, cr_id: str) -> str:
    """Check if capacity reservation has available capacity"""
    if not cr_id:
        return "NOT CONFIGURED"
    
    try:
        resp = ec2_client.describe_capacity_reservations(CapacityReservationIds=[cr_id])
        reservations = resp.get("CapacityReservations", [])
        
        if not reservations:
            return "NOT FOUND"
        
        cr = reservations[0]
        available_count = cr.get("AvailableInstanceCount", 0)
        return "AVAILABLE" if available_count > 0 else "NOT AVAILABLE"
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code == "InvalidCapacityReservationId.NotFound":
            return "NOT FOUND"
        LOGGER.error(f"Error checking capacity reservation {cr_id}: {e}")
        return "ERROR"


def _check_eni_by_ip(ec2_client, ip: str) -> Dict:
    """Check ENI attachment status by IP address"""
    if not ip:
        return {}
    
    try:
        resp = ec2_client.describe_network_interfaces(
            Filters=[{"Name": "addresses.private-ip-address", "Values": [ip]}]
        )
        
        interfaces = resp.get("NetworkInterfaces", [])
        if interfaces:
            eni = interfaces[0]
            return {
                "NetworkInterfaceId": eni.get("NetworkInterfaceId"),
                "Status": "attached" if eni.get("Attachment") else "detached"
            }
        
        return {}
        
    except ClientError as e:
        LOGGER.error(f"Error checking ENI for IP {ip}: {e}")
        return {}

# ============================================================================
# TERRAFORM ENTERPRISE HELPERS (VPC Accessible)
# ============================================================================

def _get_workspace_health_safe(tf_slug: str) -> Dict:
    """Safely get Terraform workspace health (with error handling)"""
    if not tf_slug or not _is_valid_workspace_format(tf_slug):
        return {"error": "Invalid workspace format"}
    
    try:
        org, workspace = _parse_workspace_identifier(tf_slug)
        return _get_workspace_health(org, workspace)
    except Exception as e:
        LOGGER.error(f"Error getting workspace health for {tf_slug}: {e}")
        return {"error": str(e)}


def _is_valid_workspace_format(workspace_slug: str) -> bool:
    """Validate workspace slug format (org/workspace)"""
    if not isinstance(workspace_slug, str):
        return False
    parts = workspace_slug.strip().split("/")
    return len(parts) == 2 and all(parts)


def _parse_workspace_identifier(workspace_slug: str) -> Tuple[str, str]:
    """Parse workspace slug into organization and workspace name"""
    parts = workspace_slug.strip().split("/")
    return parts[0], parts[1]


def _get_workspace_health(org: str, workspace: str) -> Dict:
    """Get comprehensive Terraform workspace health information"""
    try:
        url = f"https://{TFE_HOST}/api/v2/organizations/{org}/workspaces/{workspace}"
        resp = TFE_SESSION.get(url, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        
        data = resp.json().get("data", {})
        ws_id = data.get("id")
        attributes = data.get("attributes", {})
        
        result = {
            "organization": org,
            "workspace": workspace,
            "locked": attributes.get("locked", False),
            "terraform_version": attributes.get("terraform-version", "Unknown"),
            "latest_run_status": "No runs"
        }
        
        # Get latest run
        try:
            runs_url = f"https://{TFE_HOST}/api/v2/workspaces/{ws_id}/runs?page[size]=1"
            runs_resp = TFE_SESSION.get(runs_url, timeout=HTTP_TIMEOUT)
            runs_resp.raise_for_status()
            
            runs_data = runs_resp.json().get("data", [])
            if runs_data:
                result["latest_run_status"] = runs_data[0].get("attributes", {}).get("status", "Unknown")
        except requests.RequestException as e:
            LOGGER.warning(f"Could not fetch latest run: {e}")
        
        # Check assessments
        if attributes.get("assessments-enabled", False):
            result["assessment_results"] = _get_workspace_assessment(ws_id)
        else:
            result["assessment_results"] = "Assessments not enabled"
        
        return result
        
    except requests.RequestException as e:
        LOGGER.error(f"TFE API error for workspace {org}/{workspace}: {e}")
        return {"error": f"TFE API error: {str(e)}"}
    except (KeyError, ValueError) as e:
        LOGGER.error(f"Unexpected TFE response format: {e}")
        return {"error": "Invalid TFE response format"}


def _get_workspace_assessment(workspace_id: str) -> Any:
    """Get current assessment results for workspace"""
    try:
        url = f"https://{TFE_HOST}/api/v2/workspaces/{workspace_id}/current-assessment-result"
        resp = TFE_SESSION.get(url, timeout=HTTP_TIMEOUT)
        
        if resp.status_code == 404:
            return "Assessment not found"
        
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attr = data.get("attributes", {})
        
        return {
            "assessment_status": "succeeded" if attr.get("succeeded") else "failed",
            "drift": attr.get("drifted", False),
            "created_at": attr.get("created-at"),
            "error_message": attr.get("error-message", "")
        }
        
    except requests.RequestException as e:
        LOGGER.warning(f"Could not fetch assessment for workspace {workspace_id}: {e}")
        return "Assessment check failed"

# ============================================================================
# RESPONSE FORMATTER
# ============================================================================

def _format_response(result: DRCheckResult, status_code: int = 200) -> Dict[str, Any]:
    """Format final Lambda response in API Gateway compatible format"""
    total_instances = len(result.ec2_instances)
    ok_instances = sum(
        1 for i in result.ec2_instances 
        if i.get("overall_instance_status") == "OK"
    )
    instances_with_issues = total_instances - ok_instances
    
    dr_tool_summary = {
        "amplify_app": result.dr_tool.get("amplify_app", {}),
        "service_catalog": {
            "provisioned_product": result.dr_tool.get("provisioned_product_name"),
            "status": result.dr_tool.get("provisioned_product_status"),
            "version": result.dr_tool.get("provisioned_product_version"),
            "created_time": result.dr_tool.get("created_time")
        }
    }
    
    payload = {
        "timestamp": result.timestamp,
        "overall_status": result.status,
        "summary": {
            "total_mpi_instances": total_instances,
            "instances_ok": ok_instances,
            "instances_with_issues": instances_with_issues,
            "dr_tool": dr_tool_summary
        },
        "mpi_instances": result.ec2_instances
    }
    
    if result.errors:
        payload["errors"] = result.errors
    
    return {
        "statusCode": status_code,
        "body": json.dumps(payload, default=str, indent=2)
    }
