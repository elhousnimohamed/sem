"""
AWS Lambda: Disaster Recovery Pre-Check
"""
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError
from boto3.session import Session

# ============================================================================
# GLOBAL CONFIGURATION - Initialize once during cold start
# ============================================================================

# Configure logging
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

# Write certificate during cold start (only once)
try:
    if not os.path.exists(CERT_PATH):
        with open(CERT_PATH, 'w') as cert_file:
            cert_file.write(CERT_CONTENT)
        LOGGER.info("Certificate written successfully")
except IOError as e:
    LOGGER.error(f"Failed to write certificate: {e}")

# Environment variables with validation
def _get_required_env(key: str) -> str:
    """Get required environment variable or raise clear error"""
    value = os.environ.get(key)
    if not value:
        raise ValueError(f"Missing required environment variable: {key}")
    return value

try:
    ROLE_ARN = _get_required_env("ROLE_ARN")
    REGION = _get_required_env("REGION")
    PORTFOLIO_NAME = _get_required_env("PORTFOLIO_NAME")
    PRODUCT_NAME = _get_required_env("PRODUCT_NAME")
    DYNAMODB_TABLE_NAME = _get_required_env("DYNAMODB_TABLE_NAME")
    DYNAMODB_CONFIG_TABLE_NAME = _get_required_env("DYNAMODB_CONFIG_TABLE_NAME")
    TFE_HOST = _get_required_env("TFE_HOST")
    SHARED_TFE_ORG = _get_required_env("SHARED_TFE_ORG")
    TERRAFORM_MODULE_NAME = _get_required_env("TERRAFORM_MODULE_NAME")
    TERRAFORM_PROVIDER = _get_required_env("TERRAFORM_PROVIDER")
    ENTITY_NAME = _get_required_env("ENTITY_NAME")
except ValueError as e:
    LOGGER.error(f"Configuration error: {e}")
    

# Get global configuration from dynamodb table
def get_configuration():
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


# ============================================================================
# Get Configuration from dynamodb table
# ============================================================================
CONFIG = get_configuration()

# Connection timeout constants
HTTP_TIMEOUT = 15  # seconds
AWS_CLIENT_CONFIG = boto3.session.Config(
    connect_timeout=5,
    read_timeout=30,
    retries={'max_attempts': 3, 'mode': 'standard'}
)

def _get_tfe_token() -> str:
    LOGGER.info("Retrieving TFE token from secrets manager...")
    sm_client = boto3.client("secretsmanager", region_name=REGION, config=AWS_CLIENT_CONFIG)
    try:
        value = sm_client.get_secret_value(
            SecretId=CONFIG["TFE_TOKEN_SECRET_ARN"],
        )
        secret_json = json.loads(value["SecretString"])
        return secret_json["TFE_TOKEN"]
    except Exception as e:
        LOGGER.error(f"Error retrieving TFE token: {e}")

# Get TFE token
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
    
    Args:
        event: Lambda event payload
        context: Lambda context object
        
    Returns:
        API Gateway compatible response with statusCode and body
    """
    
    LOGGER.info('## EVENT')
    LOGGER.info(f"## Received event: {json.dumps(event, default=str)}")
    
    LOGGER.info('## ENVIRONMENT VARIABLES')
    LOGGER.info(json.dumps(dict(os.environ)))
    
    LOGGER.info('## CALLER')
    LOGGER.info(json.dumps(boto3.client('sts').get_caller_identity()))
    
    # Initialize result object
    result = DRCheckResult(timestamp=datetime.now(timezone.utc).isoformat())
    
    try:
        # Create base session
        base_session = boto3.Session()
        
        # Step 0: Get latest Terraform module version
        latest_tf_version = _get_latest_terraform_version(result)
        
        # Step 1: Assume role in Tool Account
        tool_session = _assume_tool_role(base_session, result)
        if not tool_session:
            return _format_response(result, status_code=500)
        
        # Step 2: Query Service Catalog
        _query_service_catalog(tool_session, result)
        
        # Step3 : Amplify App Check
        if result.dr_tool.get("provisioned_product_id"):
            sc_client = tool_session.client("servicecatalog", region_name=REGION, config=AWS_CLIENT_CONFIG)
            product_details = _describe_provisioned_product_with_outputs(sc_client, result.dr_tool["provisioned_product_id"])
            amplify_app_id = _extract_output(product_details.get("outputs", []), "AmplifyAppId")
            if amplify_app_id:
                LOGGER.info(f"Found Amplify application ID: {amplify_app_id}")
                amplify_status = _check_amplify_app(tool_session, amplify_app_id)
                result.dr_tool["amplify_app"] = amplify_status
                LOGGER.info(f"Amplify application status: {amplify_status.get('status')}")
            else:
                result.add_error("AmplifyAppId output missing", "Amplify")
        
        # Step 4: Query DynamoDB for EC2 records
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
# MAIN WORKFLOW FUNCTIONS
# ============================================================================

def _get_latest_terraform_version(result: DRCheckResult) -> str:
    """Fetch latest Terraform module version from TFE"""
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
    """Assume role in Tool Account"""
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


def _query_service_catalog(tool_session: Session, result: DRCheckResult) -> None:
    """Query Service Catalog for DR tool information"""
    LOGGER.info("Querying Service Catalog")
    try:
        sc_client = tool_session.client("servicecatalog", region_name=REGION, config=AWS_CLIENT_CONFIG)
        
        # Get portfolio
        portfolio_id = _get_portfolio_id(sc_client, PORTFOLIO_NAME)
        if not portfolio_id:
            raise ValueError(f"Portfolio '{PORTFOLIO_NAME}' not found")
        LOGGER.debug(f"Portfolio ID: {portfolio_id}")
        
        # Get product
        product_id = _get_product_id(sc_client, portfolio_id, PRODUCT_NAME)
        if not product_id:
            raise ValueError(f"Product '{PRODUCT_NAME}' not found in portfolio")
        LOGGER.debug(f"Product ID: {product_id}")
        
        # Get provisioned product
        provisioned_product = _get_provisioned_product(sc_client, product_id)
        if not provisioned_product:
            raise ValueError(f"No provisioned product found for '{PRODUCT_NAME}'")
        
        LOGGER.info(f"Found provisioned product: {provisioned_product.get('id')}")
        
        # Update result
        result.dr_tool.update({
            "provisioned_product_name": provisioned_product.get("name"),
            "provisioned_product_id": provisioned_product.get("id"),
            "provisioned_product_status": provisioned_product.get("status"),
            "provisioned_product_version": provisioned_product.get("version"),
            "created_time": provisioned_product.get("created_time")
        })
        
    except ValueError as e:
        result.add_error(str(e), "ServiceCatalog")
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        result.add_error(f"Service Catalog API error ({error_code}): {str(e)}", "ServiceCatalog")
    except Exception as e:
        result.add_error(f"Service Catalog query failed: {str(e)}", "ServiceCatalog")

def _check_amplify_app(tool_session: Session, app_id : str ):
    """Check Amplify application status"""
    LOGGER.info(f"Checking Amplify application with id: {app_id}")
    try:
        client = tool_session.client("amplify", region_name=REGION, config=AWS_CLIENT_CONFIG)
        app = client.get_app(appId=app_id)["app"]
        return {"app_id": app_id, "status": "ACTIVE", "name": app.get("name")}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return {
            "app_id": app_id,
            "status": "NOT_FOUND" if code == "NotFoundException" else "ERROR",
            "error": str(e)
        }
    except Exception as e:
        return {"app_id": app_id, "status": "ERROR", "error": str(e)}
def _query_dynamodb_records(tool_session: Session, result: DRCheckResult) -> List[Dict]:
    """Query DynamoDB for EC2 instance records"""
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
            
            # Assume role in target account
            role_arn = f"arn:aws:iam::{account_id}:role/awscc/{ENTITY_NAME}.ENTITYTOOL_Provisioning"
            target_session = _assume_cross_account_role(tool_session, role_arn, result)
            
            if not target_session:
                _add_account_error(result, account_id, records, "Failed to assume account role")
                continue
            
            # Validate instances in this account
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

# ============================================================================
# SERVICE CATALOG HELPERS
# ============================================================================

def _get_portfolio_id(sc_client, name: str) -> Optional[str]:
    """Find portfolio ID by name"""
    try:
        paginator = sc_client.get_paginator("list_portfolios")
        for page in paginator.paginate():
            for portfolio in page.get("PortfolioDetails", []):
                if portfolio.get("DisplayName") == name:
                    return portfolio["Id"]
        return None
    except ClientError as e:
        LOGGER.error(f"Error listing portfolios: {e}")
        return None


def _get_product_id(sc_client, portfolio_id: str, name: str) -> Optional[str]:
    """Find product ID by name within portfolio"""
    try:
        paginator = sc_client.get_paginator("search_products_as_admin")
        for page in paginator.paginate(PortfolioId=portfolio_id):
            for view in page.get("ProductViewDetails", []):
                summary = view.get("ProductViewSummary", {})
                if summary.get("Name") == name:
                    return summary.get("ProductId")
        return None
    except ClientError as e:
        LOGGER.error(f"Error searching products: {e}")
        return None


def _get_provisioned_product(sc_client, product_id: str) -> Optional[Dict]:
    """Find provisioned product for given product ID"""
    try:
        paginator = sc_client.get_paginator("scan_provisioned_products")
        for page in paginator.paginate(AccessLevelFilter={"Key": "Account", "Value": "self"}):
            for p in page.get("ProvisionedProducts", []):
                if p.get("ProductId") == product_id:
                    # Get version details
                    try:
                        artifact = sc_client.describe_provisioning_artifact(
                            ProductId=product_id,
                            ProvisioningArtifactId=p.get("ProvisioningArtifactId")
                        )
                        version = artifact.get("ProvisioningArtifactDetail", {}).get("Name", "Unknown")
                    except ClientError:
                        version = "Unknown"
                    
                    return {
                        "id": p.get("Id"),
                        "name": p.get("Name"),
                        "status": p.get("Status"),
                        "version": version,
                        "created_time": p.get("CreatedTime")
                    }
        return None
    except ClientError as e:
        LOGGER.error(f"Error scanning provisioned products: {e}")
        return None


def _describe_provisioned_product_with_outputs(sc_client, pp_id: str) -> Dict:
    """Get provisioned product details including CloudFormation outputs"""
    try:
        detail = sc_client.describe_provisioned_product(Id=pp_id)["ProvisionedProductDetail"]
        outputs = []
        
        last_record_id = detail.get("LastSuccessfulProvisioningRecordId")
        if last_record_id:
            try:
                record = sc_client.describe_record(Id=last_record_id)
                outputs = [
                    {"Key": o["OutputKey"], "Value": o["OutputValue"]}
                    for o in record.get("RecordOutputs", [])
                ]
            except ClientError as e:
                LOGGER.warning(f"Could not fetch outputs for record {last_record_id}: {e}")
        
        return {**detail, "outputs": outputs}
        
    except ClientError as e:
        LOGGER.error(f"Error describing provisioned product {pp_id}: {e}")
        return {"outputs": []}


def _get_last_5_versions(sc_client, product_id: str) -> List[Dict]:
    """Get last 5 provisioning artifact versions"""
    try:
        response = sc_client.list_provisioning_artifacts(ProductId=product_id)
        artifacts = response.get("ProvisioningArtifactDetails", [])
        sorted_artifacts = sorted(
            artifacts,
            key=lambda x: x.get("CreatedTime", datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True
        )
        return sorted_artifacts[:5]
    except ClientError as e:
        LOGGER.error(f"Error listing provisioning artifacts: {e}")
        return []

# ============================================================================
# DYNAMODB HELPERS
# ============================================================================

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


def _group_by_account_id(records: List[Dict]) -> Dict[str, List[Dict]]:
    """Group records by account_id"""
    grouped = {}
    for record in records:
        account_id = record.get("account_id")
        if account_id:
            grouped.setdefault(account_id, []).append(record)
    return grouped

# ============================================================================
# INSTANCE VALIDATION
# ============================================================================

def _validate_account_instances(
    session: Session,
    records: List[Dict],
    latest_tf_version: str
) -> List[Dict]:
    """Validate all instances in a single account"""
    # Initialize AWS clients once per account
    sc_client = session.client("servicecatalog", region_name=REGION, config=AWS_CLIENT_CONFIG)
    cf_client = session.client("cloudformation", region_name=REGION, config=AWS_CLIENT_CONFIG)
    ec2_client = session.client("ec2", region_name=REGION, config=AWS_CLIENT_CONFIG)
    elb_client = session.client("elbv2", region_name=REGION, config=AWS_CLIENT_CONFIG)
    
    report = []
    
    for record in records:
        try:
            instance_report = _validate_single_instance(
                record=record,
                sc_client=sc_client,
                cf_client=cf_client,
                ec2_client=ec2_client,
                elb_client=elb_client,
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
    sc_client,
    cf_client,
    ec2_client,
    elb_client,
    latest_tf_version: str
) -> Dict:
    """Validate a single EC2 instance"""
    # 1. Get Service Catalog details
    pp = _describe_provisioned_product_with_outputs(sc_client, record["provisioned_product_id"])
    product_id = pp.get("ProductId", "")
    support_versions = _get_last_5_versions(sc_client, product_id)
    
    # 2. Get CloudFormation parameters
    stack_arn = _extract_output(pp.get("outputs", []), "CloudformationStackARN")
    params = _get_stack_parameters(cf_client, stack_arn) if stack_arn else {}
    
    # 3. Get EC2 instance details
    instance_id = _extract_output(pp.get("outputs", []), "EC2Instance")
    ec2_info = _check_ec2_instance(ec2_client, instance_id) if instance_id else {}
    
    # 4. Get Terraform workspace health
    tf_module_ver = ec2_info.get("tags", {}).get("local.module_version")
    tf_slug = ec2_info.get("tags", {}).get("local.workspace_slug")
    ws_health = _get_workspace_health_safe(tf_slug)
    
    # 5. Build comprehensive report
    return _build_instance_report(
        record=record,
        pp=pp,
        flow_type=params.get("FlowType"),
        ec2_info=ec2_info,
        tf_module_ver=tf_module_ver,
        ws_health=ws_health,
        latest_tf_version=latest_tf_version,
        support_versions=support_versions,
        ec2_client=ec2_client,
        elb_client=elb_client
    )

# ============================================================================
# INSTANCE REPORT BUILDER
# ============================================================================

def _build_instance_report(
    record: Dict,
    pp: Dict,
    flow_type: str,
    ec2_info: Dict,
    tf_module_ver: str,
    ws_health: Dict,
    latest_tf_version: str,
    support_versions: List[Dict],
    ec2_client,
    elb_client
) -> Dict:
    """Build comprehensive instance validation report"""
    report = {
        "account_id": record.get("account_id"),
        "hostname": record.get("hostname", "N/A"),
        "overall_instance_status": "OK",
        "issues": []
    }
    
    # --- Service Catalog Validation ---
    mpi_version = ec2_info.get("tags", {}).get("mpiversion")
    supported_mpi_versions = _extract_supported_versions(support_versions)
    
    if mpi_version and mpi_version not in supported_mpi_versions:
        report["issues"].append(
            f"MPI version {mpi_version} is no longer supported. "
            f"Supported versions: {', '.join(supported_mpi_versions)}"
        )
        report["overall_instance_status"] = "WARNING"
    
    report["service_catalog"] = {
        "name": pp.get("Name"),
        "provisioned_product_id": record.get("provisioned_product_id"),
        "status": pp.get("Status"),
        "mpi_version": mpi_version,
        "supported_mpi_versions": supported_mpi_versions,
        "flow_type": flow_type
    }
    
    # Check flow type
    if flow_type and flow_type.lower() != "standard":
        report["issues"].append("FlowType parameter must be 'standard'")
        report["overall_instance_status"] = "WARNING"
    
    # --- Terraform Validation ---
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
    
    # --- EC2 Validation ---
    report["ec2"] = {
        "instance_id": ec2_info.get("instance_id"),
        "state": ec2_info.get("status"),
        "instance_type": ec2_info.get("instance_type")
    }
    
    # --- Capacity Reservations ---
    cr_type = _extract_output(pp.get("outputs", []), "CapacityReservationType")
    primary_cr = _extract_output(pp.get("outputs", []), "PrimaryCRID")
    secondary_cr = _extract_output(pp.get("outputs", []), "SecondaryCRID")
    
    primary_status = _check_capacity_reservation(ec2_client, primary_cr)
    secondary_status = _check_capacity_reservation(ec2_client, secondary_cr)
    
    report["capacity_reservations"] = {
        "type": cr_type or "none",
        "primary": _format_cr_entry(primary_cr, primary_status),
        "secondary": _format_cr_entry(secondary_cr, secondary_status)
    }
    
    if secondary_cr and not report["capacity_reservations"]["secondary"]["available"]:
        report["issues"].append("Secondary capacity reservation not available")
        report["overall_instance_status"] = "ERROR"
    
    # --- Network ENIs ---
    primary_ip = _extract_output(pp.get("outputs", []), "ENI0PrivateIP")
    secondary_ip = _extract_output(pp.get("outputs", []), "ENI1PrivateIP")
    
    report["network_enis"] = {
        "primary": _build_network_entry(elb_client, ec2_client, primary_ip),
        "secondary": _build_network_entry(elb_client, ec2_client, secondary_ip)
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


def _build_network_entry(elb_client, ec2_client, ip: str) -> Dict:
    """Build network ENI entry with attachment and target group info"""
    if not ip:
        return {
            "private_ip": None,
            "eni_id": "N/A",
            "attachment": "N/A",
            "target_groups": []
        }
    
    eni = _check_eni_by_ip(ec2_client, ip)
    target_groups = _find_target_groups_by_ip(elb_client, ip)
    
    return {
        "private_ip": ip,
        "eni_id": eni.get("NetworkInterfaceId", "NOT FOUND"),
        "attachment": eni.get("Status", "NOT FOUND"),
        "target_groups": target_groups
    }

# ============================================================================
# EC2 & NETWORKING HELPERS
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
        # Try private IP first
        for filter_name in ["addresses.private-ip-address"]:
            try:
                resp = ec2_client.describe_network_interfaces(
                    Filters=[{"Name": filter_name, "Values": [ip]}]
                )
                
                interfaces = resp.get("NetworkInterfaces", [])
                if interfaces:
                    eni = interfaces[0]
                    return {
                        "NetworkInterfaceId": eni.get("NetworkInterfaceId"),
                        "Status": "attached" if eni.get("Attachment") else "detached"
                    }
            except ClientError:
                continue
        
        return {}
        
    except ClientError as e:
        LOGGER.error(f"Error checking ENI for IP {ip}: {e}")
        return {}


def _find_target_groups_by_ip(elb_client, ip: str) -> List[Dict]:
    """Find all target groups containing the given IP"""
    if not ip:
        return []
    
    matches = []
    try:
        paginator = elb_client.get_paginator("describe_target_groups")
        
        for page in paginator.paginate():
            for tg in page.get("TargetGroups", []):
                try:
                    health = elb_client.describe_target_health(
                        TargetGroupArn=tg["TargetGroupArn"]
                    )
                    
                    for target_health in health.get("TargetHealthDescriptions", []):
                        target = target_health.get("Target", {})
                        if target.get("Id") == ip:
                            matches.append({
                                "name": tg.get("TargetGroupName"),
                                "arn": tg.get("TargetGroupArn"),
                                "port": target.get("Port")
                            })
                            
                except ClientError as e:
                    LOGGER.warning(f"Could not check target group {tg.get('TargetGroupArn')}: {e}")
                    continue
        
        return matches
        
    except ClientError as e:
        LOGGER.error(f"Error finding target groups for IP {ip}: {e}")
        return []

# ============================================================================
# CLOUDFORMATION HELPERS
# ============================================================================

def _get_stack_parameters(cf_client, stack_arn: str) -> Dict[str, str]:
    """Get CloudFormation stack parameters"""
    try:
        resp = cf_client.describe_stacks(StackName=stack_arn)
        stacks = resp.get("Stacks", [])
        
        if not stacks:
            return {}
        
        stack = stacks[0]
        return {
            p["ParameterKey"]: p["ParameterValue"]
            for p in stack.get("Parameters", [])
        }
        
    except ClientError as e:
        LOGGER.error(f"Error getting stack parameters for {stack_arn}: {e}")
        return {}

# ============================================================================
# TERRAFORM ENTERPRISE HELPERS
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
        # Get workspace details
        url = f"https://{TFE_HOST}/api/v2/organizations/{org}/workspaces/{workspace}"
        resp = TFE_SESSION.get(url, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        
        data = resp.json().get("data", {})
        ws_id = data.get("id")
        attributes = data.get("attributes", {})
        
        # Base workspace info
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
# UTILITY HELPERS
# ============================================================================

def _extract_output(outputs: List[Dict], key: str) -> Optional[str]:
    """Extract specific output value from CloudFormation outputs"""
    for output in outputs:
        if output.get("Key") == key:
            return output.get("Value")
    return None


def _extract_supported_versions(versions: List[Dict]) -> List[str]:
    """Extract version names from provisioning artifacts"""
    return [v.get("Name") for v in versions if v.get("Name")]

# ============================================================================
# RESPONSE FORMATTER
# ============================================================================

def _format_response(result: DRCheckResult, status_code: int = 200) -> Dict[str, Any]:
    """
    Format final Lambda response in API Gateway compatible format
    
    Args:
        result: DR check result object
        status_code: HTTP status code (default: 200)
        
    Returns:
        Dict with statusCode, body, and headers
    """
    # Calculate summary statistics
    total_instances = len(result.ec2_instances)
    ok_instances = sum(
        1 for i in result.ec2_instances 
        if i.get("overall_instance_status") == "OK"
    )
    instances_with_issues = total_instances - ok_instances
    
    # Build DR tool summary
    dr_tool_summary = {
        "amplify_app": result.dr_tool.get("amplify_app", {}),
        "service_catalog": {
            "provisioned_product": result.dr_tool.get("provisioned_product_name"),
            "status": result.dr_tool.get("provisioned_product_status"),
            "version": result.dr_tool.get("provisioned_product_version"),
            "created_time": result.dr_tool.get("created_time")
        }
    }
    
    # Build response payload
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
    
    # Add errors if present
    if result.errors:
        payload["errors"] = result.errors
    
    return {
        "statusCode": status_code,
        "body": json.dumps(payload, default=str, indent=2)
    }
