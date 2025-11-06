import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime,  timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError
from boto3.session import Session

# Create a LOGGER
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
log_levels = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARN": logging.WARN,
    "ERROR": logging.ERROR,
}
LOGGER = logging.getLogger()
LOGGER.setLevel(log_levels[LOG_LEVEL])


# Environment variables
ROLE_ARN = os.environ["ROLE_ARN"]
REGION = os.environ["REGION"]
PORTFOLIO_NAME = os.environ["PORTFOLIO_NAME"]
PRODUCT_NAME = os.environ["PRODUCT_NAME"]
DYNAMODB_TABLE_NAME = os.environ["DYNAMODB_TABLE_NAME"]
TFE_HOST = os.environ["TFE_HOST"]
TFE_TOKEN = os.environ.get("TERRAFORM_API_TOKEN", "")
SHARED_TFE_ORG = os.environ["SHARED_TFE_ORG"] # Global-Module-Sharing
TERRAFORM_MODULE_NAME = os.environ["TERRAFORM_MODULE_NAME"] # vm
TERRAFORM_PROVIDER = os.environ["TERRAFORM_PROVIDER"]
ENTITY_NAME = os.environ["ENTITY_NAME"]


CERT_PATH='/tmp/cert.pem'

# Use custom AXA certificate
AXA_CERT ="""-----BEGIN CERTIFICATE-----
MIIGezCCBGOgAwIBAgIJAL70CjUzx7s8MA0GCSqGSIb3DQEBCwUAMEAxEDAOBgNV
BAoTB0dJRSBBWEExHzAdBgNVBAMTFkFYQS1FbnRlcnByaXNlLVJvb3QtQ0ExCzAJ
BgNVBAYTAkZSMB4XDTE1MDUyNzEyNTgzMloXDTM1MDUyNzEyNTgzMlowQDEQMA4G
A1UEChMHR0lFIEFYQTEfMB0GA1UEAxMWQVhBLUVudGVycHJpc2UtUm9vdC1DQTEL
MAkGA1UEBhMCRlIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCrZPRh
akXgbpPjeXLHq3s5eHZ+XUGj/5hgQE16SgkU/+6TRLosaV6JJ8X+A7pGP9DVZzKp
+ZpQs2lfl1ljyxn+0smUc65OeBFXCPdR37EOEPqO8lWLFKqRlTfu/UqWyxcdyqLe
zCXFSQdwiH5WxfY5TEFpVt0zzjYmAvjQJ1gmQztQvkKHkKOdjtyZcp3Zcings8qV
D1qcMt7BApynzhPcoiCYIdHyoJ2HCQBIOxIaELmjo10PPkMmTP2vuHkWUYBR2NQN
SzvheTyTMLcxLyqbjYLAxIwK9mN8X9jxmxf8ksyySUl437lVPXo9b5cB8AlOF11f
5u+3ViIdCXkljmyvN2Ta7twgWRJI+cAVI85bH8kc3mJ0A/VQxLO2ZApov0eA89xY
zHYw6qtYGc62ybuRW9TdB8TON+qfeaAAEWh2iksRWFIV3HzqSwoIg1XlE5TMbcx5
Wd7Rd9jv43ixpkaA54rgMBmuh0Ww/tw4VJnOCGNlDode+Q62L2tV8jucn1j3nAqA
nyDq2yt9aX9YbpaEvtmQtoRAOVItEy0fVZdyI6pjV2PY6RbroqplLPdb9wPDe40P
uV+HEhblb3WSWycmquNoSjY6EoP5bYmiPIVzsc8JAXt+igsFBdUITkcSFafSJTm2
u78sRMLzpR1cc3IHb/lb6vofWQpipus/VGXfxwIDAQABo4IBdjCCAXIwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFNvOVQf9ZvgSbwab
2IOgU+dA9nmkMHAGA1UdIwRpMGeAFNvOVQf9ZvgSbwab2IOgU+dA9nmkoUSkQjBA
MRAwDgYDVQQKEwdHSUUgQVhBMR8wHQYDVQQDExZBWEEtRW50ZXJwcmlzZS1Sb290
LUNBMQswCQYDVQQGEwJGUoIJAL70CjUzx7s8MIG9BgNVHSAEgbUwgbIwga8GDisG
AQQBv3wCBAECAQEAMIGcMEEGCCsGAQUFBwIBFjVodHRwOi8vcGtpLmF4YS5jb20v
cG9saWN5L2F4YS1lbnRlcnByaXNlLWNhLWNwY3BzLnBkZjBXBggrBgEFBQcCAjBL
GklBWEEgRW50ZXJwcmlzZSBDQSBDZXJ0aWZpY2F0ZSBQb2xpY3kgYW5kIENlcnRp
ZmljYXRpb24gUHJhY3RpY2UgU3RhdGVtZW50MA0GCSqGSIb3DQEBCwUAA4ICAQBU
2NrMOBEZc09m2uk++gMxSpoOYHMU2cnteHc+23EzPf+RFPCGjRaqtRUj5PPZUvr4
IP9BPBWDIveKh2pUeTQ3ZA0N06B4vaR22TS4Du0LAL677zXvBT7ig/dMow68Juyu
P7CuBXkK7qfPYFpy+uKolKZR+wt09FQqhI9f2DHiQTriJErMdwroZallmfujI1Ye
TPoATFsSUssaj3o1COUvCiRN+v2kdlgAypu/LF3ya9wwnWRB4r4wr6hjG2zLP2sM
y1ajYLOjHjAGYyt8zuUG5WW8JNP+BI8Uar9Nv3BYsWiolipru++MnwswPmDZrV+8
hehxHRj6HWsd0SFf/Os33FsLusoia0m/ZC4dha5LQ7DIeGpa/6xQbBnb02DSBaMH
MyiRWMVkQ3y2x+vVENbq4JZt5kfYFJp28aI2nb8QUaBDN4m4bbSzJsuJTMRQp6Sv
nWB+GnQJslLDZBywlDvRubsSN0MKhqB+oZI+BNIrNhY+ZZ7ohylMl4PpEZia+1jv
TNrIzI0MPTP4sEBibVExj9gJ22H/x/pHUHAlDABvWRKpnQj5RwkymQF/oF0t3b75
oA73A9ZhOjekH5odM7CwYoMYr9Kqgk5iKlx30ebs2uRR8HqgqSdsNjE1IcGHEes6
FE+4O1ll5Dlb1nK4GzUesCQNnfr6Md+EzOakQhVoNw==
-----END CERTIFICATE-----
"""

@dataclass
class DRCheckResult:
    timestamp: str
    status: str = "SUCCESS"
    dr_tool: Dict[str, Any] = None
    ec2_instances: List[Dict[str, Any]] = None
    errors: List[str] = None

    def __post_init__(self) -> None:
        self.dr_tool = self.dr_tool or {}
        self.ec2_instances = self.ec2_instances or []
        self.errors = self.errors or []

    def add_error(self, msg: str, component: str = "") -> None:
        error_msg = f"[{component}] {msg}" if component else msg
        self.errors.append(error_msg)
        self.status = "PARTIAL" if self.status == "SUCCESS" else self.status
        LOGGER.warning(error_msg)


# Writes the AXA certificate content to a file in the Lambda /tmp directory.
try:
    with open(CERT_PATH, 'w') as cert_file:
        cert_file.write(AXA_CERT)
except Exception as e:
    raise Exception(f"Failed to write certificate: {e}")

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    LOGGER.info('## EVENT')
    LOGGER.info(f"## Received event: {json.dumps(event, default=str)}")
    
    LOGGER.info('## ENVIRONMENT VARIABLES')
    LOGGER.info(json.dumps(dict(os.environ)))
    
    LOGGER.info('## CALLER')
    LOGGER.info(json.dumps(boto3.client('sts').get_caller_identity()))

    result = DRCheckResult(timestamp=datetime.now(timezone.utc).isoformat())
    base_session = boto3.Session()

    latest_tf_version: Optional[str] = None
    tool_session: Optional[Session] = None
    sc_client = None
    portfolio_id = None
    product_id = None
    provisioned_product = None
    amplify_app_id = None

    # ==============================
    # 0. Get Latest Terraform Module Version
    # ==============================
    LOGGER.info(f"## Get Latest Terraform module Version")
    try:
        latest_tf_version = _get_latest_module_version()
        if not latest_tf_version:
            result.add_error("Latest Terraform module version not found", "TFE")
        LOGGER.info(f"## Found Terraform module version : {latest_tf_version}")
    except Exception as e:
        result.add_error(f"TFE module check failed: {e}", "TFE")
        latest_tf_version = "UNKNOWN"

    # ==============================
    # 1. Assume Role in Tool Account
    # ==============================
    try:
        tool_session = _assume_role(base_session, ROLE_ARN, REGION)
        LOGGER.info("## Assumed role successfully in Tool Account")
        sc_client = tool_session.client("servicecatalog", region_name=REGION)
    except Exception as e:
        result.add_error(f"Failed to assume tool role: {e}", "IAM")
        return _format_response(result, status_code=200)
    # ==============================
    # 2. Service Catalog: Portfolio → Product → Provisioned Product
    # ==============================
    try:
        portfolio_id = _get_portfolio_id(sc_client, PORTFOLIO_NAME)
        if not portfolio_id:
            raise ValueError(f"Portfolio '{PORTFOLIO_NAME}' not found")
        LOGGER.info(f"## Found portfolio id : {portfolio_id}")
        
        product_id = _get_product_id(sc_client, portfolio_id, PRODUCT_NAME)
        if not product_id:
            raise ValueError(f"Product '{PRODUCT_NAME}' not found")
        LOGGER.info(f"## Found product id : {product_id}")
        
        provisioned_product = _get_provisioned_product(sc_client, product_id)
        LOGGER.info(f"## Found provisioned product : {provisioned_product}")

        if not provisioned_product:
            raise ValueError(f"No provisioned product for '{PRODUCT_NAME}'")
        LOGGER.info(f"## Found disaster recovery provisioned product : {provisioned_product.get('id')}")
        
        result.dr_tool.update({
            "provisioned_product_name": provisioned_product.get("name"),
            "provisioned_product_id": provisioned_product.get("id"),
            "provisioned_product_status": provisioned_product.get("status"),
            "provisioned_product_version": provisioned_product.get("version"),
            "created_time": provisioned_product.get("created_time").isoformat()
        })
    except Exception as e:
        result.add_error(str(e), "ServiceCatalog")
                
    # ==============================
    # 3. Amplify App Check
    # ==============================
    # try:
    #     LOGGER.info("## Check amplify app.")
    #     product_details = _describe_provisioned_product_with_outputs(sc_client, provisioned_product["id"])
    #     amplify_app_id = _extract_output(product_details.get("outputs", []), "AmplifyAppId")
    #     if not amplify_app_id:
    #         raise ValueError("AmplifyAppId output missing")
    #     LOGGER.info(f"## Found amplify application id: {amplify_app_id}.")
               
    #     amplify_status = _check_amplify_app_by_id(tool_session, REGION, amplify_app_id)
    #     result.dr_tool["amplify_app"] = amplify_status
    # except Exception as e:
    #     result.add_error(f"Amplify check failed: {e}", "Amplify")

    # ==============================
    # 4. Query DynamoDB for EC2 Records
    # ==============================
    ec2_records: List[Dict] = []
    try:
        dynamodb_client = tool_session.client("dynamodb", region_name=REGION)
        LOGGER.info('## CALLER')
        LOGGER.info(json.dumps(tool_session.client('sts').get_caller_identity()))
        ec2_records = _query_dynamodb_instances(dynamodb_client, DYNAMODB_TABLE_NAME)
        LOGGER.info(f"## Found records in DynamoDB: {len(ec2_records)}")
    except Exception as e:
        result.add_error(f"DynamoDB query failed: {e}", "DynamoDB")

    # ==============================
    # 5. Process EC2 Instances Per Account
    # ==============================
    grouped_by_account = _group_by_account_id(ec2_records)
    
    for account_id, records in grouped_by_account.items():
        try:
            if account_id != "864899851412":
                continue
            role_arn = f"arn:aws:iam::{account_id}:role/awscc/{ENTITY_NAME}.ENTITYTOOL_Provisioning"
            target_session = _assume_role(tool_session, role_arn, REGION)
            LOGGER.info(f"## Assumed role successfully in Account {account_id}")
            LOGGER.info('## CALLER')
            LOGGER.info(json.dumps(target_session.client('sts').get_caller_identity()))
            account_report = _validate_account_instances(
                session=target_session,
                records=records,
                latest_tf_version=latest_tf_version or "UNKNOWN"
            )
            result.ec2_instances.extend(account_report)
        except Exception as e:
            LOGGER.error(f"Account {account_id} processing failed: {e}")
            result.ec2_instances.append({
                "account_id": account_id,
                "hostname": [r.get("hostname") for r in records],
                "overall_instance_status": "ERROR",
                "issues": [f"Account-level failure: {e}"]
            })

    # Final status
    if result.errors:
        result.status = "PARTIAL" if result.ec2_instances or result.dr_tool else "FAILED"

    return _format_response(result)

# ========================
# Helper Functions
# ========================

def _assume_role(session: Session, role_arn: str, region: str) -> Session:
    sts_client = session.client("sts")
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="DR-Precheck-Session",
            DurationSeconds=3600,
        )
        creds = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    except Exception as e:
        raise RuntimeError(f"Role assumption failed: {e}")


def _get_latest_module_version() -> Optional[str]:
    url = f"https://{TFE_HOST}/api/v2/organizations/{SHARED_TFE_ORG}/registry-modules/private/{SHARED_TFE_ORG}/{TERRAFORM_MODULE_NAME}/{TERRAFORM_PROVIDER}"
    headers = {"Authorization": f"Bearer {TFE_TOKEN}", "Content-Type": "application/vnd.api+json"}
    try:
        resp = requests.get(url, headers=headers, timeout=10, verify='/tmp/cert.pem')
        resp.raise_for_status()
        versions = resp.json().get("data", {}).get("attributes", {}).get("version-statuses", [])
        return versions[0].get("version") if versions else None
    except Exception:
        return None


def _get_portfolio_id(sc_client, name):
    try:
        paginator = sc_client.get_paginator("list_portfolios")
        for page in paginator.paginate():
            for p in page.get("PortfolioDetails", []):
                if p["DisplayName"] == name:
                    return p["Id"]
        return None
    except Exception:
        return None


def _get_product_id(sc_client, portfolio_id, name):
    try:
        paginator = sc_client.get_paginator("search_products_as_admin")
        for page in paginator.paginate(PortfolioId=portfolio_id):
            for view in page.get("ProductViewDetails", []):
                summary = view.get("ProductViewSummary", {})
                if summary.get("Name") == name:
                    return summary.get("ProductId")
        return None
    except Exception:
        return None


def _get_provisioned_product(sc_client, product_id):
    try:
        paginator = sc_client.get_paginator("scan_provisioned_products")
        for page in paginator.paginate(AccessLevelFilter={"Key": "Account", "Value": "self"}):
            for p in page.get("ProvisionedProducts", []):
                if p.get("ProductId") == product_id:
                    provisioning_artifact= sc_client.describe_provisioning_artifact(
                        ProductId= product_id,
                        ProvisioningArtifactId=p.get('ProvisioningArtifactId')
                    )
                    return {"id": p.get("Id"), "name": p.get("Name"), "status": p.get("Status"), "version": provisioning_artifact.get('ProvisioningArtifactDetail').get('Name'), "created_time": p.get("CreatedTime")}
        return None
    except Exception:
        return None


def _describe_provisioned_product_with_outputs(sc_client, pp_id: str) -> Dict:
    try:
        detail = sc_client.describe_provisioned_product(Id=pp_id)["ProvisionedProductDetail"]
        outputs = []
        last_record_id = detail.get("LastSuccessfulProvisioningRecordId")
        if last_record_id:
            record = sc_client.describe_record(Id=last_record_id)
            outputs = [
                {"Key": o["OutputKey"], "Value": o["OutputValue"]}
                for o in record.get("RecordOutputs", [])
            ]
        return {"outputs": outputs, **detail}
    except Exception:
        return {"outputs": []}


def _extract_output(outputs: List[Dict], key: str) -> Optional[str]:
    for o in outputs:
        if o.get("Key") == key:
            return o.get("Value")
    return None


def _check_amplify_app_by_id(session: Session, region: str, app_id: str) -> Dict:
    client = session.client("amplify", region_name=region)
    try:
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


def _query_dynamodb_instances(client, table_name: str) -> List[Dict[str, str]]:
    records = []
    paginator = client.get_paginator("scan")
    try:
        for page in paginator.paginate(TableName=table_name):
            for item in page.get("Items", []):
                record = {k: v["S"] for k, v in item.items() if "S" in v}
                if "account_id" in record and "provisioned_product_id" in record:
                    records.append(record)
        return records
    except Exception:
        return []


def _group_by_account_id(records: List[Dict]) -> Dict[str, List[Dict]]:
    grouped = {}
    for r in records:
        grouped.setdefault(r["account_id"], []).append(r)
    return grouped


# ========================
# NEW: Per-Instance Report Builder
# ========================

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
    elb_client,
) -> Dict:
    report = {
        "account_id": record.get("account_id"),
        "hostname": record.get("hostname"), # TODO : hostname may be empty
        "overall_instance_status": "OK",
        "issues": []
    }

    # --- Service Catalog ---
    # is_up_to_date = _version_exists(pp.get("ProvisioningArtifactId"), support_versions)
    mpi_version= ec2_info.get("tags", {}).get("mpiversion")
    supported_mpi_versions= _extract_supported_versions(support_versions)

    if mpi_version not in  supported_mpi_versions:
        report["issues"].append(f"The current MPI version {mpi_version} is no longer supported. Supported versions are: {', '.join(support_versions)}. Please upgrade your product to one of these supported versions to ensure compatibility.")
        report["overall_instance_status"] = "WARNING"

    report["service_catalog"] = {
        "name": pp.get("Name"),
        "provisioned_product_id": record.get("provisioned_product_id"),
        "status": pp.get("Status"),
        "mpi_version": mpi_version,
        "supported_mpi_versions": supported_mpi_versions,
        "flow_type": flow_type,
    }
    # Check if the flow type is standard 
    if flow_type != 'standard':
        report["issues"].append("The parameter `FlowType` must be set to `standard`")
        report["overall_instance_status"] = "WARNING"


    # --- Terraform ---
    up_to_date_tf = tf_module_ver == latest_tf_version
    if not up_to_date_tf and tf_module_ver:
        report["issues"].append(f"Terraform module {tf_module_ver} != latest {latest_tf_version}")
        report["overall_instance_status"] = "WARNING"

    tf_slug = ec2_info.get("tags", {}).get("local.workspace_slug", "")

    report["terraform"] = {
        "module_version": tf_module_ver or "UNKNOWN",
        "latest_module_version": latest_tf_version,
        "up_to_date": up_to_date_tf,
        "workspace": {
            "slug": tf_slug,
            "locked": ws_health.get("locked"),
            "terraform_version": ws_health.get("terraform_version", "Unknown"),
            "latest_run_status": ws_health.get("latest_run_status", "No runs"),
            "assessment_results": ws_health.get("assessment_results"),
        }
    }

    # --- EC2 ---
    report["ec2"] = {
        "instance_id": ec2_info.get("instance_id"),
        "state": ec2_info.get("status"),
        "instance_type": ec2_info.get("instance_type")
    }

    # --- Capacity Reservations ---
    cr_type = _extract_output(pp.get("outputs", []), "CapacityReservationType") 
    primary_cr = _extract_output(pp.get("outputs", []), "PrimaryCRID")
    primary_avail = _is_cr_available(ec2_client, primary_cr)

    secondary_cr = _extract_output(pp.get("outputs", []), "SecondaryCRID")
    secondary_avail = _is_cr_available(ec2_client, secondary_cr)

    def _cr_entry(cid: str, avail: str) -> Dict:
        entry = {"id": cid, "available": avail == "AVAILABLE"}
        if not entry["available"]:
            entry["reason"] = avail
        return entry

    report["capacity_reservations"] = {
        "type": cr_type or "none",
        "primary": _cr_entry(primary_cr, primary_avail),
        "secondary": _cr_entry(secondary_cr, secondary_avail)
    }

    if secondary_cr and not report["capacity_reservations"]["secondary"]["available"]:
        report["issues"].append("Secondary CR not available")
        report["overall_instance_status"] = "ERROR"

    # --- Network ENIs ---
    primary_ip = _extract_output(pp.get("outputs", []), "ENI0PrivateIP")
    secondary_ip = _extract_output(pp.get("outputs", []), "ENI1PrivateIP")
    report["network_enis"] = {
        "primary": _network_entry(elb_client, ec2_client, primary_ip),
        "secondary": _network_entry(elb_client, ec2_client, secondary_ip)
    }

    # Final status
    if report["overall_instance_status"] == "OK" and report["issues"]:
        report["overall_instance_status"] = "WARNING"

    return report


def _network_entry(elb_client, ec2_client, ip: str) -> Dict:
    if not ip:
        return {
            "private_ip": None,
            "eni_id": "N/A",
            "attachment": "N/A",
            "target_groups": []
        }

    eni = _check_eni_attachment_by_ip(ec2_client, ip) or {}
    tgs = _find_target_groups_by_ip(elb_client, ip)

    return {
        "private_ip": ip,
        "eni_id": eni.get("NetworkInterfaceId", "NOT FOUND"),
        "attachment": eni.get("Status", "NOT FOUND"),
        "target_groups": tgs
    }


# ========================
# NEW: Account Instance Validation
# ========================

def _validate_account_instances(session: Session, records: List[Dict], latest_tf_version: str) -> List[Dict]:
    LOGGER.info('## CALLER')
    LOGGER.info(json.dumps(session.client('sts').get_caller_identity()))
    sc_client = session.client("servicecatalog", region_name=REGION)
    cf_client = session.client("cloudformation", region_name=REGION)
    ec2_client = session.client("ec2", region_name=REGION)
    elb_client = session.client("elbv2", region_name=REGION)

    report = []
    for record in records:
        try:
            # 1. Service Catalog
            pp = _describe_provisioned_product_with_outputs(sc_client, record["provisioned_product_id"])
            LOGGER.info(f"Provisioned Product: {pp}")
            support_versions = _get_last_5_versions(sc_client, pp.get("ProductId", ""))
            LOGGER.info(f"Support versions: {support_versions}")
            # 2. CloudFormation
            params = {}
            stack_arn = _extract_output(pp.get("outputs", []), "CloudformationStackARN")
            LOGGER.info(f"Stack ARN: {stack_arn}")
            if stack_arn:
                params = _get_stack_parameters(cf_client, stack_arn)

            # 3. EC2
            instance_id = _extract_output(pp.get("outputs", []), "EC2Instance")
            LOGGER.info(f"Instance ID: {instance_id}")
            
            ec2_info = _check_ec2_instance(ec2_client, instance_id) if instance_id else {}
            LOGGER.info(f"EC2 Info: {ec2_info}")

            tf_module_ver = ec2_info.get("tags", {}).get("local.module_version")
            LOGGER.info(f"TF Module Version: {tf_module_ver}")
            
            # 4. TFE Workspace
            tf_slug = ec2_info.get("tags", {}).get("local.workspace_slug")
            LOGGER.info(f"TF Slug: {tf_slug}")
            ws_health = {}
            if tf_slug and _is_valid_workspace_format(tf_slug):
                try:
                    org, ws = _parse_workspace_identifier(tf_slug)
                    ws_health = _get_workspace_health(TFE_HOST, org, ws, TFE_TOKEN)
                    LOGGER.info(f"Workspace Health: {ws_health}")
                except Exception as e:
                    ws_health = {"error": str(e)}

            # 5. Build Report
            instance_report = _build_instance_report(
                record=record,
                pp=pp,
                flow_type= params.get('FlowType'),
                ec2_info=ec2_info,
                tf_module_ver=tf_module_ver,
                ws_health=ws_health,
                latest_tf_version=latest_tf_version,
                support_versions=support_versions,
                ec2_client=ec2_client,
                elb_client=elb_client,
            )
            report.append(instance_report)
            break
        except Exception as e:
            report.append({
                "account_id": record.get("account_id"),
                "hostname": record.get("hostname"),
                "overall_instance_status": "ERROR",
                "issues": [f"Validation failed: {e}"]
            })
            LOGGER.error(f"Instance validation failed: {e}")

    return report


# ========================
# Reused Helpers (unchanged)
# ========================
    
def _get_stack_parameters(cf_client, stack_arn: str) -> Dict[str, str]:
    try:
        stack = cf_client.describe_stacks(StackName=stack_arn)["Stacks"][0]
        return {p["ParameterKey"]: p["ParameterValue"] for p in stack.get("Parameters", [])}
    except Exception:
        return {}


def _get_last_5_versions(sc_client, product_id: str) -> List[Dict]:
    try:
        artifacts = sc_client.list_provisioning_artifacts(ProductId=product_id)["ProvisioningArtifactDetails"]
        return sorted(artifacts, key=lambda x: x.get("CreatedTime", ""), reverse=True)[:5]
    except Exception:
        return []


def _version_exists(vid: str, versions: List[Dict]) -> bool:
    return any(v.get("Id") == vid for v in versions)


def _extract_supported_versions(versions: List[Dict]) -> List[str]:
    return [v.get("Name") for v in versions if v.get("Name")]

def _check_ec2_instance(ec2_client, instance_id: str) -> Dict:
    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        inst = resp["Reservations"][0]["Instances"][0]
        return {
            "instance_id": instance_id,
            "status": inst["State"]["Name"],
            "instance_type": inst.get("InstanceType"),
            "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
        }
    except Exception:
        return {"instance_id": instance_id, "status": "NOT_FOUND"}


def _is_cr_available(ec2_client, cr_id: str) -> str:
    if not cr_id:
        return "NOT CONFIGURED"
    try:
        resp = ec2_client.describe_capacity_reservations(CapacityReservationIds=[cr_id])
        cr = resp["CapacityReservations"][0]
        return "AVAILABLE" if cr.get("AvailableInstanceCount", 0) > 0 else "NOT AVAILABLE"
    except Exception:
        return "NOT FOUND"


def _find_target_groups_by_ip(elb_client, ip: str) -> List[Dict]:
    try:
        paginator = elb_client.get_paginator("describe_target_groups")
        matches = []
        for page in paginator.paginate():
            for tg in page["TargetGroups"]:
                health = elb_client.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                for t in health["TargetHealthDescriptions"]:
                    if t["Target"]["Id"] == ip:
                        matches.append({
                            "name": tg["TargetGroupName"],
                            "arn": tg["TargetGroupArn"],
                            "port": t["Target"]["Port"],
                        })
        return matches
    except Exception:
        return []


def _check_eni_attachment_by_ip(ec2_client, ip: str) -> Optional[Dict]:
    try:
        for filter_name in ["addresses.private-ip-address", "association.public-ip"]:
            resp = ec2_client.describe_network_interfaces(Filters=[{"Name": filter_name, "Values": [ip]}])
            if resp["NetworkInterfaces"]:
                eni = resp["NetworkInterfaces"][0]
                return {
                    "NetworkInterfaceId": eni["NetworkInterfaceId"],
                    "Status": "attached" if eni.get("Attachment") else "detached",
                }
        return None
    except Exception:
        return None


def _is_valid_workspace_format(v: str) -> bool:
    return isinstance(v, str) and len(v.strip().split("/")) == 2


def _parse_workspace_identifier(v: str) -> Tuple[str, str]:
    return tuple(v.strip().split("/"))


def _get_workspace_health(host: str, org: str, ws: str, token: str) -> Dict:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/vnd.api+json"}
    try:
         # --- Get workspace details ---
        url = f"https://{host}/api/v2/organizations/{org}/workspaces/{ws}"
        resp = requests.get(url, headers=headers, timeout=10, verify='/tmp/cert.pem')
        resp.raise_for_status()
        data = resp.json()["data"]
        ws_id = data["id"]

        # --- Get latest run ---
        runs = requests.get(f"https://{host}/api/v2/workspaces/{ws_id}/runs?page[size]=1", headers=headers, verify='/tmp/cert.pem')
        runs.raise_for_status()
        latest = runs.json().get("data", [])[0] if runs.json().get("data") else {}


         # --- Base workspace info ---
        result = {
            "organization": org,
            "workspace": ws,
            "locked": data["attributes"].get("locked", False),
            "terraform_version": data["attributes"].get("terraform-version", "Unknown"),
            "latest_run_status": latest.get("attributes", {}).get("status", "No runs")
        }
                
         # --- Check for assessments ---
        if data["attributes"].get("assessments-enabled", False):
            status_resp = requests.get(f"https://{host}/api/v2/workspaces/{ws_id}/current-assessment-result", headers=headers, verify='/tmp/cert.pem')
            if status_resp.status_code == 404:
                # No current assessment found
                result["assessment_results"] = "Assessments not found"
            else:
                status_resp.raise_for_status()
                status_data = status_resp.json().get("data", {})
                attr = status_data.get("attributes", {})
                result["assessment_results"] = {
                    "assessment_status": "succeeded" if attr.get("succeeded") else "failed",
                    "drift": attr.get("drifted", False),
                    "created_at": attr.get("created-at"),
                    "error_message": attr.get("error-message") if attr.get("error-message") else ''
                }
        else:
            result["assessment_results"] = "Assessments not enabled"

        return result
    except Exception as e:
        return {"error": str(e)}


# ========================
# NEW: Final Response Formatter
# ========================

def _format_response(result: DRCheckResult, status_code: int = 200) -> Dict[str, Any]:
    total = len(result.ec2_instances)
    ok = sum(1 for i in result.ec2_instances if i.get("overall_instance_status") == "OK")
    with_issues = total - ok

    dr_tool = {
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
            "total_mpi_instances": total,
            "instances_ok": ok,
            "instances_with_issues": with_issues,
            "dr_tool": dr_tool
        },
        "mpi_instances": result.ec2_instances
    }

    if result.errors:
        payload["errors"] = result.errors

    return {
        "statusCode": status_code,
        "body": json.dumps(payload, default=str)
    }
