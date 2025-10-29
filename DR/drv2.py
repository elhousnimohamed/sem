import json
import logging
import os
from datetime import datetime

import boto3
import requests
from botocore.exceptions import ClientError

# Configure logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
ROLE_ARN = os.environ["ROLE_ARN"]
REGION = os.environ["REGION"]
PORTFOLIO_NAME = os.environ["PORTFOLIO_NAME"]
PRODUCT_NAME = os.environ["PRODUCT_NAME"]
DYNAMODB_TABLE_NAME = os.environ["DYNAMODB_TABLE_NAME"]
TFE_HOST = os.environ["TFE_HOST"]
TFE_TOKEN = os.environ.get("TERRAFORM_API_TOKEN", "")
SHARED_TFE_ORG = os.environ["SHARED_TFE_ORG"]
TERRAFORM_MODULE_NAME = os.environ["TERRAFORM_MODULE_NAME"]
TERRAFORM_PROVIDER = os.environ["TERRAFORM_PROVIDER"]
ENTITY_NAME = os.environ["ENTITY_NAME"]


def lambda_handler(event, context):
    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "status": "SUCCESS",
        "dr_tool": {},
        "ec2_instances": [],
        "errors": []
    }

    base_session = boto3.Session()
    latest_tf_version = "UNKNOWN"
    tool_session = None
    sc_client = None
    provisioned_product = None

    # ==============================
    # 0. Get Latest Terraform Module Version
    # ==============================
    try:
        latest_tf_version = _get_latest_module_version()
        if not latest_tf_version:
            _add_error(result, "Latest Terraform module version not found", "TFE")
    except Exception as e:
        _add_error(result, f"TFE module check failed: {e}", "TFE")
        latest_tf_version = "UNKNOWN"

    # ==============================
    # 1. Assume Role in Tool Account
    # ==============================
    try:
        tool_session = _assume_role(base_session, ROLE_ARN, REGION)
        sc_client = tool_session.client("servicecatalog", region_name=REGION)
    except Exception as e:
        _add_error(result, f"Failed to assume tool role: {e}", "IAM")
        return _format_response(result)

    # ==============================
    # 2. Service Catalog: Portfolio → Product → Provisioned Product
    # ==============================
    try:
        portfolio_id = _get_portfolio_id(sc_client, PORTFOLIO_NAME)
        if not portfolio_id:
            raise ValueError(f"Portfolio '{PORTFOLIO_NAME}' not found")

        product_id = _get_product_id(sc_client, portfolio_id, PRODUCT_NAME)
        if not product_id:
            raise ValueError(f"Product '{PRODUCT_NAME}' not found")

        provisioned_product = _get_provisioned_product(sc_client, product_id)
        if not provisioned_product:
            raise ValueError(f"No provisioned product for '{PRODUCT_NAME}'")

        result["dr_tool"].update({
            "provisioned_product_name": provisioned_product["name"],
            "provisioned_product_id": provisioned_product["id"],
            "provisioned_product_status": provisioned_product["status"],
        })
    except Exception as e:
        _add_error(result, str(e), "ServiceCatalog")

    # ==============================
    # 3. Amplify App Check
    # ==============================
    if provisioned_product:
        try:
            product_details = _describe_provisioned_product_with_outputs(sc_client, provisioned_product["id"])
            amplify_app_id = _extract_output(product_details.get("outputs", []), "AmplifyAppId")
            if not amplify_app_id:
                raise ValueError("AmplifyAppId output missing")

            amplify_status = _check_amplify_app_by_id(tool_session, REGION, amplify_app_id)
            result["dr_tool"]["amplify_app"] = amplify_status
        except Exception as e:
            _add_error(result, f"Amplify check failed: {e}", "Amplify")

    # ==============================
    # 4. Query DynamoDB for EC2 Records
    # ==============================
    ec2_records = []
    if tool_session:
        try:
            dynamodb_client = tool_session.client("dynamodb", region_name=REGION)
            ec2_records = _query_dynamodb_instances(dynamodb_client, DYNAMODB_TABLE_NAME)
        except Exception as e:
            _add_error(result, f"DynamoDB query failed: {e}", "DynamoDB")

    # ==============================
    # 5. Process EC2 Instances Per Account
    # ==============================
    grouped_by_account = _group_by_account_id(ec2_records)
    for account_id, records in grouped_by_account.items():
        try:
            role_arn = f"arn:aws:iam::{account_id}:role/awscc/{ENTITY_NAME}.ENTITYTOOL_Provisioning"
            target_session = _assume_role(tool_session, role_arn, REGION)
            account_report = _validate_account_instances(target_session, records, latest_tf_version)
            result["ec2_instances"].extend(account_report)
        except Exception as e:
            logger.error(f"Account {account_id} processing failed: {e}")
            result["ec2_instances"].append({
                "account_id": account_id,
                "hostname": [r.get("hostname") for r in records],
                "overall_instance_status": "ERROR",
                "issues": [f"Account-level failure: {e}"]
            })

    # Final status
    if result["errors"]:
        result["status"] = "PARTIAL" if result["ec2_instances"] or result["dr_tool"] else "FAILED"

    return _format_response(result)


# ========================
# Helper Functions
# ========================

def _add_error(result, msg, component=""):
    error_msg = f"[{component}] {msg}" if component else msg
    result["errors"].append(error_msg)
    result["status"] = "PARTIAL" if result["status"] == "SUCCESS" else result["status"]
    logger.warning(error_msg)


def _assume_role(session, role_arn, region):
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


def _get_latest_module_version():
    url = f"https://{TFE_HOST}/api/v2/organizations/{SHARED_TFE_ORG}/registry-modules/private/{SHARED_TFE_ORG}/{TERRAFORM_MODULE_NAME}/{TERRAFORM_PROVIDER}"
    headers = {"Authorization": f"Bearer {TFE_TOKEN}", "Content-Type": "application/vnd.api+json"}
    try:
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        resp.raise_for_status()
        versions = resp.json().get("data", {}).get("attributes", {}).get("version-statuses", [])
        return versions[0].get("version") if versions else None
    except Exception:
        return None


def _get_portfolio_id(sc_client, name):
    paginator = sc_client.get_paginator("list_portfolios")
    for page in paginator.paginate():
        for p in page.get("PortfolioDetails", []):
            if p["DisplayName"] == name:
                return p["Id"]
    return None


def _get_product_id(sc_client, portfolio_id, name):
    paginator = sc_client.get_paginator("search_products_as_admin")
    for page in paginator.paginate(PortfolioId=portfolio_id):
        for view in page.get("ProductViewDetails", []):
            summary = view.get("ProductViewSummary", {})
            if summary.get("Name") == name:
                return summary.get("ProductId")
    return None


def _get_provisioned_product(sc_client, product_id):
    paginator = sc_client.get_paginator("scan_provisioned_products")
    for page in paginator.paginate(AccessLevelFilter={"Key": "Account", "Value": "self"}):
        for p in page.get("ProvisionedProducts", []):
            if p.get("ProductId") == product_id:
                return {"id": p.get("Id"), "name": p.get("Name"), "status": p.get("Status")}
    return None


def _describe_provisioned_product_with_outputs(sc_client, pp_id):
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


def _extract_output(outputs, key):
    for o in outputs:
        if o.get("Key") == key:
            return o.get("Value")
    return None


def _check_amplify_app_by_id(session, region, app_id):
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


def _query_dynamodb_instances(client, table_name):
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


def _group_by_account_id(records):
    grouped = {}
    for r in records:
        grouped.setdefault(r["account_id"], []).append(r)
    return grouped


# ========================
# Per-Instance Report Builder
# ========================

def _build_instance_report(record, pp, params, ec2_info, tf_module_ver, ws_health, latest_tf_version, support_versions, ec2_client, elb_client):
    report = {
        "account_id": record.get("account_id"),
        "hostname": record.get("hostname"),
        "overall_instance_status": "OK",
        "issues": []
    }

    # Service Catalog
    is_up_to_date = any(v.get("Id") == pp.get("provisioning_artifact_id") for v in support_versions)
    report["service_catalog"] = {
        "provisioned_product_id": record.get("provisioned_product_id"),
        "status": pp.get("status"),
        "mpi_version_up_to_date": is_up_to_date,
        "supported_mpi_versions": [v.get("Name") for v in support_versions if v.get("Name")]
    }

    # Terraform
    up_to_date_tf = tf_module_ver == latest_tf_version
    if not up_to_date_tf and tf_module_ver:
        report["issues"].append(f"Terraform module {tf_module_ver} ≠ latest {latest_tf_version}")
        report["overall_instance_status"] = "WARNING"

    tf_slug = ec2_info.get("tags", {}).get("local.workspace_slug", "")
    report["terraform"] = {
        "module_version": tf_module_ver or "UNKNOWN",
        "latest_available": latest_tf_version,
        "up_to_date": up_to_date_tf,
        "workspace": {
            "slug": tf_slug,
            "locked": ws_health.get("locked"),
            "terraform_version": ws_health.get("terraform_version", "Unknown"),
            "latest_run_status": ws_health.get("latest_run_status", "No runs"),
        }
    }

    # EC2
    report["ec2"] = {
        "instance_id": ec2_info.get("instance_id"),
        "state": ec2_info.get("status"),
        "instance_type": ec2_info.get("instance_type")
    }

    # Capacity Reservations
    cr_type = params.get("CapacityReservationType")
    primary_cr = params.get("PrimaryCRID")
    secondary_cr = params.get("SecondaryCRID")
    primary_avail = _is_cr_available(ec2_client, primary_cr)
    secondary_avail = _is_cr_available(ec2_client, secondary_cr)

    def _cr_entry(cid, avail):
        entry = {"id": cid, "available": avail == "AVAILABLE"}
        if not entry["available"]:
            entry["reason"] = avail
        return entry

    report["capacity_reservations"] = {
        "type": cr_type or "none",
        "primary": _cr_entry(primary_cr, primary_avail),
        "secondary": _cr_entry(secondary_cr, secondary_avail)
    }

    if primary_cr and not report["capacity_reservations"]["primary"]["available"]:
        report["issues"].append("Primary CR not available")
        report["overall_instance_status"] = "ERROR"
    if secondary_cr and not report["capacity_reservations"]["secondary"]["available"]:
        report["issues"].append("Secondary CR not available")
        report["overall_instance_status"] = "ERROR"

    # Network ENIs
    primary_ip = params.get("ENI0PrivateIP")
    secondary_ip = params.get("ENI1PrivateIP")
    report["network_enis"] = {
        "primary": _network_entry(elb_client, ec2_client, primary_ip),
        "secondary": _network_entry(elb_client, ec2_client, secondary_ip)
    }

    # Final status
    if report["overall_instance_status"] == "OK" and report["issues"]:
        report["overall_instance_status"] = "WARNING"

    return report


def _network_entry(elb_client, ec2_client, ip):
    if not ip:
        return {
            "private_ip": None,
            "eni_id": "N/A",
            "attachment": "N/A",
            "target_groups": []
        }

    eni = _check_eni_attachment_by_ip(ec2_client, ip) or {}
    tgs = _find_target_groups_by_ip(elb_client, ip)
    for tg in tgs:
        tg["health"] = "healthy"

    return {
        "private_ip": ip,
        "eni_id": eni.get("NetworkInterfaceId", "NOT FOUND"),
        "attachment": eni.get("Status", "NOT FOUND"),
        "target_groups": tgs
    }


# ========================
# Account Validation
# ========================

def _validate_account_instances(session, records, latest_tf_version):
    sc_client = session.client("servicecatalog", region_name=REGION)
    cf_client = session.client("cloudformation", region_name=REGION)
    ec2_client = session.client("ec2", region_name=REGION)
    elb_client = session.client("elbv2", region_name=REGION)

    report = []
    for record in records:
        try:
            pp = _describe_provisioned_product_with_outputs(sc_client, record["provisioned_product_id"])
            support_versions = _get_last_5_versions(sc_client, pp.get("product_id", ""))

            params = {}
            stack_arn = _extract_output(pp.get("outputs", []), "CloudformationStackARN")
            if stack_arn:
                params = _get_stack_parameters(cf_client, stack_arn)

            instance_id = params.get("EC2Instance")
            ec2_info = _check_ec2_instance(ec2_client, instance_id) if instance_id else {}
            tf_module_ver = ec2_info.get("tags", {}).get("local.module_version")

            tf_slug = ec2_info.get("tags", {}).get("local.workspace_slug")
            ws_health = {}
            if tf_slug and "/" in tf_slug:
                try:
                    org, ws = tf_slug.split("/", 1)
                    ws_health = _get_workspace_health(TFE_HOST, org, ws, TFE_TOKEN)
                except Exception as e:
                    ws_health = {"error": str(e)}

            instance_report = _build_instance_report(
                record=record,
                pp=pp,
                params=params,
                ec2_info=ec2_info,
                tf_module_ver=tf_module_ver,
                ws_health=ws_health,
                latest_tf_version=latest_tf_version,
                support_versions=support_versions,
                ec2_client=ec2_client,
                elb_client=elb_client,
            )
            report.append(instance_report)

        except Exception as e:
            report.append({
                "account_id": record.get("account_id"),
                "hostname": record.get("hostname"),
                "overall_instance_status": "ERROR",
                "issues": [f"Validation failed: {e}"]
            })
            logger.error(f"Instance validation failed: {e}")

    return report


# ========================
# Reused Helpers
# ========================

def _get_stack_parameters(cf_client, stack_arn):
    try:
        stack = cf_client.describe_stacks(StackName=stack_arn)["Stacks"][0]
        return {p["ParameterKey"]: p["ParameterValue"] for p in stack.get("Parameters", [])}
    except Exception:
        return {}


def _get_last_5_versions(sc_client, product_id):
    try:
        artifacts = sc_client.list_provisioning_artifacts(ProductId=product_id)["ProvisioningArtifactDetails"]
        return sorted(artifacts, key=lambda x: x.get("CreatedTime", ""), reverse=True)[:5]
    except Exception:
        return []


def _check_ec2_instance(ec2_client, instance_id):
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


def _is_cr_available(ec2_client, cr_id):
    if not cr_id:
        return "NOT CONFIGURED"
    try:
        resp = ec2_client.describe_capacity_reservations(CapacityReservationIds=[cr_id])
        cr = resp["CapacityReservations"][0]
        return "AVAILABLE" if cr.get("AvailableInstanceCount", 0) > 0 else "NOT AVAILABLE"
    except Exception:
        return "NOT FOUND"


def _find_target_groups_by_ip(elb_client, ip):
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


def _check_eni_attachment_by_ip(ec2_client, ip):
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


def _get_workspace_health(host, org, ws, token):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/vnd.api+json"}
    try:
        url = f"https://{host}/api/v2/organizations/{org}/workspaces/{ws}"
        resp = requests.get(url, headers=headers, timeout=10, verify=False)
        resp.raise_for_status()
        data = resp.json()["data"]
        ws_id = data["id"]
        runs = requests.get(f"https://{host}/api/v2/workspaces/{ws_id}/runs?page[size]=1", headers=headers, verify=False)
        runs.raise_for_status()
        latest = runs.json().get("data", [{}])[0]
        return {
            "organization": org,
            "workspace": ws,
            "locked": data["attributes"].get("locked", False),
            "terraform_version": data["attributes"].get("terraform-version", "Unknown"),
            "latest_run_status": latest.get("attributes", {}).get("status", "No runs"),
        }
    except Exception as e:
        return {"error": str(e)}


# ========================
# Final Response
# ========================

def _format_response(result):
    total = len(result["ec2_instances"])
    ok = sum(1 for i in result["ec2_instances"] if i.get("overall_instance_status") == "OK")
    with_issues = total - ok

    dr_tool = {
        "amplify_app": result["dr_tool"].get("amplify_app", {}),
        "service_catalog": {
            "portfolio": PORTFOLIO_NAME,
            "product": PRODUCT_NAME,
            "provisioned_product": result["dr_tool"].get("provisioned_product_name"),
            "status": result["dr_tool"].get("provisioned_product_status")
        }
    }

    payload = {
        "timestamp": result["timestamp"],
        "overall_status": result["status"],
        "summary": {
            "total_mpi_instances": total,
            "instances_ok": ok,
            "instances_with_issues": with_issues,
            "dr_tool": dr_tool
        },
        "mpi_instances": result["ec2_instances"]
    }

    if result["errors"]:
        payload["errors"] = result["errors"]

    return {
        "statusCode": 200,
        "body": json.dumps(payload, default=str)
    }
