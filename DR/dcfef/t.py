"""
AWS Lambda Function B: Public Handler
Runs outside VPC, handles Service Catalog, ELB, and Amplify operations
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

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

AWS_CLIENT_CONFIG = boto3.session.Config(
    connect_timeout=5,
    read_timeout=30,
    retries={'max_attempts': 3, 'mode': 'standard'}
)

# ============================================================================
# LAMBDA HANDLER - Main entry point
# ============================================================================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler for public API operations
    Routes requests based on operation type
    
    Expected event structure:
    {
        "operation": "query_service_catalog" | "check_amplify_app" | 
                     "get_provisioned_product_details" | "find_target_groups",
        "credentials": {
            "access_key_id": "...",
            "secret_access_key": "...",
            "session_token": "..."
        },
        "region": "us-east-1",
        ...additional operation-specific parameters
    }
    """
    
    LOGGER.info(f"## Received event: {json.dumps(event, default=str)}")
    
    try:
        # Validate required fields
        operation = event.get("operation")
        if not operation:
            return _error_response("Missing 'operation' field")
        
        credentials = event.get("credentials")
        if not credentials:
            return _error_response("Missing 'credentials' field")
        
        region = event.get("region")
        if not region:
            return _error_response("Missing 'region' field")
        
        # Create boto3 session with provided credentials
        session = boto3.Session(
            aws_access_key_id=credentials.get("access_key_id"),
            aws_secret_access_key=credentials.get("secret_access_key"),
            aws_session_token=credentials.get("session_token"),
            region_name=region
        )
        
        # Route to appropriate handler
        if operation == "query_service_catalog":
            return _handle_query_service_catalog(session, event)
        
        elif operation == "check_amplify_app":
            return _handle_check_amplify_app(session, event)
        
        elif operation == "get_provisioned_product_details":
            return _handle_get_provisioned_product_details(session, event)
        
        elif operation == "find_target_groups":
            return _handle_find_target_groups(session, event)
        
        else:
            return _error_response(f"Unknown operation: {operation}")
        
    except Exception as e:
        LOGGER.exception("Unhandled exception in lambda_handler")
        return _error_response(f"Internal error: {str(e)}")

# ============================================================================
# OPERATION HANDLERS
# ============================================================================

def _handle_query_service_catalog(session: boto3.Session, event: Dict) -> Dict:
    """
    Query Service Catalog for DR tool information
    
    Required event fields:
    - portfolio_name: Name of the Service Catalog portfolio
    - product_name: Name of the Service Catalog product
    """
    try:
        portfolio_name = event.get("portfolio_name")
        product_name = event.get("product_name")
        region = event.get("region")
        
        if not portfolio_name or not product_name:
            return _error_response("Missing portfolio_name or product_name")
        
        sc_client = session.client("servicecatalog", region_name=region, config=AWS_CLIENT_CONFIG)
        
        # Get portfolio
        portfolio_id = _get_portfolio_id(sc_client, portfolio_name)
        if not portfolio_id:
            return _error_response(f"Portfolio '{portfolio_name}' not found")
        
        LOGGER.info(f"Found portfolio ID: {portfolio_id}")
        
        # Get product
        product_id = _get_product_id(sc_client, portfolio_id, product_name)
        if not product_id:
            return _error_response(f"Product '{product_name}' not found in portfolio")
        
        LOGGER.info(f"Found product ID: {product_id}")
        
        # Get provisioned product
        provisioned_product = _get_provisioned_product(sc_client, product_id)
        if not provisioned_product:
            return _error_response(f"No provisioned product found for '{product_name}'")
        
        LOGGER.info(f"Found provisioned product: {provisioned_product.get('id')}")
        
        return _success_response({
            "provisioned_product_name": provisioned_product.get("name"),
            "provisioned_product_id": provisioned_product.get("id"),
            "provisioned_product_status": provisioned_product.get("status"),
            "provisioned_product_version": provisioned_product.get("version"),
            "created_time": provisioned_product.get("created_time")
        })
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return _error_response(f"Service Catalog API error ({error_code}): {str(e)}")
    except Exception as e:
        LOGGER.exception("Error in query_service_catalog")
        return _error_response(f"Service Catalog query failed: {str(e)}")


def _handle_check_amplify_app(session: boto3.Session, event: Dict) -> Dict:
    """
    Check Amplify application status
    
    Required event fields:
    - provisioned_product_id: Service Catalog provisioned product ID
    """
    try:
        pp_id = event.get("provisioned_product_id")
        region = event.get("region")
        
        if not pp_id:
            return _error_response("Missing provisioned_product_id")
        
        # Get Amplify App ID from Service Catalog outputs
        sc_client = session.client("servicecatalog", region_name=region, config=AWS_CLIENT_CONFIG)
        product_details = _describe_provisioned_product_with_outputs(sc_client, pp_id)
        
        amplify_app_id = _extract_output(product_details.get("outputs", []), "AmplifyAppId")
        
        if not amplify_app_id:
            return _error_response("AmplifyAppId output not found in provisioned product")
        
        LOGGER.info(f"Found Amplify application ID: {amplify_app_id}")
        
        # Check Amplify app status
        amplify_client = session.client("amplify", region_name=region, config=AWS_CLIENT_CONFIG)
        
        try:
            app = amplify_client.get_app(appId=amplify_app_id)["app"]
            return _success_response({
                "app_id": amplify_app_id,
                "status": "ACTIVE",
                "name": app.get("name")
            })
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "NotFoundException":
                return _success_response({
                    "app_id": amplify_app_id,
                    "status": "NOT_FOUND",
                    "error": "Amplify app not found"
                })
            else:
                return _success_response({
                    "app_id": amplify_app_id,
                    "status": "ERROR",
                    "error": str(e)
                })
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return _error_response(f"Amplify check API error ({error_code}): {str(e)}")
    except Exception as e:
        LOGGER.exception("Error in check_amplify_app")
        return _error_response(f"Amplify check failed: {str(e)}")


def _handle_get_provisioned_product_details(session: boto3.Session, event: Dict) -> Dict:
    """
    Get detailed information about a provisioned product including outputs
    
    Required event fields:
    - provisioned_product_id: Service Catalog provisioned product ID
    """
    try:
        pp_id = event.get("provisioned_product_id")
        region = event.get("region")
        
        if not pp_id:
            return _error_response("Missing provisioned_product_id")
        
        sc_client = session.client("servicecatalog", region_name=region, config=AWS_CLIENT_CONFIG)
        
        # Get provisioned product details with outputs
        pp_details = _describe_provisioned_product_with_outputs(sc_client, pp_id)
        
        # Get CloudFormation parameters
        stack_arn = _extract_output(pp_details.get("outputs", []), "CloudformationStackARN")
        
        cf_params = {}
        if stack_arn:
            cf_client = session.client("cloudformation", region_name=region, config=AWS_CLIENT_CONFIG)
            cf_params = _get_stack_parameters(cf_client, stack_arn)
        
        # Get last 5 versions
        product_id = pp_details.get("ProductId")
        support_versions = []
        if product_id:
            support_versions = _get_last_5_versions(sc_client, product_id)
        
        # Extract key outputs
        data = {
            "name": pp_details.get("Name"),
            "product_id": pp_details.get("ProductId"),
            "status": pp_details.get("Status"),
            "instance_id": _extract_output(pp_details.get("outputs", []), "EC2Instance"),
            "primary_eni_ip": _extract_output(pp_details.get("outputs", []), "ENI0PrivateIP"),
            "secondary_eni_ip": _extract_output(pp_details.get("outputs", []), "ENI1PrivateIP"),
            "primary_cr_id": _extract_output(pp_details.get("outputs", []), "PrimaryCRID"),
            "secondary_cr_id": _extract_output(pp_details.get("outputs", []), "SecondaryCRID"),
            "cr_type": _extract_output(pp_details.get("outputs", []), "CapacityReservationType"),
            "flow_type": cf_params.get("FlowType"),
            "supported_mpi_versions": _extract_supported_versions(support_versions)
        }
        
        return _success_response(data)
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return _error_response(f"Service Catalog API error ({error_code}): {str(e)}")
    except Exception as e:
        LOGGER.exception("Error in get_provisioned_product_details")
        return _error_response(f"Failed to get provisioned product details: {str(e)}")


def _handle_find_target_groups(session: boto3.Session, event: Dict) -> Dict:
    """
    Find all ELB target groups containing the given IP addresses
    
    Required event fields:
    - ip_addresses: List of IP addresses to check
    """
    try:
        ip_addresses = event.get("ip_addresses", [])
        region = event.get("region")
        
        if not ip_addresses:
            return _success_response({})
        
        elb_client = session.client("elbv2", region_name=region, config=AWS_CLIENT_CONFIG)
        
        # Build result dictionary: IP -> list of target groups
        result = {}
        
        for ip in ip_addresses:
            result[ip] = _find_target_groups_by_ip(elb_client, ip)
        
        return _success_response(result)
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        return _error_response(f"ELB API error ({error_code}): {str(e)}")
    except Exception as e:
        LOGGER.exception("Error in find_target_groups")
        return _error_response(f"Failed to find target groups: {str(e)}")

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
# ELB HELPERS
# ============================================================================

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
# RESPONSE HELPERS
# ============================================================================

def _success_response(data: Any) -> Dict[str, Any]:
    """Format successful response"""
    return {
        "status": "success",
        "data": data
    }


def _error_response(error_message: str) -> Dict[str, Any]:
    """Format error response"""
    LOGGER.error(f"Error response: {error_message}")
    return {
        "status": "error",
        "error": error_message
    }
