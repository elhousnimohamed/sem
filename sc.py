#!/usr/bin/env python3
"""
Find Service Catalog provisioned product matching specific account information.

This script searches through AWS Service Catalog provisioned products for a specific product,
extracts account information from outputs, and returns the provisioned product ID matching a given account ID.

Handles pagination manually since search_provisioned_products doesn't support automatic pagination.
"""

import argparse
import json
import logging
import sys
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(name)-16s | %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S"
)

def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Find Service Catalog provisioned product by account ID",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--product-id", required=True,
                        help="Service Catalog Product ID to search")
    parser.add_argument("--account-id", required=True,
                        help="Target AWS account ID to find")
    parser.add_argument("--region", default="eu-central-1",
                        help="AWS region name")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--max-results", type=int, default=20,
                        help="Max results per API call (AWS limit: 100)")
    
    return parser.parse_args()

def get_servicecatalog_client(region, profile=None):
    """Create AWS Service Catalog client with error handling."""
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        return session.client('servicecatalog', region_name=region)
    except (BotoCoreError, ClientError) as error:
        logger.error("AWS API connection failed: %s", error)
        sys.exit(1)

def find_matching_provisioned_product(client, product_id, target_account_id, max_results):
    """
    Search provisioned products and find matching account ID.
    
    Args:
        client: Service Catalog client
        product_id: Product ID to search
        target_account_id: Account ID to match
        max_results: Max results per API call
    
    Returns:
        Matching provisioned product ID or None
    """
    next_page_token = None
    processed_count = 0

    try:
        while True:
            # Prepare API parameters
            params = {
                'Filters': {'SearchQuery': [f"productId:{product_id}"]},
                'AccessLevelFilter': {'Key': 'Account', 'Value': 'self'},
                'PageSize': max_results
            }
            if next_page_token:
                params['PageToken'] = next_page_token

            # Execute API call
            response = client.search_provisioned_products(**params)
            products = response.get('ProvisionedProducts', [])
            logger.info("Processing %d provisioned products", len(products))
            processed_count += len(products)

            # Process each product
            for product in products:
                pp_id = product['Id']
                logger.debug("Checking provisioned product: %s", pp_id)
                if process_provisioned_product(client, pp_id, target_account_id):
                    return pp_id

            # Handle pagination
            next_page_token = response.get('NextPageToken')
            if not next_page_token:
                logger.info("Finished processing %d products", processed_count)
                break

    except ClientError as error:
        logger.error("AWS API request failed: %s", error)
        sys.exit(1)
    
    return None

def process_provisioned_product(client, provisioned_product_id, target_account_id):
    """
    Process a single provisioned product to check for account match.
    
    Args:
        client: Service Catalog client
        provisioned_product_id: Provisioned product ID to check
        target_account_id: Account ID to match
    
    Returns:
        True if account matches, False otherwise
    """
    try:
        response = client.describe_provisioned_product(Id=provisioned_product_id)
        outputs = response['ProvisionedProductDetail'].get('Outputs', [])
        
        for output in outputs:
            if output.get('OutputKey') == 'CallbackData':
                callback_value = output.get('OutputValue', '')
                if callback_value and check_callback_data(callback_value, target_account_id):
                    return True
    except ClientError as error:
        logger.warning("Skipping product %s: %s", provisioned_product_id, error)
    except KeyError as error:
        logger.warning("Unexpected response structure for product %s: %s", provisioned_product_id, error)
    
    return False

def check_callback_data(callback_data, target_account_id):
    """
    Parse and validate CallbackData output.
    
    Args:
        callback_data: JSON string from CallbackData output
        target_account_id: Account ID to match
    
    Returns:
        True if account matches, False otherwise
    """
    try:
        # Handle potential double-encoded JSON
        outer_data = json.loads(callback_data)
        account_info = json.loads(outer_data['AccountInfo'])
        return account_info.get('account_id') == target_account_id
    except (KeyError, json.JSONDecodeError, TypeError) as error:
        logger.warning("Invalid CallbackData format: %s", error)
        return False

def main():
    """Main execution function."""
    args = parse_arguments()
    logger.info("Starting search for account: %s in product: %s", 
                args.account_id, args.product_id)
    
    # Validate max results within AWS limits
    if args.max_results > 100 or args.max_results < 1:
        logger.error("Max results must be between 1 and 100")
        sys.exit(2)
    
    sc_client = get_servicecatalog_client(args.region, args.profile)
    result = find_matching_provisioned_product(
        client=sc_client,
        product_id=args.product_id,
        target_account_id=args.account_id,
        max_results=args.max_results
    )
    
    if result:
        print(result)
        logger.info("Found matching provisioned product: %s", result)
    else:
        logger.error("No matching provisioned product found")
        sys.exit(1)

if __name__ == "__main__":
    main()
