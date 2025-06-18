#!/usr/bin/env python3
"""
Find Service Catalog provisioned product matching specific account information.

Handles large numbers of provisioned products (>100) with parallel processing and proper output retrieval.
Uses get_provisioned_product_outputs API for efficient output fetching.
"""

import argparse
import json
import logging
import sys
import concurrent.futures
import time
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
    parser.add_argument("--max-workers", type=int, default=10,
                        help="Max parallel threads for processing")
    parser.add_argument("--page-size", type=int, default=100,
                        help="Max results per API page (AWS limit: 100)")
    parser.add_argument("--max-pages", type=int, default=None,
                        help="Max pages to process (for testing)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Max execution time in seconds")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug logging")
    
    return parser.parse_args()

def get_servicecatalog_client(region, profile=None):
    """Create AWS Service Catalog client with error handling."""
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        return session.client('servicecatalog', region_name=region)
    except (BotoCoreError, ClientError) as error:
        logger.error("AWS API connection failed: %s", error)
        sys.exit(1)

def get_provisioned_products(client, product_id, page_size, max_pages=None):
    """Generator to yield provisioned products with pagination."""
    next_page_token = None
    page_count = 0

    try:
        while True:
            if max_pages and page_count >= max_pages:
                logger.info("Reached max pages limit (%d)", max_pages)
                break

            params = {
                'Filters': {'SearchQuery': [f"productId:{product_id}"]},
                'AccessLevelFilter': {'Key': 'Account', 'Value': 'self'},
                'PageSize': page_size
            }
            if next_page_token:
                params['PageToken'] = next_page_token

            response = client.search_provisioned_products(**params)
            products = response.get('ProvisionedProducts', [])
            page_count += 1
            logger.info("Retrieved page %d with %d products", page_count, len(products))
            
            yield from products

            next_page_token = response.get('NextPageToken')
            if not next_page_token:
                logger.info("Finished retrieving all %d pages", page_count)
                break

    except ClientError as error:
        logger.error("AWS API request failed: %s", error)
        sys.exit(1)

def get_outputs_for_product(client, provisioned_product_id):
    """Retrieve outputs for a provisioned product using proper API."""
    try:
        response = client.get_provisioned_product_outputs(
            ProvisionedProductId=provisioned_product_id
        )
        return response.get('Outputs', [])
    except ClientError as error:
        # Handle common errors gracefully
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        if error_code == 'ResourceNotFoundException':
            logger.warning("Provisioned product %s not found", provisioned_product_id)
        elif error_code == 'InvalidParametersException':
            logger.warning("Invalid parameters for product %s", provisioned_product_id)
        else:
            logger.warning("Error retrieving outputs for %s: %s", provisioned_product_id, error)
        return []

def process_product(client, product, target_account_id, verbose=False):
    """Process a single provisioned product to check for account match."""
    pp_id = product['Id']
    if verbose:
        logger.debug("Processing provisioned product: %s", pp_id)
    
    try:
        # Get outputs using the correct API
        outputs = get_outputs_for_product(client, pp_id)
        
        for output in outputs:
            if output.get('OutputKey') == 'CallbackData':
                callback_value = output.get('OutputValue', '')
                if callback_value:
                    if verbose:
                        logger.debug("Found CallbackData for %s: %s", pp_id, callback_value[:100] + '...' if len(callback_value) > 100 else callback_value)
                    if check_callback_data(callback_value, target_account_id, verbose):
                        return pp_id
    except Exception as error:
        logger.error("Unexpected error processing %s: %s", pp_id, error, exc_info=verbose)
    
    return None

def check_callback_data(callback_data, target_account_id, verbose=False):
    """Parse and validate CallbackData output."""
    try:
        # Handle potential double-encoded JSON
        outer_data = json.loads(callback_data)
        if verbose:
            logger.debug("Outer CallbackData: %s", json.dumps(outer_data, indent=2))
        
        # Check if AccountInfo is a string that needs parsing
        account_info_str = outer_data.get('AccountInfo')
        if isinstance(account_info_str, str):
            account_info = json.loads(account_info_str)
        else:
            account_info = account_info_str
        
        if verbose:
            logger.debug("AccountInfo: %s", json.dumps(account_info, indent=2))
        
        return account_info.get('account_id') == target_account_id
    except json.JSONDecodeError:
        # Try direct account ID extraction as fallback
        if verbose:
            logger.debug("JSON decode failed, trying direct search")
        return f'"account_id": "{target_account_id}"' in callback_data
    except (KeyError, TypeError) as error:
        if verbose:
            logger.debug("CallbackData format error: %s", error)
        return False

def main():
    """Main execution function with parallel processing."""
    args = parse_arguments()
    start_time = time.time()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose debugging enabled")
    
    logger.info("Starting search for account: %s in product: %s", 
                args.account_id, args.product_id)
    
    # Validate parameters
    if args.page_size > 100 or args.page_size < 1:
        logger.error("Page size must be between 1 and 100")
        sys.exit(2)
    if args.max_workers > 100:
        logger.warning("High worker count (%d) may trigger API limits", args.max_workers)
    
    sc_client = get_servicecatalog_client(args.region, args.profile)
    product_generator = get_provisioned_products(
        sc_client,
        args.product_id,
        args.page_size,
        args.max_pages
    )
    
    # Use thread pool for parallel processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = []
        matched_id = None
        processed_count = 0
        
        # Submit tasks as we retrieve products
        for product in product_generator:
            # Check timeout periodically
            if time.time() - start_time > args.timeout:
                logger.error("Execution timeout reached (%d seconds)", args.timeout)
                sys.exit(3)
            
            futures.append(
                executor.submit(
                    process_product, 
                    sc_client, 
                    product, 
                    args.account_id,
                    args.verbose
                )
            )
            processed_count += 1
            if processed_count % 100 == 0:
                logger.info("Submitted %d products for processing", processed_count)
        
        logger.info("Processing %d provisioned products", processed_count)
        
        # Process results as they complete
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            if i % 50 == 0 or i == processed_count:
                logger.info("Processed %d/%d products", i, processed_count)
            
            if result:
                matched_id = result
                logger.info("Found matching provisioned product: %s", matched_id)
                # Cancel remaining tasks since we found a match
                for f in futures:
                    f.cancel()
                break
    
    if matched_id:
        print(matched_id)
        logger.info("Total execution time: %.2f seconds", time.time() - start_time)
        sys.exit(0)
    else:
        logger.error("No matching provisioned product found after processing %d products", processed_count)
        sys.exit(1)

if __name__ == "__main__":
    main()
