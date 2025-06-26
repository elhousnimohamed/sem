import argparse
import json
import logging
import sys
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError

# Configure logging for the script
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_product_id_by_name(
    service_catalog_client: boto3.client, product_name: str
) -> Optional[str]:
    """
    Retrieves the Product ID for a given AWS Service Catalog Product Name.

    Args:
        service_catalog_client: Boto3 Service Catalog client instance.
        product_name: The exact name of the Service Catalog Product.

    Returns:
        The Product ID string if found, otherwise None.
    """
    try:
        paginator = service_catalog_client.get_paginator('search_products')
        pages = paginator.paginate(
            Filters={'FullTextSearch': [product_name]},
            AcceptLanguage='en'
        )
        for page in pages:
            for product_view in page.get('ProductViewSummaries', []):
                # Ensure we get an exact match for the product name
                if product_view.get('Name') == product_name:
                    logger.info(f"Found Product ID '{product_view.get('ProductId')}' for Product Name '{product_name}'.")
                    return product_view.get('ProductId')
        logger.warning(f"Product with name '{product_name}' not found in Service Catalog.")
    except ClientError as e:
        logger.error(f"Error searching for product by name '{product_name}': {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while getting product ID by name: {e}")
    return None

def get_provisioned_products_for_product(
    service_catalog_client: boto3.client, product_name: str
) -> List[Dict[str, Any]]:
    """
    Retrieves all provisioned products associated with a specific AWS Service Catalog Product Name.

    Args:
        service_catalog_client: Boto3 Service Catalog client instance.
        product_name: The name of the Service Catalog Product.

    Returns:
        A list of dictionaries, each representing a provisioned product.
        Returns an empty list if no provisioned products are found or an error occurs.
    """
    provisioned_products = []
    product_id = get_product_id_by_name(service_catalog_client, product_name)

    if not product_id:
        logger.error(f"Cannot retrieve provisioned products: Product ID not found for name '{product_name}'.")
        return []

    paginator = service_catalog_client.get_paginator('search_provisioned_products')

    try:
        pages = paginator.paginate(
            Filters={'ProductId': [product_id]},
            AcceptLanguage='en' # Specify language to avoid potential errors
        )
        for page in pages:
            for pp in page.get('ProvisionedProducts', []):
                provisioned_products.append(pp)
        logger.info(f"Found {len(provisioned_products)} provisioned products for Product Name: {product_name} (ID: {product_id})")
    except ClientError as e:
        logger.error(f"Error listing provisioned products for product ID {product_id} (Name: {product_name}): {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while listing provisioned products: {e}")

    return provisioned_products

def get_provisioned_product_details(
    service_catalog_client: boto3.client, provisioned_product_id: str
) -> Optional[Dict[str, Any]]:
    """
    Retrieves detailed information, including outputs, for a specific provisioned product.

    Args:
        service_catalog_client: Boto3 Service Catalog client instance.
        provisioned_product_id: The ID of the provisioned product.

    Returns:
        A dictionary containing the provisioned product details, or None if an error occurs.
    """
    try:
        response = service_catalog_client.describe_provisioned_product(
            Id=provisioned_product_id,
            AcceptLanguage='en' # Specify language
        )
        return response.get('ProvisionedProductDetail')
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.warning(f"Provisioned product '{provisioned_product_id}' not found.")
        else:
            logger.error(f"Error describing provisioned product '{provisioned_product_id}': {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while describing provisioned product '{provisioned_product_id}': {e}")
    return None

def parse_callback_data(provisioned_product_outputs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Parses the 'CallbackData' output from a list of provisioned product outputs.

    Args:
        provisioned_product_outputs: A list of output dictionaries from a provisioned product.

    Returns:
        A dictionary containing the parsed AccountInfo from CallbackData, or None if not found or parsing fails.
    """
    for output in provisioned_product_outputs:
        if output.get('OutputKey') == 'CallbackData':
            callback_data_str = output.get('OutputValue')
            if callback_data_str:
                try:
                    callback_data = json.loads(callback_data_str)
                    account_info_str = callback_data.get('AccountInfo')
                    if account_info_str:
                        try:
                            account_info = json.loads(account_info_str)
                            return account_info
                        except json.JSONDecodeError:
                            logger.warning(f"Could not parse 'AccountInfo' JSON: {account_info_str}")
                    else:
                        logger.debug("'AccountInfo' key not found in CallbackData.")
                except json.JSONDecodeError:
                    logger.warning(f"Could not parse 'CallbackData' JSON: {callback_data_str}")
            return None # Return None if CallbackData exists but is empty or unparsable
    return None # Return None if CallbackData output key is not found

def find_matching_provisioned_products(
    product_name: str, target_account_id: str, region_name: str
) -> List[str]:
    """
    Finds provisioned product IDs that match the target account ID within their CallbackData.

    Args:
        product_name: The AWS Service Catalog Product Name.
        target_account_id: The specific AWS account ID to search for.
        region_name: The AWS region to connect to.

    Returns:
        A list of matching provisioned product IDs.
    """
    matched_provisioned_product_ids: List[str] = []

    try:
        service_catalog_client = boto3.client('servicecatalog', region_name=region_name)
    except Exception as e:
        logger.critical(f"Failed to create AWS Service Catalog client in region {region_name}: {e}")
        return matched_provisioned_product_ids

    logger.info(f"Searching for provisioned products under Product Name '{product_name}' "
                f"matching account ID '{target_account_id}' in region '{region_name}'.")

    provisioned_products = get_provisioned_products_for_product(service_catalog_client, product_name)

    if not provisioned_products:
        logger.info(f"No provisioned products found for Product Name '{product_name}'.")
        return matched_provisioned_product_ids

    for pp in provisioned_products:
        pp_id = pp.get('Id')
        pp_name = pp.get('Name')
        logger.info(f"Processing provisioned product: ID='{pp_id}', Name='{pp_name}'")

        if not pp_id:
            logger.warning(f"Skipping provisioned product with no ID: {pp}")
            continue

        pp_details = get_provisioned_product_details(service_catalog_client, pp_id)

        if pp_details and pp_details.get('Outputs'):
            account_info = parse_callback_data(pp_details['Outputs'])
            if account_info:
                extracted_account_id = account_info.get('account_id')
                if extracted_account_id == target_account_id:
                    matched_provisioned_product_ids.append(pp_id)
                    logger.info(f"MATCH FOUND: Provisioned Product ID '{pp_id}' "
                                f"for Account ID '{extracted_account_id}'.")
                else:
                    logger.debug(f"No match: PP ID '{pp_id}', Extracted Account ID '{extracted_account_id}' "
                                 f"does not match '{target_account_id}'.")
            else:
                logger.debug(f"No valid CallbackData with AccountInfo found for PP ID '{pp_id}'.")
        else:
            logger.debug(f"No details or outputs found for PP ID '{pp_id}'.")

    return matched_provisioned_product_ids

def main():
    """
    Main function to parse arguments and initiate the search for matching provisioned products.
    """
    parser = argparse.ArgumentParser(
        description="Find AWS Service Catalog provisioned product IDs by account ID in CallbackData."
    )
    parser.add_argument(
        '--product-name',
        required=True,
        help="The AWS Service Catalog Product Name (e.g., 'My-Cloud-Account-Product')."
    )
    parser.add_argument(
        '--target-account-id',
        required=True,
        help="The target AWS account ID to search for within the CallbackData output."
    )
    parser.add_argument(
        '--region',
        default='eu-central-1',
        help="The AWS region to operate in (default: eu-central-1)."
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Enable verbose logging (DEBUG level)."
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    matching_ids = find_matching_provisioned_products(
        product_name=args.product_name,
        target_account_id=args.target_account_id,
        region_name=args.region
    )

    if matching_ids:
        print("\n--- Matching Provisioned Product IDs ---")
        for pp_id in matching_ids:
            print(pp_id)
        print("--------------------------------------")
    else:
        print("\nNo provisioned products found matching the criteria.")

if __name__ == "__main__":
    main()
