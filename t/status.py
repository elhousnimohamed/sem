#!/usr/bin/env python3
"""
AWS Service Catalog Provisioned Product Status Checker

This script checks the status of provisioned products in AWS Service Catalog
and retrieves error messages for products in error or tainted states.
"""

import boto3
import logging
import sys
from typing import Dict, List, Optional, Tuple
from botocore.exceptions import ClientError, NoCredentialsError
import argparse
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ProvisionedProductInfo:
    """Data class to hold provisioned product information."""
    id: str
    name: str
    type: str
    status: str
    status_message: Optional[str]
    created_time: Optional[datetime]
    last_record_id: Optional[str]
    error_details: Optional[str] = None


class ServiceCatalogChecker:
    """AWS Service Catalog provisioned product status checker."""
    
    def __init__(self, region_name: str = None, profile_name: str = None):
        """
        Initialize the Service Catalog checker.
        
        Args:
            region_name: AWS region name
            profile_name: AWS profile name
        """
        self.logger = self._setup_logging()
        self.region_name = region_name
        self.profile_name = profile_name
        
        try:
            # Initialize boto3 session and client
            if profile_name:
                session = boto3.Session(profile_name=profile_name)
                self.sc_client = session.client('servicecatalog', region_name=region_name)
            else:
                self.sc_client = boto3.client('servicecatalog', region_name=region_name)
                
            self.logger.info(f"Initialized AWS Service Catalog client for region: {region_name or 'default'}")
            
        except NoCredentialsError:
            self.logger.error("AWS credentials not found. Please configure your credentials.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Failed to initialize AWS client: {str(e)}")
            sys.exit(1)
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        # Create console handler with formatting
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        
        # Add handler to logger if not already added
        if not logger.handlers:
            logger.addHandler(console_handler)
        
        return logger
    
    def get_all_provisioned_products(self) -> List[ProvisionedProductInfo]:
        """
        Retrieve all provisioned products from AWS Service Catalog.
        
        Returns:
            List of ProvisionedProductInfo objects
        """
        provisioned_products = []
        
        try:
            paginator = self.sc_client.get_paginator('scan_provisioned_products')
            
            for page in paginator.paginate():
                for product in page.get('ProvisionedProducts', []):
                    product_info = ProvisionedProductInfo(
                        id=product.get('Id'),
                        name=product.get('Name'),
                        type=product.get('Type'),
                        status=product.get('Status'),
                        status_message=product.get('StatusMessage'),
                        created_time=product.get('CreatedTime'),
                        last_record_id=product.get('LastRecordId')
                    )
                    provisioned_products.append(product_info)
            
            self.logger.info(f"Retrieved {len(provisioned_products)} provisioned products")
            return provisioned_products
            
        except ClientError as e:
            self.logger.error(f"AWS API error while retrieving provisioned products: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error while retrieving provisioned products: {e}")
            return []
    
    def get_provisioned_product_details(self, product_id: str) -> Optional[Dict]:
        """
        Get detailed information about a specific provisioned product.
        
        Args:
            product_id: The provisioned product ID
            
        Returns:
            Dictionary with product details or None if error
        """
        try:
            response = self.sc_client.describe_provisioned_product(Id=product_id)
            return response.get('ProvisionedProductDetail', {})
        except ClientError as e:
            self.logger.error(f"Error getting details for product {product_id}: {e}")
            return None
    
    def get_record_details(self, record_id: str) -> Optional[Dict]:
        """
        Get details about a provisioning record to extract error information.
        
        Args:
            record_id: The record ID
            
        Returns:
            Dictionary with record details or None if error
        """
        try:
            response = self.sc_client.describe_record(Id=record_id)
            return response.get('RecordDetail', {})
        except ClientError as e:
            self.logger.error(f"Error getting record details for {record_id}: {e}")
            return None
    
    def get_additional_details(self, product: ProvisionedProductInfo) -> str:
        """
        Get additional details for any provisioned product regardless of state.
        
        Args:
            product: ProvisionedProductInfo object
            
        Returns:
            Formatted additional details string
        """
        details = []
        
        # Add status message if available
        if product.status_message:
            details.append(f"Status Message: {product.status_message}")
        
        # Get record details for comprehensive information
        if product.last_record_id:
            record_details = self.get_record_details(product.last_record_id)
            if record_details:
                # Extract record status and type
                record_status = record_details.get('Status', 'Unknown')
                record_type = record_details.get('RecordType', 'Unknown')
                details.append(f"Last Record Status: {record_status}")
                details.append(f"Last Record Type: {record_type}")
                
                # Extract creation and update times
                created_time = record_details.get('CreatedTime')
                updated_time = record_details.get('UpdatedTime')
                if created_time:
                    details.append(f"Record Created: {created_time.strftime('%Y-%m-%d %H:%M:%S')}")
                if updated_time:
                    details.append(f"Record Updated: {updated_time.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Extract record errors (for ERROR/TAINTED states)
                record_errors = record_details.get('RecordErrors', [])
                if record_errors:
                    details.append("Record Errors:")
                    for error in record_errors:
                        error_code = error.get('Code', 'Unknown')
                        error_description = error.get('Description', 'No description')
                        details.append(f"  • {error_code}: {error_description}")
                
                # Extract outputs (for successful deployments)
                record_outputs = record_details.get('RecordOutputs', [])
                if record_outputs:
                    details.append("Record Outputs:")
                    for output in record_outputs[:5]:  # Limit to first 5 outputs
                        output_key = output.get('OutputKey', 'Unknown')
                        output_value = output.get('OutputValue', 'No value')
                        details.append(f"  • {output_key}: {output_value}")
                    if len(record_outputs) > 5:
                        details.append(f"  ... and {len(record_outputs) - 5} more outputs")
                
                # Extract record tags for additional context
                record_tags = record_details.get('RecordTags', [])
                if record_tags:
                    tag_info = ", ".join([f"{tag['Key']}={tag['Value']}" for tag in record_tags])
                    details.append(f"Record Tags: {tag_info}")
                
                # Extract path information
                path_id = record_details.get('PathId')
                if path_id:
                    details.append(f"Path ID: {path_id}")
        
        return "\n".join(details) if details else "No additional details available"
    
    def check_product_status(self, product_name: str = None, product_id: str = None) -> List[ProvisionedProductInfo]:
        """
        Check the status of provisioned products, handling all possible states.
        
        Args:
            product_name: Optional specific product name to check
            product_id: Optional specific product ID to check
            
        Returns:
            List of products with their status information
        """
        products = []
        
        # If specific product ID is provided, get only that product (most efficient)
        if product_id:
            product_details = self.get_provisioned_product_details(product_id)
            if product_details:
                product_info = ProvisionedProductInfo(
                    id=product_details.get('Id'),
                    name=product_details.get('Name'),
                    type=product_details.get('Type'),
                    status=product_details.get('Status'),
                    status_message=product_details.get('StatusMessage'),
                    created_time=product_details.get('CreatedTime'),
                    last_record_id=product_details.get('LastRecordId')
                )
                products = [product_info]
                self.logger.info(f"Retrieved product with ID: {product_id}")
            else:
                self.logger.warning(f"No product found with ID: {product_id}")
                return []
        else:
            # Get all products and filter by name if provided (less efficient)
            products = self.get_all_provisioned_products()
            
            if product_name:
                products = [p for p in products if p.name == product_name]
                if not products:
                    self.logger.warning(f"No product found with name: {product_name}")
                    return []
        
        # Get detailed information for all products (not just error/tainted)
        for product in products:
            # Always get additional details for comprehensive status reporting
            product.error_details = self.get_additional_details(product)
        
        return products
    
    def print_status_report(self, products: List[ProvisionedProductInfo]):
        """
        Print a formatted status report of provisioned products.
        
        Args:
            products: List of ProvisionedProductInfo objects
        """
        if not products:
            print("No provisioned products found.")
            return
        
        print(f"\n{'='*80}")
        print(f"AWS SERVICE CATALOG - PROVISIONED PRODUCTS STATUS REPORT")
        print(f"{'='*80}")
        print(f"Total Products: {len(products)}")
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}\n")
        
        # Group by status
        status_groups = {}
        for product in products:
            status = product.status.upper()
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(product)
        
        # Print summary by status
        for status, product_list in status_groups.items():
            print(f"{status}: {len(product_list)} product(s)")
        print()
        
        # Print detailed information for each product
        for i, product in enumerate(products, 1):
            print(f"{i}. Product: {product.name}")
            print(f"   ID: {product.id}")
            print(f"   Type: {product.type}")
            print(f"   Status: {product.status}")
            
            if product.created_time:
                print(f"   Created: {product.created_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if product.status_message:
                print(f"   Status Message: {product.status_message}")
            
            # Show detailed information for all products (not just error/tainted)
            if product.error_details:
                print(f"   Additional Details:")
                for line in product.error_details.split('\n'):
                    print(f"      {line}")
            
            print(f"   {'-'*60}")


def main():
    """Main function to run the Service Catalog status checker."""
    parser = argparse.ArgumentParser(
        description="Check AWS Service Catalog provisioned product status"
    )
    parser.add_argument(
        '--product-id', '-i',
        help="Specific product ID to check (optional)"
    )
    parser.add_argument(
        '--product-name', '-p',
        help="Specific product name to check (optional)"
    )
    parser.add_argument(
        '--region', '-r',
        help="AWS region (optional, uses default if not specified)"
    )
    parser.add_argument(
        '--profile',
        help="AWS profile name (optional)"
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize checker
    checker = ServiceCatalogChecker(
        region_name=args.region,
        profile_name=args.profile
    )
    
    # Check product status
    products = checker.check_product_status(
        product_name=args.product_name,
        product_id=args.product_id
    )
    
    # Print report
    checker.print_status_report(products)
    
    # Exit with specific codes based on product status
    if products:
        primary_status = products[0].status.upper()
        if primary_status in ['ERROR', 'TAINTED']:
            print(f"\n❌ Product is in {primary_status} state!")
            sys.exit(1)
        elif primary_status in ['UNDER_CHANGE', 'IN_PROGRESS']:
            print(f"\n🔄 Product is currently {primary_status}.")
            sys.exit(0)
        elif primary_status == 'AVAILABLE':
            print(f"\n✅ Product is AVAILABLE and healthy.")
            sys.exit(0)
        else:
            print(f"\n📊 Product status: {primary_status}")
            sys.exit(0)
    else:
        print(f"\n❓ No products found to check.")
        sys.exit(2)


if __name__ == "__main__":
    main()
