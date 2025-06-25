#!/usr/bin/env python3
"""
AWS Service Catalog Product Retriever

This script retrieves all products from an AWS Service Catalog portfolio
and finds a specific product ID by name.

Requirements:
    - boto3
    - Appropriate AWS credentials configured
    - AWS Service Catalog permissions

Usage:
    python service_catalog_retriever.py --portfolio-id <portfolio-id> --product-name <product-name>
"""

import argparse
import logging
import sys
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


class ServiceCatalogClient:
    """AWS Service Catalog client wrapper with error handling."""
    
    def __init__(self, region_name: Optional[str] = None):
        """
        Initialize the Service Catalog client.
        
        Args:
            region_name: AWS region name. If None, uses default region.
        """
        try:
            self.client = boto3.client('servicecatalog', region_name=region_name)
            self.logger = logging.getLogger(__name__)
        except NoCredentialsError:
            raise ValueError("AWS credentials not found. Please configure your credentials.")
        except Exception as e:
            raise ValueError(f"Failed to initialize AWS Service Catalog client: {str(e)}")
    
    def list_portfolio_products(self, portfolio_id: str) -> List[Dict]:
        """
        List all products in a Service Catalog portfolio.
        
        Args:
            portfolio_id: The ID of the portfolio
            
        Returns:
            List of product dictionaries
            
        Raises:
            ValueError: If portfolio_id is invalid or API call fails
        """
        if not portfolio_id or not portfolio_id.strip():
            raise ValueError("Portfolio ID cannot be empty")
        
        products = []
        paginator = self.client.get_paginator('search_products_as_admin')
        
        try:
            for page in paginator.paginate(PortfolioId=portfolio_id):
                products.extend(page.get('ProductViewDetails', []))
            
            self.logger.info(f"Retrieved {len(products)} products from portfolio {portfolio_id}")
            return products
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            if error_code == 'ResourceNotFoundException':
                raise ValueError(f"Portfolio '{portfolio_id}' not found")
            elif error_code == 'AccessDeniedException':
                raise ValueError(f"Access denied to portfolio '{portfolio_id}'. Check your permissions.")
            else:
                raise ValueError(f"AWS API error ({error_code}): {error_message}")
                
        except BotoCoreError as e:
            raise ValueError(f"AWS connection error: {str(e)}")
    
    def find_product_by_name(self, products: List[Dict], product_name: str) -> Optional[Tuple[str, Dict]]:
        """
        Find a product by name in the list of products.
        
        Args:
            products: List of product dictionaries
            product_name: Name of the product to find
            
        Returns:
            Tuple of (product_id, product_details) if found, None otherwise
        """
        if not product_name or not product_name.strip():
            raise ValueError("Product name cannot be empty")
        
        product_name_lower = product_name.lower().strip()
        
        for product in products:
            product_view = product.get('ProductViewSummary', {})
            current_name = product_view.get('Name', '').lower().strip()
            
            if current_name == product_name_lower:
                product_id = product_view.get('ProductId')
                self.logger.info(f"Found product '{product_name}' with ID: {product_id}")
                return product_id, product
        
        self.logger.warning(f"Product '{product_name}' not found in portfolio")
        return None


def setup_logging(verbose: bool = False) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def print_products_table(products: List[Dict]) -> None:
    """Print products in a formatted table."""
    if not products:
        print("No products found in the portfolio.")
        return
    
    print(f"\n{'Product Name':<40} {'Product ID':<25} {'Type':<15}")
    print("-" * 80)
    
    for product in products:
        product_view = product.get('ProductViewSummary', {})
        name = product_view.get('Name', 'N/A')
        product_id = product_view.get('ProductId', 'N/A')
        product_type = product_view.get('Type', 'N/A')
        
        # Truncate long names for table formatting
        display_name = name[:37] + "..." if len(name) > 40 else name
        print(f"{display_name:<40} {product_id:<25} {product_type:<15}")


def main():
    """Main function to handle command line arguments and execute the script."""
    parser = argparse.ArgumentParser(
        description="Retrieve AWS Service Catalog products from a portfolio",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --portfolio-id port-1234567890 --product-name "My Product"
  %(prog)s --portfolio-id port-1234567890 --list-all
  %(prog)s --portfolio-id port-1234567890 --product-name "My Product" --region us-west-2 --verbose
        """
    )
    
    parser.add_argument(
        '--portfolio-id',
        required=True,
        help='AWS Service Catalog Portfolio ID'
    )
    
    parser.add_argument(
        '--product-name',
        help='Name of the product to find (case-insensitive)'
    )
    
    parser.add_argument(
        '--list-all',
        action='store_true',
        help='List all products in the portfolio'
    )
    
    parser.add_argument(
        '--region',
        help='AWS region (default: uses AWS CLI default region)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.product_name and not args.list_all:
        parser.error("Either --product-name or --list-all must be specified")
    
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize Service Catalog client
        sc_client = ServiceCatalogClient(region_name=args.region)
        
        # Retrieve products from portfolio
        logger.info(f"Retrieving products from portfolio: {args.portfolio_id}")
        products = sc_client.list_portfolio_products(args.portfolio_id)
        
        if args.list_all:
            print_products_table(products)
        
        if args.product_name:
            result = sc_client.find_product_by_name(products, args.product_name)
            
            if result:
                product_id, product_details = result
                print(f"\n✓ Product found!")
                print(f"  Name: {args.product_name}")
                print(f"  Product ID: {product_id}")
                
                if args.verbose:
                    product_view = product_details.get('ProductViewSummary', {})
                    print(f"  Type: {product_view.get('Type', 'N/A')}")
                    print(f"  Owner: {product_view.get('Owner', 'N/A')}")
                    print(f"  Short Description: {product_view.get('ShortDescription', 'N/A')}")
            else:
                print(f"\n✗ Product '{args.product_name}' not found in portfolio '{args.portfolio_id}'")
                
                # Suggest similar products
                similar_products = [
                    p.get('ProductViewSummary', {}).get('Name', '')
                    for p in products
                    if args.product_name.lower() in p.get('ProductViewSummary', {}).get('Name', '').lower()
                ]
                
                if similar_products:
                    print("\nSimilar products found:")
                    for similar in similar_products[:5]:  # Show max 5 suggestions
                        print(f"  - {similar}")
                
                sys.exit(1)
    
    except ValueError as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
