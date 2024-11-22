import json
import argparse

def format_resource_address(module_path, resource_type, resource_name, index_key=None):
    """
    Format the resource address considering modules and for_each.
    
    Args:
        module_path (list): List of module names in the path
        resource_type (str): Type of the resource
        resource_name (str): Name of the resource
        index_key: The for_each key if present
    
    Returns:
        str: Formatted resource address
    """
    # Build module path if present
    module_prefix = ""
    if module_path:
        module_prefix = "module." + ".module.".join(module_path) + "."
    
    # Build resource address
    if index_key is not None:
        # Handle for_each with proper quoting
        if isinstance(index_key, str):
            return f'{module_prefix}{resource_type}.{resource_name}["{index_key}"]'
        else:
            return f'{module_prefix}{resource_type}.{resource_name}[{index_key}]'
    else:
        return f'{module_prefix}{resource_type}.{resource_name}'

def generate_import_blocks(state_file):
    """
    Generate Terraform import blocks from a tfstate file, including modules and for_each resources.
    
    Args:
        state_file (str): Path to the terraform.tfstate file
    
    Returns:
        list: List of import block strings
    """
    import_blocks = []
    dependencies = {}
    
    try:
        with open(state_file, 'r') as f:
            state_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: State file {state_file} not found.")
        return []
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in state file {state_file}.")
        return []
    
    if 'resources' not in state_data:
        print("No resources found in the state file.")
        return []
    
    for resource in state_data['resources']:
        resource_type = resource.get('type', '')
        resource_name = resource.get('name', '')
        module_path = resource.get('module', '').split('.module.') if resource.get('module') else []
        
        # Filter out empty strings from module path
        module_path = [m for m in module_path if m]
        
        # Handle instances
        if 'instances' in resource:
            for instance in resource['instances']:
                try:
                    resource_id = instance['attributes'].get('id', '')
                    if not resource_id:
                        continue
                    
                    # Check for for_each key
                    index_key = instance.get('index_key')
                    
                    # Format resource address
                    resource_address = format_resource_address(
                        module_path, 
                        resource_type, 
                        resource_name, 
                        index_key
                    )
                    
                    # Generate import command
                    import_block = f"terraform import {resource_address} {resource_id}"
                    
                    # Store dependencies if present
                    dependencies[resource_address] = instance.get('dependencies', [])
                    
                    import_blocks.append(import_block)
                
                except KeyError as e:
                    print(f"Warning: Could not process resource {resource_type}.{resource_name}: {e}")
                    continue
    
    # Sort import blocks based on dependencies
    sorted_blocks = sort_import_blocks(import_blocks, dependencies)
    return sorted_blocks

def sort_import_blocks(import_blocks, dependencies):
    """
    Sort import blocks based on their dependencies.
    
    Args:
        import_blocks (list): List of import commands
        dependencies (dict): Dictionary of resource dependencies
    
    Returns:
        list: Sorted list of import commands
    """
    # Create a mapping of resource addresses to import blocks
    address_to_block = {}
    for block in import_blocks:
        address = block.split(' ')[2]  # Get resource address from import command
        address_to_block[address] = block
    
    # Sort based on dependencies
    sorted_blocks = []
    processed = set()
    
    def process_resource(address):
        if address in processed:
            return
        
        # Process dependencies first
        deps = dependencies.get(address, [])
        for dep in deps:
            if dep in address_to_block:
                process_resource(dep)
        
        # Add the current resource
        if address in address_to_block:
            sorted_blocks.append(address_to_block[address])
            processed.add(address)
    
    # Process all resources
    for address in address_to_block:
        process_resource(address)
    
    return sorted_blocks

def main():
    parser = argparse.ArgumentParser(description='Generate Terraform import blocks from state file')
    parser.add_argument('state_file', help='Path to the terraform.tfstate file')
    parser.add_argument('-o', '--output', help='Output file for import blocks', default=None)
    parser.add_argument('--module', help='Filter by specific module name', default=None)
    
    args = parser.parse_args()
    
    # Generate import blocks
    import_blocks = generate_import_blocks(args.state_file)
    
    # Filter by module if specified
    if args.module:
        import_blocks = [block for block in import_blocks if f'module.{args.module}.' in block]
    
    # Output handling
    if import_blocks:
        output = '#!/bin/bash\n\n# Generated Terraform import commands\n\n'
        output += '\n'.join(import_blocks)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"Import blocks written to {args.output}")
        else:
            print(output)
    else:
        print("No import blocks could be generated.")

if __name__ == '__main__':
    main()
