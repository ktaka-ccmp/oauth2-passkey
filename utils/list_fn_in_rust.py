#!/usr/bin/env python3

import os
import re
import sys
import json
import argparse
from pathlib import Path

def parse_attributes(lines, start_idx):
    """Parse attributes (macros) preceding a function or module."""
    attributes = []
    current_idx = start_idx
    
    # Look backwards for attributes
    while current_idx > 0:
        current_idx -= 1
        line = lines[current_idx].strip()
        
        # Skip empty lines
        if not line:
            continue
            
        # Check if this line contains an attribute
        if line.startswith('#[') and line.endswith(']'):
            # Single-line attribute
            attr_content = line[2:-1].strip()
            attributes.insert(0, attr_content)
        elif line.startswith('#['):
            # Multi-line attribute - collect until closing ]
            attr_lines = [line[2:]]  # Remove #[
            current_idx += 1
            
            while current_idx < len(lines):
                attr_line = lines[current_idx].strip()
                if attr_line.endswith(']'):
                    attr_lines.append(attr_line[:-1])  # Remove ]
                    break
                else:
                    attr_lines.append(attr_line)
                current_idx += 1
            
            attr_content = ' '.join(attr_lines).strip()
            attributes.insert(0, attr_content)
            current_idx -= len(attr_lines)  # Adjust index
        else:
            # If we hit a non-attribute line, stop looking
            break
    
    return attributes

def parse_function_signature(signature):
    """Parse a function signature and extract components."""
    # Clean up the signature
    signature = re.sub(r'\s+', ' ', signature.strip())
    
    # Extract visibility
    visibility = "private"
    if re.search(r'\bpub\b', signature):
        if re.search(r'\bpub\(crate\)', signature):
            visibility = "pub(crate)"
        elif re.search(r'\bpub\(super\)', signature):
            visibility = "pub(super)"
        else:
            visibility = "public"
    
    # Check if async
    is_async = bool(re.search(r'\basync\b', signature))
    
    # Check if unsafe
    is_unsafe = bool(re.search(r'\bunsafe\b', signature))
    
    # Check if const
    is_const = bool(re.search(r'\bconst\b', signature))
    
    # Check if extern
    is_extern = bool(re.search(r'\bextern\b', signature))
    
    # Extract function name
    name_match = re.search(r'\bfn\s+([a-zA-Z_][a-zA-Z0-9_]*)', signature)
    if not name_match:
        return None
    
    function_name = name_match.group(1)
    
    # Extract parameters
    params_match = re.search(r'\([^)]*\)', signature)
    parameters = []
    
    if params_match:
        params_str = params_match.group(0)[1:-1].strip()  # Remove parentheses
        if params_str:
            # Split parameters by comma, but be careful with nested types
            param_parts = []
            current_param = ""
            paren_depth = 0
            angle_depth = 0
            
            for char in params_str:
                if char == '(':
                    paren_depth += 1
                elif char == ')':
                    paren_depth -= 1
                elif char == '<':
                    angle_depth += 1
                elif char == '>':
                    angle_depth -= 1
                elif char == ',' and paren_depth == 0 and angle_depth == 0:
                    param_parts.append(current_param.strip())
                    current_param = ""
                    continue
                
                current_param += char
            
            if current_param.strip():
                param_parts.append(current_param.strip())
            
            for param in param_parts:
                param = param.strip()
                if param:
                    # Split parameter into name and type
                    if ':' in param:
                        parts = param.split(':', 1)
                        param_name = parts[0].strip()
                        param_type = parts[1].strip()
                    else:
                        # Handle cases like 'self' or '&self'
                        param_name = param
                        param_type = param
                    
                    parameters.append({
                        "name": param_name,
                        "type": param_type
                    })
    
    # Extract return type
    return_type = ""
    return_match = re.search(r'->\s*([^{;]+)', signature)
    if return_match:
        return_type = return_match.group(1).strip()
    
    return {
        "name": function_name,
        "visibility": visibility,
        "is_async": is_async,
        "is_unsafe": is_unsafe,
        "is_const": is_const,
        "is_extern": is_extern,
        "parameters": parameters,
        "return_type": return_type,
        "description": ""
    }

def get_module_path(filepath, src_dir):
    """Generate module path from file path."""
    # Convert file path to module path
    rel_path = os.path.relpath(filepath, src_dir)
    
    # Remove .rs extension and convert path separators
    module_parts = rel_path.replace('.rs', '').split(os.sep)
    
    # Handle mod.rs files
    if module_parts[-1] == 'mod':
        module_parts.pop()
    
    # Filter out empty parts and create module path
    module_parts = [part for part in module_parts if part]
    
    if module_parts:
        return "crate::" + "::".join(module_parts)
    else:
        return "crate"

def extract_functions_from_file(filepath, src_dir):
    """Extract function information from a Rust file, including nested modules."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        # Skip files that can't be decoded as UTF-8
        return []
    
    base_module_path = get_module_path(filepath, src_dir)
    rel_filepath = os.path.relpath(filepath, src_dir)
    crate_name = get_project_name(src_dir)
    
    return parse_rust_content(content, base_module_path, rel_filepath, crate_name)

def parse_rust_content(content, base_module_path, file_path, crate_name):
    """Parse Rust content and extract functions, handling nested modules."""
    lines = content.split('\n')
    
    def parse_block(lines, start_idx, current_module_path, current_module_attributes=None):
        """Parse a block of code, tracking module nesting."""
        i = start_idx
        block_functions = []
        
        if current_module_attributes is None:
            current_module_attributes = []
        
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('//'):
                i += 1
                continue
            
            # Handle module declarations
            mod_match = re.match(r'^((pub(\([^)]*\))?)\s+)?mod\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{', line)
            if mod_match:
                module_name = mod_match.group(4)
                new_module_path = f"{current_module_path}::{module_name}"
                
                # Parse attributes for this module
                module_attributes = parse_attributes(lines, i)
                
                # Find the end of this module block
                module_start = i
                brace_count = 1
                i += 1
                
                while i < len(lines) and brace_count > 0:
                    line_content = lines[i]
                    # Count braces, but ignore those in strings/comments
                    in_string = False
                    in_comment = False
                    j = 0
                    while j < len(line_content):
                        char = line_content[j]
                        if not in_string and not in_comment:
                            if char == '"' and (j == 0 or line_content[j-1] != '\\'):
                                in_string = True
                            elif char == '/' and j + 1 < len(line_content) and line_content[j+1] == '/':
                                in_comment = True
                                break
                            elif char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                        elif in_string and char == '"' and (j == 0 or line_content[j-1] != '\\'):
                            in_string = False
                        j += 1
                    i += 1
                
                # Parse the module content
                if brace_count == 0:
                    module_content = '\n'.join(lines[module_start + 1:i - 1])
                    # Combine current module attributes with new ones
                    combined_attributes = current_module_attributes + module_attributes
                    module_functions = parse_rust_content(module_content, new_module_path, file_path, crate_name)
                    
                    # Add module attributes to all functions in this module
                    for func in module_functions:
                        func["module_attributes"] = combined_attributes
                    
                    block_functions.extend(module_functions)
                continue
            
            # Handle function declarations
            fn_pattern = r'^((pub(\([^)]*\))?|const|async|unsafe|extern)\s+)*fn\s+'
            if re.match(fn_pattern, line):
                # Parse attributes for this function
                function_attributes = parse_attributes(lines, i)
                
                # Found start of function
                signature = line
                
                # Check if function signature is complete on this line
                if re.search(r'[{;]\s*$', line):
                    # Single-line function
                    signature = re.sub(r'\s+', ' ', signature)
                    if re.search(r';\s*$', signature):
                        signature = re.sub(r';.*$', ';', signature)
                    else:
                        signature = re.sub(r'\{.*$', '{}', signature)
                    
                    func_info = parse_function_signature(signature)
                    if func_info:
                        func_info["canonical_name"] = f"{current_module_path}::{func_info['name']}"
                        func_info["module_path"] = current_module_path
                        func_info["file_path"] = file_path
                        func_info["attributes"] = function_attributes
                        func_info["module_attributes"] = current_module_attributes
                        func_info["crate_name"] = crate_name
                        block_functions.append(func_info)
                else:
                    # Multi-line function - collect continuation lines
                    i += 1
                    while i < len(lines):
                        next_line = lines[i].strip()
                        signature += ' ' + next_line
                        
                        if re.search(r'[{;]\s*$', next_line):
                            # Found end of signature
                            signature = re.sub(r'\s+', ' ', signature)
                            if re.search(r';\s*$', signature):
                                signature = re.sub(r';.*$', ';', signature)
                            else:
                                signature = re.sub(r'\{.*$', '{}', signature)
                            
                            func_info = parse_function_signature(signature)
                            if func_info:
                                func_info["canonical_name"] = f"{current_module_path}::{func_info['name']}"
                                func_info["module_path"] = current_module_path
                                func_info["file_path"] = file_path
                                func_info["attributes"] = function_attributes
                                func_info["module_attributes"] = current_module_attributes
                                func_info["crate_name"] = crate_name
                                block_functions.append(func_info)
                            break
                        i += 1
            
            i += 1
        
        return block_functions
    
    return parse_block(lines, 0, base_module_path)

def get_project_name(src_dir):
    """Extract project name from Cargo.toml or directory name."""
    cargo_toml = os.path.join(src_dir, "Cargo.toml")
    if os.path.exists(cargo_toml):
        try:
            with open(cargo_toml, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip().startswith('name'):
                        # Extract name from 'name = "project_name"'
                        match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', line)
                        if match:
                            return match.group(1)
        except:
            pass
    
    # Fallback to directory name
    return os.path.basename(os.path.abspath(src_dir))

def analyze_rust_project(src_dir, output_format="json"):
    """Analyze Rust project and return function information."""
    # Find all .rs files
    rust_files = []
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))
    
    rust_files.sort()
    
    all_functions = []
    
    for filepath in rust_files:
        functions = extract_functions_from_file(filepath, src_dir)
        all_functions.extend(functions)
    
    project_name = get_project_name(src_dir)
    
    if output_format == "json":
        result = {
            "project_name": project_name,
            "functions": all_functions
        }
        return json.dumps(result, indent=2)
    else:
        # Enhanced text format with attributes
        output = []
        current_file = None
        
        for func in all_functions:
            if func["file_path"] != current_file:
                if current_file is not None:
                    output.append("")  # Add blank line
                output.append(f"**{func['file_path']}:**")
                current_file = func["file_path"]
            
            # Build attribute strings
            attr_strings = []
            
            # Add module attributes if any
            if func.get("module_attributes"):
                for attr in func["module_attributes"]:
                    attr_strings.append(f"#[{attr}]")
            
            # Add function attributes if any
            if func.get("attributes"):
                for attr in func["attributes"]:
                    attr_strings.append(f"#[{attr}]")
            
            # Reconstruct signature for display
            modifiers = []
            if func["visibility"] != "private":
                modifiers.append(func["visibility"])
            if func.get("is_const"):
                modifiers.append("const")
            if func.get("is_unsafe"):
                modifiers.append("unsafe")
            if func.get("is_extern"):
                modifiers.append("extern")
            if func["is_async"]:
                modifiers.append("async")
            
            modifier_str = " ".join(modifiers)
            if modifier_str:
                modifier_str += " "
            
            params = ", ".join([f"{p['name']}: {p['type']}" for p in func["parameters"]])
            return_str = f" -> {func['return_type']}" if func["return_type"] else ""
            
            signature = f"{modifier_str}fn {func['name']}({params}){return_str}"
            
            # Combine attributes and signature on a single line
            if attr_strings:
                attrs_str = " ".join(attr_strings)
                full_line = f"{attrs_str} {signature}"
            else:
                full_line = signature
            
            output.append(f"  {full_line}")
        
        return "\n".join(output)

def main():
    parser = argparse.ArgumentParser(
        description='Analyze Rust project functions and output as JSON or text (with macro/attribute support)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s oauth2_passkey                    # Text output (default)
  %(prog)s oauth2_passkey --json             # JSON output  
  %(prog)s oauth2_passkey --json -o out.json # JSON to file

Features:
  - Parses function attributes like #[cfg(test)], #[tokio::test]
  - Handles module attributes that apply to nested functions
  - Supports multi-line attributes
  - Tracks function modifiers (const, unsafe, extern, async)
        '''
    )
    
    parser.add_argument('source_directory', 
                       help='Source directory containing Rust files')
    parser.add_argument('--json', action='store_true',
                       help='Output as JSON instead of text')
    parser.add_argument('-o', '--output', 
                       help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    src_dir = args.source_directory
    
    if not os.path.exists(src_dir):
        print(f"Error: Directory '{src_dir}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.isdir(src_dir):
        print(f"Error: '{src_dir}' is not a directory", file=sys.stderr)
        sys.exit(1)
    
    # Determine output format
    output_format = "json" if args.json else "text"
    
    # Analyze the project
    result = analyze_rust_project(src_dir, output_format)
    
    # Output result
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(result)
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(result)

if __name__ == "__main__":
    main()
