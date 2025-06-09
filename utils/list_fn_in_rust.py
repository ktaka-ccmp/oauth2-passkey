#!/usr/bin/env python3

import os
import re
import sys

def extract_functions_from_file(filepath):
    """Extract function signatures from a Rust file."""
    functions = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Enhanced pattern to match all function types
        fn_pattern = r'^((pub(\([^)]*\))?|const|async|unsafe|extern)\s+)*fn\s+'
        
        if re.match(fn_pattern, line):
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
                functions.append(signature)
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
                        functions.append(signature)
                        break
                    i += 1
        i += 1
    
    return functions

def list_rust_functions(src_dir):
    """List all functions from Rust files in the specified directory."""
    # Find all .rs files
    rust_files = []
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))
    
    rust_files.sort()
    
    first_file = True
    
    for filepath in rust_files:
        functions = extract_functions_from_file(filepath)
        
        if functions:
            # Add blank line before output (except for the first file)
            if not first_file:
                print()
            
            print(f"**{filepath}:**")
            for func in functions:
                print(f"  {func}")
            
            first_file = False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <source_directory>", file=sys.stderr)
        print("Example: python3 list_functions.py oauth2_passkey", file=sys.stderr)
        sys.exit(1)
    
    src_dir = sys.argv[1]
    
    if not os.path.exists(src_dir):
        print(f"Error: Directory '{src_dir}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.isdir(src_dir):
        print(f"Error: '{src_dir}' is not a directory", file=sys.stderr)
        sys.exit(1)
    
    list_rust_functions(src_dir)
    