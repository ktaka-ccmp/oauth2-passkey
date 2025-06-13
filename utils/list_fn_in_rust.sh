#!/bin/bash

#SRCDIR="oauth2_passkey"
SRCDIR="$1"
if [[ -z "$SRCDIR" ]]; then
    echo "Usage: $0 <source_directory>"
    exit 1
fi

# Track if this is the first file to avoid leading blank line
first_file=true

find "$SRCDIR" -name "*.rs" | sort | while read -r file; do
    output=$(awk -v filename="$file" '
    BEGIN { 
        collecting = 0
        signature = ""
        file_functions = ""
    }
    
    # Enhanced pattern to match all function types including const, unsafe, extern
    /^[[:space:]]*((pub(\([^)]*\))?|const|async|unsafe|extern)[[:space:]]+)*fn[[:space:]]/ {
        # Start collecting a new function signature
        collecting = 1
        current_line = $0
        gsub(/^[[:space:]]+/, "", current_line)
        signature = current_line
        
        # Check if this is a complete single-line function
        if ($0 ~ /[{;][[:space:]]*$/) {
            gsub(/[[:space:]]+/, " ", signature)
            if ($0 ~ /;[[:space:]]*$/) {
                gsub(/;.*$/, ";", signature)
            } else {
                gsub(/\{.*$/, "{}", signature)
            }
            file_functions = file_functions "  " signature "\n"
            collecting = 0
            signature = ""
        }
        next
    }
    
    # Only process lines when we are collecting a multi-line function
    collecting == 1 {
        current_line = $0
        gsub(/^[[:space:]]+/, "", current_line)
        
        # Append this line to the signature
        signature = signature " " current_line
        
        # Check if this line ends the function signature
        if ($0 ~ /[{;][[:space:]]*$/) {
            # Clean up spacing and finish the signature
            gsub(/[[:space:]]+/, " ", signature)
            
            if ($0 ~ /;[[:space:]]*$/) {
                gsub(/;.*$/, ";", signature)
            } else {
                gsub(/\{.*$/, "{}", signature)
            }
            
            file_functions = file_functions "  " signature "\n"
            collecting = 0
            signature = ""
        }
    }
    
    END {
        if (length(file_functions) > 0) {
            print "**" filename ":**"
            printf "%s", file_functions
        }
    }
    ' "$file")
    
    # Only print output if the file had functions
    if [[ -n "$output" ]]; then
        # Add blank line before output (except for the first file)
        if [[ "$first_file" != true ]]; then
            echo
        fi
        echo "$output"
        first_file=false
    fi
done
