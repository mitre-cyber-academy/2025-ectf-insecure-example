#!/usr/bin/env python3
"""
Author: Crypto Caballeros
Date: 2025

Extract cryptographic keys from the secrets file and generate a C header file, 
to be used in decoder processes.
This script is intended to be run during the Docker build process.
"""
import os
import sys
import traceback
import json
import glob
from pathlib import Path

def debug_path(path):
    """Analyze a path and print detailed information about it"""
    print(f"Analyzing path: {path}")
    
    if not os.path.exists(path):
        print(f"  Path does not exist")
        return
        
    if os.path.isdir(path):
        print(f"  Path is a directory")
        try:
            contents = os.listdir(path)
            print(f"  Contains {len(contents)} items:")
            for item in contents:
                item_path = os.path.join(path, item)
                item_type = "dir" if os.path.isdir(item_path) else "file"
                item_size = os.path.getsize(item_path) if os.path.isfile(item_path) else "-"
                print(f"    {item} ({item_type}, {item_size} bytes)")
        except Exception as e:
            print(f"  Error listing directory: {e}")
    elif os.path.isfile(path):
        print(f"  Path is a file, size: {os.path.getsize(path)} bytes")
        try:
            with open(path, 'rb') as f:
                header = f.read(32)
            print(f"  File header (hex): {header.hex()[:60]}...")
            
            # Try to identify file type
            if header.startswith(b'{'):
                print(f"  Appears to be a JSON file (starts with brace)")
            elif header.startswith(b'PK'):
                print(f"  Appears to be a ZIP file")
            else:
                print(f"  Binary file type not immediately recognized")
                
        except Exception as e:
            print(f"  Error reading file: {e}")
    else:
        print(f"  Path exists but is neither file nor directory (special file)")

def print_debug_info():
    """Print comprehensive debug information about the environment"""
    print("\n===== ENVIRONMENT INFORMATION =====")
    print(f"Python version: {sys.version}")
    print(f"Current working directory: {os.getcwd()}")
    print(f"Environment variables: {dict(os.environ)}")
    
    print("\n===== ROOT DIRECTORY STRUCTURE =====")
    try:
        root_contents = os.listdir('/')
        print(f"Root directory contains {len(root_contents)} items:")
        for item in root_contents:
            path = os.path.join('/', item)
            item_type = "dir" if os.path.isdir(path) else "file"
            print(f"  /{item} ({item_type})")
    except Exception as e:
        print(f"Error listing root directory: {e}")
    
    print("\n===== CHECKING POTENTIAL SECRET PATHS =====")
    for path in ['/', '/secrets', '/global.secrets', '/secrets/secrets.json', '/global.secrets/secrets.json']:
        debug_path(path)
    
    print("\n===== CHECKING DECODER DIRECTORIES =====")
    for path in ['/decoder', '/decoder/scripts', '/decoder/inc']:
        debug_path(path)

def find_candidate_files():
    """Find all potential files that could contain secrets"""
    candidates = []
    
    # First, try direct paths that might be mounted files
    direct_paths = ['/global.secrets', '/secrets.json', '/global.json']
    for path in direct_paths:
        if os.path.isfile(path):
            candidates.append(path)
    
    # Then check common directories
    directories = ['/secrets', '/']
    for directory in directories:
        if not os.path.isdir(directory):
            continue
            
        # Look for JSON files
        for item in os.listdir(directory):
            full_path = os.path.join(directory, item)
            if os.path.isfile(full_path):
                if item.endswith('.json'):
                    candidates.append(full_path)
                elif item.endswith('.bin'):
                    candidates.append(full_path)
                # Also consider files without extensions
                elif '.' not in item:
                    candidates.append(full_path)
    
    return candidates

def try_parse_as_json(file_path):
    """Attempt to parse a file as JSON data"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        # Try direct JSON parsing
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try with different encodings
            for encoding in ['utf-8', 'latin-1', 'utf-16']:
                try:
                    text = content.decode(encoding)
                    return json.loads(text)
                except:
                    pass
    except Exception as e:
        print(f"Error parsing {file_path} as JSON: {e}")
    
    return None

def try_parse_as_bin(file_path):
    """Attempt to extract keys from a binary file format"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        print(f"Examining binary file {file_path}, size: {len(content)} bytes")
        
        # Try a simple key extraction based on known structure
        # This is a placeholder - you would need to replace this with actual
        # logic based on your binary format
        
        # For example - check if this is a JSON file without .json extension
        if content.startswith(b'{') and content.endswith(b'}'):
            try:
                json_data = json.loads(content)
                print(f"Successfully parsed {file_path} as JSON despite extension")
                return json_data
            except:
                pass
    
    except Exception as e:
        print(f"Error processing binary file {file_path}: {e}")
    
    return None

def generate_key_header(key_data, output_path):
    """Generate C header file with the key constants"""
    try:
        # Extract expected keys
        keys_to_extract = {
            "encryption_Key": "ENCRYPTION_KEY",
            "subscription_Key": "SUBSCRIPTION_KEY", 
            "MAC_Key": "MAC_KEY"
        }
        
        extracted_keys = {}
        for json_key, header_name in keys_to_extract.items():
            if json_key in key_data:
                try:
                    # Try to convert from hex string to bytes
                    key_bytes = bytes.fromhex(key_data[json_key])
                    extracted_keys[header_name] = key_bytes
                    print(f"Successfully extracted {header_name} ({len(key_bytes)} bytes)")
                except ValueError:
                    print(f"Error: '{json_key}' is not a valid hex string")
        
        if not extracted_keys:
            print("Error: No valid keys found in data")
            return False
        
        # Write the header file
        with open(output_path, 'w') as f:
            f.write("/**\n")
            f.write(" * @file secret_keys.h\n")
            f.write(" * @author Auto-generated\n")
            f.write(" * @brief Secret cryptographic keys for decoder\n")
            f.write(" */\n\n")
            
            f.write("#ifndef __SECRET_KEYS_H\n")
            f.write("#define __SECRET_KEYS_H\n\n")
            
            f.write("#include <stdint.h>\n\n")
            
            # Write key arrays
            for name, key_bytes in extracted_keys.items():
                f.write(f"/**\n * {name} extracted from secrets\n */\n")
                f.write(f"static const uint8_t {name}[] = {{\n    ")
                
                # Format bytes in rows of 8
                bytes_str = []
                for i, b in enumerate(key_bytes):
                    if i > 0 and i % 8 == 0:
                        bytes_str.append("\n    ")
                    bytes_str.append(f"0x{b:02x}")
                    if i < len(key_bytes) - 1:
                        bytes_str.append(", ")
                
                f.write("".join(bytes_str))
                f.write("\n};\n\n")
            
            # Define key sizes
            for name in extracted_keys.keys():
                f.write(f"#define {name}_SIZE (sizeof({name}))\n\n")
            
            # Add utility functions
            for name in extracted_keys.keys():
                f.write(f"static inline void load_{name.lower()}(uint8_t *key_buffer) {{\n")
                f.write(f"    for (int i = 0; i < {name}_SIZE; i++) {{\n")
                f.write(f"        key_buffer[i] = {name}[i];\n")
                f.write("    }\n")
                f.write("}\n\n")
            
            # Add secure clear function
            f.write("static inline void secure_clear(volatile uint8_t *buffer, size_t size) {\n")
            f.write("    if (buffer == NULL || size == 0) {\n")
            f.write("        return;\n")
            f.write("    }\n\n")
            f.write("    // Multiple pass overwrite\n")
            f.write("    volatile uint8_t *p;\n\n")
            f.write("    // First pass: 0xFF\n")
            f.write("    p = buffer;\n")
            f.write("    for (size_t i = 0; i < size; i++) {\n")
            f.write("        *p++ = 0xFF;\n")
            f.write("    }\n\n")
            f.write("    __asm__ volatile (\"\" : : : \"memory\");\n\n")
            f.write("    // Second pass: 0x00\n")
            f.write("    p = buffer;\n")
            f.write("    for (size_t i = 0; i < size; i++) {\n")
            f.write("        *p++ = 0x00;\n")
            f.write("    }\n\n")
            f.write("    __asm__ volatile (\"\" : : : \"memory\");\n")
            f.write("}\n\n")
            
            f.write("#endif // __SECRET_KEYS_H\n")
        
        print(f"Successfully wrote header file to {output_path}")
        return True
    
    except Exception as e:
        print(f"Error generating header file: {e}")
        traceback.print_exc()
        return False

def main():
    """Main function to extract keys and generate C header"""
    print("Starting key extraction process...")
    
    # Create output directory if it doesn't exist
    output_path = "/decoder/inc/secret_keys.h"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Print debug information to understand the environment
    print_debug_info()
    
    # Find all candidate files that might contain secrets
    candidates = find_candidate_files()
    print(f"\nFound {len(candidates)} candidate files: {candidates}")
    
    # Try parsing each candidate file
    for file_path in candidates:
        print(f"\nExamining file: {file_path}")
        
        # Try parsing as JSON first
        data = try_parse_as_json(file_path)
        if data:
            print(f"Successfully parsed {file_path} as JSON")
            if generate_key_header(data, output_path):
                print("Key extraction completed successfully!")
                return 0
        
        # If JSON parsing failed, try as binary
        data = try_parse_as_bin(file_path)
        if data:
            print(f"Successfully extracted keys from binary file {file_path}")
            if generate_key_header(data, output_path):
                print("Key extraction completed successfully!")
                return 0
    
    # If we get here, we failed to extract keys from any file
    print("\nERROR: Could not extract keys from any available files")
    
    # As a last resort, check if we can generate a minimal valid header
    # This allows the build to continue even if keys couldn't be extracted
    print("\nGenerating minimal header as fallback...")
    try:
        with open(output_path, 'w') as f:
            f.write("#ifndef __SECRET_KEYS_H\n")
            f.write("#define __SECRET_KEYS_H\n\n")
            f.write("#include <stdint.h>\n\n")
            f.write("// WARNING: This is a fallback header with empty keys\n")
            f.write("// The key extraction process failed\n\n")
            
            # Define empty keys
            for name in ["ENCRYPTION_KEY", "SUBSCRIPTION_KEY", "MAC_KEY"]:
                f.write(f"static const uint8_t {name}[] = {{ 0x00 }};\n")
                f.write(f"#define {name}_SIZE (sizeof({name}))\n\n")
                
                f.write(f"static inline void load_{name.lower()}(uint8_t *key_buffer) {{\n")
                f.write(f"    key_buffer[0] = {name}[0];\n")
                f.write("}\n\n")
            
            f.write("static inline void secure_clear(volatile uint8_t *buffer, size_t size) {\n")
            f.write("    if (buffer != NULL && size > 0) {\n")
            f.write("        *buffer = 0;\n")
            f.write("    }\n")
            f.write("}\n\n")
            
            f.write("#endif // __SECRET_KEYS_H\n")
        
        print("Generated fallback header file")
        return 1  # Non-zero exit code to indicate failure but allow build to continue
        
    except Exception as e:
        print(f"Failed to generate fallback header: {e}")
        return 2  # Error code

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Unhandled exception: {e}")
        traceback.print_exc()
        sys.exit(3)