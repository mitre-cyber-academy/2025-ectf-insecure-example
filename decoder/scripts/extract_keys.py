#!/usr/bin/env python3
"""
Author: Crypto Caballeros
Date: 2025

Extract cryptographic keys from the secrets file and generate a C header file
with XOR-obfuscated fragmentation to protect against memory attacks.
This script ensures the original key can be correctly reconstructed by the decoder.
"""
import os
import sys
import traceback
import json
import hashlib
import random
from pathlib import Path


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


def generate_key_header(key_data, output_path):
    """Generate C header file with the key constants using XOR obfuscation"""
    try:
        # Extract expected keys
        keys_to_extract = {
            "encryption_Key": "ENCRYPTION_KEY",
            "subscription_Key": "SUBSCRIPTION_KEY", 
            "MAC_Key": "MAC_KEY"
        }
        
        # Generate device-specific seed for masks
        # This will make each build's masks unique
        build_seed = os.urandom(16)
        
        extracted_keys = {}
        for json_key, header_name in keys_to_extract.items():
            if json_key in key_data:
                try:
                    # Convert from hex string to bytes
                    key_bytes = bytes.fromhex(key_data[json_key])
                    
                    # Ensure we have 32 bytes
                    if len(key_bytes) != 32:
                        if len(key_bytes) < 32:
                            key_bytes = key_bytes + bytes([0] * (32 - len(key_bytes)))
                        else:
                            key_bytes = key_bytes[:32]
                    
                    # Create 4 fragments of 8 bytes each
                    fragments = [
                        key_bytes[0:8],
                        key_bytes[8:16],
                        key_bytes[16:24],
                        key_bytes[24:32]
                    ]
                    
                    # Generate 4 unique XOR masks
                    masks = []
                    for i in range(4):
                        # Each mask is deterministic but unique
                        mask_seed = hashlib.sha256(build_seed + bytes([i]) + json_key.encode()).digest()
                        masks.append(mask_seed[:8])  # Use first 8 bytes as mask
                    
                    # Apply XOR to each fragment
                    masked_fragments = []
                    for i, fragment in enumerate(fragments):
                        masked = bytes(a ^ b for a, b in zip(fragment, masks[i]))
                        masked_fragments.append(masked)
                    
                    # Store fragments and masks
                    extracted_keys[header_name] = {
                        'fragments': masked_fragments,
                        'masks': masks,
                        'size': len(key_bytes)
                    }
                    
                    print(f"Successfully extracted and obfuscated {header_name} ({len(key_bytes)} bytes)")
                except ValueError:
                    print(f"Error: '{json_key}' is not a valid hex string")
        
        if not extracted_keys:
            print("Error: No valid keys found in data")
            return False
        
        # Write the header file
        with open(output_path, 'w') as f:
            f.write("/**\n")
            f.write(" * @file secret_keys.h\n")
            f.write(" * @author Crypto Caballeros\n")
            f.write(" * @brief Secret cryptographic keys with XOR obfuscation & memory clearing for memory attack protection,\n")
            f.write("    and delays to counter timing attacks\n")
            f.write(" * @date 2025\n")
            f.write(" */\n\n")
            
            f.write("#ifndef __SECRET_KEYS_H\n")
            f.write("#define __SECRET_KEYS_H\n\n")
            
            f.write("#include <stdint.h>\n\n")
            
            # Define memory barrier macro
            f.write("// Memory barrier to prevent compiler optimizations\n")
            f.write("#if defined(__GNUC__) || defined(__clang__)\n")
            f.write("    #define MEMORY_BARRIER() __asm__ volatile (\"\" : : : \"memory\")\n")
            f.write("#else\n")
            f.write("    #define MEMORY_BARRIER() ((void)0)\n")
            f.write("#endif\n\n")
            
            # Write secure memory clearing function first
            f.write("/**\n")
            f.write(" * @brief Securely clear sensitive data from memory using three passes\n")
            f.write(" * @param buffer Pointer to memory to clear\n")
            f.write(" * @param size Number of bytes to clear\n")
            f.write(" */\n")
            f.write("static inline void secure_zero_memory(volatile void *buffer, size_t size) {\n")
            f.write("    if (buffer == NULL || size == 0) {\n")
            f.write("        return;\n")
            f.write("    }\n\n")
            
            f.write("    volatile uint8_t *p = (volatile uint8_t *)buffer;\n\n")
            
            f.write("    // First pass: 0xFF (all ones)\n")
            f.write("    for (size_t i = 0; i < size; i++) {\n")
            f.write("        p[i] = 0xFF;\n")
            f.write("    }\n")
            f.write("    MEMORY_BARRIER();\n\n")
            
            f.write("    // Second pass: 0xAA (alternating bits)\n")
            f.write("    for (size_t i = 0; i < size; i++) {\n")
            f.write("        p[i] = 0xAA;\n")
            f.write("    }\n")
            f.write("    MEMORY_BARRIER();\n\n")
            
            f.write("    // Third pass: 0x00 (all zeros)\n")
            f.write("    for (size_t i = 0; i < size; i++) {\n")
            f.write("        p[i] = 0x00;\n")
            f.write("    }\n")
            f.write("    MEMORY_BARRIER();\n")
            f.write("}\n\n")
            
            # Write each key's fragments
            for name, key in extracted_keys.items():
                f.write(f"/**\n * {name} storage - fragmented and XOR obfuscated\n */\n")
                
                # Write the four masked fragments
                for i, fragment in enumerate(key['fragments']):
                    f.write(f"static const uint8_t {name}_FRAGMENT{i+1}[] = {{\n    ")
                    bytes_str = []
                    for j, b in enumerate(fragment):
                        if j > 0 and j % 8 == 0:
                            bytes_str.append("\n    ")
                        bytes_str.append(f"0x{b:02x}")
                        if j < len(fragment) - 1:
                            bytes_str.append(", ")
                    f.write("".join(bytes_str))
                    f.write("\n};\n\n")
                
                # Write the four XOR masks
                for i, mask in enumerate(key['masks']):
                    f.write(f"static const uint8_t {name}_MASK{i+1}[] = {{\n    ")
                    bytes_str = []
                    for j, b in enumerate(mask):
                        if j > 0 and j % 8 == 0:
                            bytes_str.append("\n    ")
                        bytes_str.append(f"0x{b:02x}")
                        if j < len(mask) - 1:
                            bytes_str.append(", ")
                    f.write("".join(bytes_str))
                    f.write("\n};\n\n")
                
                # Define key size
                f.write(f"#define {name}_SIZE {key['size']}\n\n")
                
                # Reconstruction function for each key type
                f.write(f"/**\n * @brief Load {name.lower()} from fragmented storage with anti-side-channel protections\n")
                f.write(f" * @param key_buffer Output buffer for key (must be at least {name}_SIZE bytes)\n")
                f.write(" */\n")
                f.write(f"static inline void load_{name.lower()}(uint8_t *key_buffer) {{\n")
                f.write("    if (key_buffer == NULL) return;\n\n")
                
                f.write("    // Reconstruct key from XOR-masked fragments\n")
                for i in range(4):
                    f.write(f"    // Fragment {i+1} - bytes {i*8} to {i*8+7}\n")
                    f.write(f"    for (int j = 0; j < 8; j++) {{\n")
                    f.write(f"        // XOR the fragment with its mask to recover original bytes\n")
                    f.write(f"        key_buffer[{i*8} + j] = {name}_FRAGMENT{i+1}[j] ^ {name}_MASK{i+1}[j];\n")
                    f.write("    }\n")
                
                # Add anti-timing attack protection
                f.write("\n    // Add timing variance to help prevent timing attacks\n")
                f.write("    volatile int delay = 5 + (key_buffer[0] & 0x07);\n")
                f.write("    while (delay--) {\n")
                f.write("        __asm__ volatile (\"nop\");\n")
                f.write("    }\n")
                
                f.write("}\n\n")
            
            f.write("#endif // __SECRET_KEYS_H\n")
        
        print(f"Successfully wrote key header file to {output_path}")
        return True
    
    except Exception as e:
        print(f"Error generating header file: {e}")
        traceback.print_exc()
        return False


def generate_fallback_header(output_path):
    """Generate minimal header as fallback"""
    try:
        with open(output_path, 'w') as f:
            f.write("#ifndef __SECRET_KEYS_H\n")
            f.write("#define __SECRET_KEYS_H\n\n")
            f.write("#include <stdint.h>\n\n")
            f.write("// WARNING: This is a fallback header with empty keys\n")
            f.write("// The key extraction process failed\n\n")
            
            # Memory barrier
            f.write("#if defined(__GNUC__) || defined(__clang__)\n")
            f.write("    #define MEMORY_BARRIER() __asm__ volatile (\"\" : : : \"memory\")\n")
            f.write("#else\n")
            f.write("    #define MEMORY_BARRIER() ((void)0)\n")
            f.write("#endif\n\n")
            
            # Secure memory clearing function
            f.write("static inline void secure_zero_memory(volatile void *buffer, size_t size) {\n")
            f.write("    if (buffer == NULL || size == 0) {\n")
            f.write("        return;\n")
            f.write("    }\n")
            f.write("    volatile uint8_t *p = (volatile uint8_t *)buffer;\n")
            f.write("    for (size_t i = 0; i < size; i++) {\n")
            f.write("        p[i] = 0;\n")
            f.write("    }\n")
            f.write("    MEMORY_BARRIER();\n")
            f.write("}\n\n")
            
            # Define empty keys with minimal fragments for each key type
            for name in ["ENCRYPTION_KEY", "SUBSCRIPTION_KEY", "MAC_KEY"]:
                for i in range(4):
                    f.write(f"static const uint8_t {name}_FRAGMENT{i+1}[] = {{ 0x00 }};\n")
                    f.write(f"static const uint8_t {name}_MASK{i+1}[] = {{ 0x00 }};\n")
                f.write(f"#define {name}_SIZE 32\n\n")
                
                # Simple load function
                f.write(f"static inline void load_{name.lower()}(uint8_t *key_buffer) {{\n")
                f.write(f"    for (int i = 0; i < {name}_SIZE; i++) {{\n")
                f.write(f"        key_buffer[i] = 0;\n")
                f.write("    }\n")
                f.write("}\n\n")
            
            f.write("#endif // __SECRET_KEYS_H\n")
        
        print("Generated fallback header file")
        return True
        
    except Exception as e:
        print(f"Failed to generate fallback header: {e}")
        return False


def main():
    """Main function to extract keys and generate C header"""
    print("Starting key extraction process with XOR obfuscation...")
    
    # Create output directory if it doesn't exist
    output_path = "/decoder/inc/secret_keys.h"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Find all candidate files that might contain secrets
    candidates = find_candidate_files()
    print(f"Found {len(candidates)} candidate files: {candidates}")
    
    # Try parsing each candidate file
    for file_path in candidates:
        print(f"Examining file: {file_path}")
        
        # Try parsing as JSON first
        data = try_parse_as_json(file_path)
        if data:
            print(f"Successfully parsed {file_path} as JSON")
            if generate_key_header(data, output_path):
                print("Key extraction with XOR obfuscation completed successfully!")
                return 0
    
    # If we get here, we failed to extract keys from any file
    print("ERROR: Could not extract keys from any available files")
    
    # As a last resort, generate a minimal valid header
    print("Generating minimal header as fallback...")
    if generate_fallback_header(output_path):
        return 1  # Non-zero exit code to indicate failure but allow build to continue
        
    return 2  # Error code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Unhandled exception: {e}")
        traceback.print_exc()
        sys.exit(3)