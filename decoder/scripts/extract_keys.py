#!/usr/bin/env python3
"""
Author: Crypto Caballeros
Date: 2025

Extract cryptographic keys from the secrets file and generate a C header file, 
to be used in decoder processes.
This script is intended to be run during the Docker build process.
"""
import json
import os
import sys

# Path to the secrets file mounted in the Docker container
SECRETS_FILE = "/secrets/secrets.json"
# Output header file path
OUTPUT_HEADER = "/decoder/inc/secret_keys.h"

def main():
    try:
        # Get device ID from environment variable
        device_id_hex = os.environ.get('DECODER_ID', '0x0')
        device_id = int(device_id_hex, 16)
        print(f"Using device ID: {device_id_hex}")
        
        # Read and parse the secrets JSON file
        print(f"Reading secrets from {SECRETS_FILE}")
        with open(SECRETS_FILE, 'r') as f:
            secrets_data = json.load(f)
        
        # Extract the subscription key
        subscription_key_hex = secrets_data.get('subscription_Key')
        if not subscription_key_hex:
            print(f"Error: Could not find 'subscription_Key' in {SECRETS_FILE}")
            print(f"Available keys: {list(secrets_data.keys())}")
            return 1
        
        # Extract encryption key
        encryption_key_hex = secrets_data.get('encryption_Key')
        if not encryption_key_hex:
            print(f"Error: Could not find 'encryption_key' in {SECRETS_FILE}")
            return 1

        # Extract MAC key
        mac_key_hex = secrets_data.get('MAC_Key')
        if not mac_key_hex:
            print(f"Error: Could not find 'MAC_key' in {SECRETS_FILE}")

        print(f"Successfully extracted keys: sub-{subscription_key_hex[:8]}..., enc-{encryption_key_hex[:8]}..., MAC-{mac_key_hex[:8]}...")
        
        # Convert hex string to bytes
        subscription_key = bytes.fromhex(subscription_key_hex)
        encryption_key = bytes.fromhex(encryption_key_hex)
        mac_key = bytes.fromhex(mac_key_hex)
        
        # Generate the header file
        with open(OUTPUT_HEADER, 'w') as f:
            # File header with documentation
            f.write("/**\n")
            f.write(" * @file secret_keys.h\n")
            f.write(" * @author Crypto Caballeros\n")
            f.write(" * @brief File containing cryptographic keys\n")
            f.write(" * @Date 2025\n")
            f.write(" */\n\n")
            
            # Include guards
            f.write("#ifndef __SECRET_KEYS_H\n")
            f.write("#define __SECRET_KEYS_H\n\n")
            
            # Required includes
            f.write("#include <stdint.h>\n\n")

            f.write("/****************************** Define Keys *******************************/\n\n")
            
            # Define the subscription key as a byte array
            f.write("/**\n")
            f.write(" * Subscription key extracted from secrets.json\n")
            f.write(" */\n")
            f.write("static const uint8_t SUBSCRIPTION_KEY[] = {\n    ")
            
            # Format the bytes into rows of 8 for readability
            bytes_str = []
            for i, b in enumerate(subscription_key):
                if i > 0 and i % 8 == 0:
                    bytes_str.append("\n    ")
                bytes_str.append(f"0x{b:02x}")
                if i < len(subscription_key) - 1:
                    bytes_str.append(", ")
            
            f.write("".join(bytes_str))
            f.write("\n};\n\n")

            # Define Encryption key as a byte array
            f.write("/**\n")
            f.write(" * Encryption key extracted from secrets.json\n")
            f.write(" */\n")
            f.write("static const uint8_t ENCRYPTION_KEY[] = {\n    ")

            # Format the bytes into rows of 8 for readability
            bytes_str = []
            for i, b in enumerate(encryption_key):
                if i > 0 and i % 8 == 0:
                    bytes_str.append("\n    ")
                bytes_str.append(f"0x{b:02x}")
                if i < len(encryption_key) - 1:
                    bytes_str.append(", ")
            
            f.write("".join(bytes_str))
            f.write("\n};\n\n")

            
            # Define MAC key as a byte array
            f.write("/**\n")
            f.write(" * MAC key extracted from secrets.json\n")
            f.write(" */\n")
            f.write("static const uint8_t MAC_KEY[] = {\n    ")

            # Format the bytes into rows of 8 for readability
            bytes_str = []
            for i, b in enumerate(mac_key):
                if i > 0 and i % 8 == 0:
                    bytes_str.append("\n    ")
                bytes_str.append(f"0x{b:02x}")
                if i < len(mac_key) - 1:
                    bytes_str.append(", ")
            
            f.write("".join(bytes_str))
            f.write("\n};\n\n")


            f.write("/***************************** Define Key Sizes *****************************/\n\n")
            
            # Define the key size constants
            f.write("#define SUBSCRIPTION_KEY_SIZE (sizeof(SUBSCRIPTION_KEY))\n\n")
            f.write("#define ENCRYPTION_KEY_SIZE (sizeof(ENCRYPTION_KEY))\n\n")
            f.write("#define MAC_KEY_SIZE (sizeof(MAC_KEY))\n\n")
            
            
            f.write("/*************************** Extraction Functions ****************************/\n\n")


            # Add the load_subscription_key function for convenience
            f.write("/** @brief Loads the entire subscription key into a buffer\n")
            f.write(" * \n")
            f.write(" * @param key_buffer Buffer to receive the key (must be at least SUBSCRIPTION_KEY_SIZE bytes)\n")
            f.write(" */\n")
            f.write("static inline void load_subscription_key(uint8_t *key_buffer) {\n")
            f.write("    for (int i = 0; i < SUBSCRIPTION_KEY_SIZE; i++) {\n")
            f.write("        key_buffer[i] = SUBSCRIPTION_KEY[i];\n")
            f.write("    }\n")
            f.write("}\n\n")

            f.write("/** @brief Loads the entire encryption key into a buffer\n")
            f.write(" * \n")
            f.write(" * @param key_buffer Buffer to receive the key (must be at least ENCRYPTION_KEY_SIZE bytes)\n")
            f.write(" */\n")
            f.write("static inline void load_encryption_key(uint8_t *key_buffer) {\n")
            f.write("    for (int i = 0; i < ENCRYPTION_KEY_SIZE; i++) {\n")
            f.write("        key_buffer[i] = ENCRYPTION_KEY[i];\n")
            f.write("    }\n")
            f.write("}\n\n")

            f.write("/** @brief Loads the entire MAC key into a buffer\n")
            f.write(" * \n")
            f.write(" * @param key_buffer Buffer to receive the key (must be at least MAC_KEY_SIZE bytes)\n")
            f.write(" */\n")
            f.write("static inline void load_MAC_key(uint8_t *key_buffer) {\n")
            f.write("    for (int i = 0; i < MAC_KEY_SIZE; i++) {\n")
            f.write("        key_buffer[i] = MAC_KEY[i];\n")
            f.write("    }\n")
            f.write("}\n\n")
            
            f.write("/*************************** Deletion Functions ****************************/\n\n")

            # A utility function for securely clearing sensitive data
            f.write("/** @brief Securely clears a memory buffer (e.g., after using a key)\n")
            f.write(" * \n")
            f.write(" * @param buffer The buffer to clear\n")
            f.write(" * @param size The size of the buffer in bytes\n")
            f.write(" */\n")
            f.write("static inline void secure_clear(volatile uint8_t *buffer, size_t size) {\n")
            f.write("    // Prevent compiler optomization\n")
            f.write("    if (buffer == NULL || size == 0) {\n")
            f.write("        return;\n")
            f.write("    }\n")
            f.write("\n")
            f.write("    // Multiple pass overwrite with different patterns\n")
            f.write("    volatile uint8_t *p;\n")
            f.write("\n")
            f.write("    // First pass: 0xFF\n")
            f.write("    p = buffer;\n")
            f.write("    for (size_t i = 0; i < size; i++) {\n")
            f.write("        *p++ = 0xFF;\n")
            f.write("    }\n")
            f.write("\n")
            f.write("    // Memory barrier to prevent reordering\n")
            f.write("    __asm__ volatile (\"\" : : : \"memory\");\n")
            f.write("\n")
            f.write("    // Second pass: 0x00\n")
            f.write("    p = buffer;\n")
            f.write("    for (size_t i = 0; i < size; i++) {\n")
            f.write("        *p++ = 0x00;\n")
            f.write("    }\n")
            f.write("\n")
            f.write("    // Final memory barrier\n")
            f.write("    __asm__ volatile (\"\" : : : \"memory\");\n")
            f.write("}\n\n")
            
            # Close the include guard
            f.write("#endif // __SECRET_KEYS_H\n")
        
        print(f"Successfully generated {OUTPUT_HEADER}")
        return 0
    
    except FileNotFoundError:
        print(f"Error: Could not find secrets file at {SECRETS_FILE}")
        print(f"Current directory: {os.getcwd()}")
        if os.path.exists("/secrets"):
            print(f"Contents of /secrets directory: {os.listdir('/secrets')}")
        return 1
    
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in secrets file: {e}")
        # Try to print the problematic content
        try:
            with open(SECRETS_FILE, 'r') as f:
                content = f.read()
                print(f"File content (first 100 chars): {repr(content[:100])}")
        except:
            print("Could not read file contents for debugging")
        return 1
    
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())