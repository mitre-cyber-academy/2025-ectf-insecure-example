/** @file "simple_crypto.c"
*   @author Crypto Caballero
*   @brief Source file holding cryptographic efforts performed by FIU's 2025 eCTF team.
*   @date 2025
*
*/

#include <stdint.h>
#include <string.h>
#include "simple_crypto.h"
#include "host_messaging.h"
 
// MAX78000 Hardware includes
#include "aes.h"   // AES Hardware

// Using wolfSSL for SHA-256
#include "wolfssl/wolfcrypt/sha256.h"
 
// Global variables for crypto contexts
static int crypto_initialized = 0;
 
/** @brief Initialize the cryptographic hardware
*/
int crypto_init(void) {
    if (crypto_initialized) {
        return 0; // Already initialized
    }
    
    int result;
    
    // Initialize AES hardware
    result = MXC_AES_Init();
    if (result != E_NO_ERROR) {
        char debug_buf[64];
        sprintf(debug_buf, "AES initialization failed with code %d", result);
        print_debug(debug_buf);
        return -1;
    }
    
    // Initialize TRNG hardware
    result = MXC_TRNG_Init();
    if (result != E_NO_ERROR) {
        char debug_buf[64];
        sprintf(debug_buf, "TRNG initialization failed with code %d", result);
        print_debug(debug_buf);
        return -2;
    }
     
    crypto_initialized = 1;
    print_debug("Cryptographic hardware initialized successfully");
    return 0;
}

/**
 * @brief Decrypt data using AES-CBC mode
 * 
 * @param ciphertext Input ciphertext data
 * @param len Length of data (must be multiple of BLOCK_SIZE)
 * @param key Decryption key
 * @param iv Initialization vector (16 bytes)
 * @param plaintext Output buffer for plaintext
 * 
 * @return 0 on success, negative value on error
 */
int decrypt_sym_cbc(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *iv, uint8_t *plaintext) {
    char debug_buf[128];
    
    // Ensure crypto hardware is initialized
    if (!crypto_initialized) {
        int result = crypto_init();
        if (result != 0) {
            return result;
        }
    }
    
    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE != 0) {
        print_debug("Invalid length for decryption");
        return -1;
    }
    
    // Set up AES request structure for ECB mode
    mxc_aes_req_t aes_req;
    aes_req.keySize = MXC_AES_128BITS;  // Using AES-128
    
    // Copy key to AES key register
    MXC_AES_SetExtKey(key, aes_req.keySize);
    
    // Save the previous ciphertext block for XOR operation
    uint8_t prev_block[BLOCK_SIZE];
    memcpy(prev_block, iv, BLOCK_SIZE);  // Initialize with IV
    
    // Process each block in CBC mode
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        // Save current ciphertext block for next iteration
        uint8_t current_block[BLOCK_SIZE];
        memcpy(current_block, ciphertext + i, BLOCK_SIZE);
        
        // Decrypt the current block using hardware ECB
        aes_req.inputData = (uint32_t*)(ciphertext + i);
        aes_req.resultData = (uint32_t*)(plaintext + i);
        aes_req.length = BLOCK_SIZE;
        
        int result = MXC_AES_Decrypt(&aes_req);
        if (result != E_NO_ERROR) {
            sprintf(debug_buf, "AES decryption failed with code %d", result);
            print_debug(debug_buf);
            return -2;
        }
        
        // XOR with previous ciphertext block (or IV for first block)
        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            plaintext[i + j] ^= prev_block[j];
        }
        
        // Update previous block for next iteration
        memcpy(prev_block, current_block, BLOCK_SIZE);
    }
    
    return 0;
}
 
/** @brief Hash data using wolfSSL SHA-256
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    char debug_buf[128];
    
    // Ensure crypto hardware is initialized
    if (!crypto_initialized) {
        int result = crypto_init();
        if (result != 0) {
            return result;
        }
    }
     
    if (data == NULL) {
        print_debug("NULL data pointer passed to hash");
        return -1;
    }
     
    if (hash_out == NULL) {
        print_debug("NULL output pointer passed to hash");
        return -2;
    }

    if (len == 0) {
        print_debug("Zero length passed to hash - this may be valid but unusual");
    }
     
    // Use wolfSSL SHA-256
    wc_Sha256 sha;
    int result;
    
    result = wc_InitSha256(&sha);
    if (result != 0) {
        sprintf(debug_buf, "SHA-256 init failed with code %d", result);
        print_debug(debug_buf);
        return -3;
    }
    
    result = wc_Sha256Update(&sha, (const byte*)data, len);
    if (result != 0) {
        sprintf(debug_buf, "SHA-256 update failed with code %d", result);
        print_debug(debug_buf);
        return -4;
    }
    
    result = wc_Sha256Final(&sha, hash_out);
    if (result != 0) {
        sprintf(debug_buf, "SHA-256 final failed with code %d", result);
        print_debug(debug_buf);
        return -5;
    }
     
    return 0;
}

/** @brief Creates HMAC object using wolfSSL hash function
 * 
 *  @param key A pointer to a buffer of length key_len containing key for HMAC
 *  @param key_len The length of the key to be used for HMAC
 *  @param message A pointer to a buffer of length message_len containing message for HMAC
 *  @param message_len The length of message to be used for HMAC
 *  @param hmac_output The computed output of HMAC
 * 
 *  @return 0 if successful
 * 
 *  @note Standard HMAC implementation (H is the hash function, K is the key)
 *  HMAC(K,m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
 *  where K' is the key padded to block size and m is the message
 */
int compute_hmac(uint8_t *key, size_t key_len, uint8_t *message, size_t message_len, uint8_t *hmac_output) {
    uint8_t k_prime[HMAC_BLOCK_SIZE];
    uint8_t k_opad[HMAC_BLOCK_SIZE];
    uint8_t k_ipad[HMAC_BLOCK_SIZE];
    uint8_t inner_hash[HASH_SIZE];

    // Debug original inputs
    print_debug("HMAC Key (hex):");
    print_hex_debug(key, key_len);
    print_debug("HMAC Message (hex):");
    print_hex_debug(message, message_len);

    // Prepare the key
    memset(k_prime, 0, HMAC_BLOCK_SIZE); // Initialize buffer
    if (key_len > HMAC_BLOCK_SIZE) {     // if key > block size
        hash(key, key_len, k_prime);     // hash it
    } else {
        memcpy(k_prime, key, key_len);   // Copy into memory
    }

    print_debug("k_prime:");
    print_hex_debug(k_prime, key_len);

    // Prepare padded keys
    for (int i=0; i < HMAC_BLOCK_SIZE; i++) { // Pad with zeros if key < block size
        k_opad[i] = k_prime[i] ^ OPAD;
        k_ipad[i] = k_prime[i] ^ IPAD;
    }

    print_debug("K XOR ipad:");
    print_hex_debug(k_ipad, HMAC_BLOCK_SIZE);

    // Inner hash: H((K' ⊕ ipad) || m)
    uint8_t *inner_data = malloc(HMAC_BLOCK_SIZE + message_len);
    memcpy(inner_data, k_ipad, HMAC_BLOCK_SIZE);
    memcpy(inner_data + HMAC_BLOCK_SIZE, message, message_len);

    print_debug("Inner data (K' ⊕ ipad || message):");
    print_hex_debug(inner_data, HMAC_BLOCK_SIZE + message_len);

    hash(inner_data, HMAC_BLOCK_SIZE + message_len, inner_hash);
    free(inner_data);

    print_debug("inner_hash:");
    print_hex_debug(inner_hash, HASH_SIZE);

    print_debug("K XOR opad:");
    print_hex_debug(k_opad, HMAC_BLOCK_SIZE);

    // Outer hash: H((K' ⊕ opad) || inner_hash)
    uint8_t *outer_data = malloc(HMAC_BLOCK_SIZE + HASH_SIZE);
    memcpy(outer_data, k_opad, HMAC_BLOCK_SIZE);
    memcpy(outer_data + HMAC_BLOCK_SIZE, inner_hash, HASH_SIZE);

    print_debug("Outer data (K' ⊕ opad || inner_hash):");
    print_hex_debug(outer_data, HMAC_BLOCK_SIZE + HASH_SIZE);

    hash(outer_data, HMAC_BLOCK_SIZE + HASH_SIZE, hmac_output);
    free(outer_data);

    print_debug("hmac_output:");
    print_hex_debug(hmac_output, HASH_SIZE);

    return 0;
}