/*****FIU MITRE eCTF 2025********************************************
*                                                                  *
*    simple_crypto.c                                               *
*                                                                  *
*   Author: Crypto Caballeros                                      *
*   Date: 2025                                                     *
*   Description: Source file holding cryptographic efforts         *
*        preformed by FIU's 2025 eCTF team                         *
*                                                                  *
*******************************************************************/



/****************************INCLUDES*****************************/

#include <stdint.h>
#include <string.h>
#include "simple_crypto.h"
#include "host_messaging.h"
#include "secret_keys.h"
// Using wolfSSL for SHA-256 & AES
#include "wolfssl/wolfcrypt/sha256.h"
#include <wolfssl/wolfcrypt/aes.h>
#include "trng.h"

/***********************************************************************************************************
 @brief AES Decryption function using wolfSSL
 
  @param ciphertext A pointer to a buffer of length ciphertext_len containing ciphertext from encoder
  @param ciphertext_len Legth of ciphertext
  @param key A pointer to a buffer containing the encryption key to be used in AES
  @param iv A pointer to a buffer containing the Initialization vector (IV) to be used in AES
  @param plaintext A pointer to a buffer containing the output of decryption, plaintext
 
  @return plaintext_len for error messages
 ************************************************************************************************************/
int aes_decrypt(uint8_t* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, uint8_t* plaintext) {
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return -1;

    ret = wc_AesSetKey(&aes, key, ENCRYPTION_KEY_SIZE, iv, AES_DECRYPTION);
    if (ret != 0) return -1;

    ret = wc_AesCbcDecrypt(&aes, plaintext, ciphertext, ciphertext_len);
    if (ret != 0) return -1;

    // Remove padding
    int plaintext_len = ciphertext_len;
    while (plaintext_len > 0 && plaintext[plaintext_len-1] == 0) {
    plaintext_len--;
    }

    wc_AesFree(&aes);
    return plaintext_len;
}
 
/*******************************************************************************************************
 *  @brief Hashes arbitrary-length data using wolfSSL SHA-256
 *
 *  @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 *  @param len The length of the data to hash
 *  @param hash_out A pointer to a buffer of length HASH_SIZE (32 bytes) where the resulting
 *           hash output will be written to
 *
 *  @return 0 on success, non-zero for other error
 *******************************************************************************************************/
int hash(void *data, size_t len, uint8_t *hash_out) {
    char debug_buf[128];
    
    // Check that inputs are valid
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

/*******************************************************************************************************
 *  @brief Creates HMAC object using wolfSSL hash function
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
 ********************************************************************************************************/
int compute_hmac(uint8_t *key, size_t key_len, uint8_t *message, size_t message_len, uint8_t *hmac_output) {
    uint8_t k_prime[HMAC_BLOCK_SIZE];
    uint8_t k_opad[HMAC_BLOCK_SIZE];
    uint8_t k_ipad[HMAC_BLOCK_SIZE];
    uint8_t inner_hash[HASH_SIZE];

    // Prepare the key
    memset(k_prime, 0, HMAC_BLOCK_SIZE); // Initialize buffer
    if (key_len > HMAC_BLOCK_SIZE) {     // if key > block size
        hash(key, key_len, k_prime);     // hash it
    } else {
        memcpy(k_prime, key, key_len);   // Copy into memory
    }


    // Prepare padded keys
    for (int i=0; i < HMAC_BLOCK_SIZE; i++) { // Pad with zeros if key < block size
        k_opad[i] = k_prime[i] ^ OPAD;
        k_ipad[i] = k_prime[i] ^ IPAD;
    }

    // Inner hash: H((K' ⊕ ipad) || m)
    uint8_t *inner_data = malloc(HMAC_BLOCK_SIZE + message_len);
    if (inner_data == NULL) {
        print_debug("Memory allocation failed in compute_hmac");
        return -1;
    }
    memcpy(inner_data, k_ipad, HMAC_BLOCK_SIZE);
    memcpy(inner_data + HMAC_BLOCK_SIZE, message, message_len);
    hash(inner_data, HMAC_BLOCK_SIZE + message_len, inner_hash);
    free(inner_data);

    // Outer hash: H((K' ⊕ opad) || inner_hash)
    uint8_t *outer_data = malloc(HMAC_BLOCK_SIZE + HASH_SIZE);
    if (outer_data == NULL) {
        print_debug("Memory allocation failed in compute_hmac");
        return -1;
    }
    memcpy(outer_data, k_opad, HMAC_BLOCK_SIZE);
    memcpy(outer_data + HMAC_BLOCK_SIZE, inner_hash, HASH_SIZE);
    hash(outer_data, HMAC_BLOCK_SIZE + HASH_SIZE, hmac_output);
    free(outer_data);

    return 0;
}