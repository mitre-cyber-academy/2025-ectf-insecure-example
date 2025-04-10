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


#ifndef ECTF_CRYPTO_HW_H
#define ECTF_CRYPTO_HW_H
 
#include <stdint.h>
#include <stddef.h>
 
/******************************** MACRO DEFINITIONS ********************************/
 #define BLOCK_SIZE 16
 #define KEY_SIZE 16
 #define HASH_SIZE 32  // SHA-256 produces a 32-byte hash
 #define HMAC_BLOCK_SIZE 64 // SHA-256 block size
 #define OPAD 0x5c
 #define IPAD 0x36
 
/******************************** FUNCTION PROTOTYPES ********************************/

/******************************************************************************************************
 *  @brief AES-256 Decryption function using wolfSSL
 * 
 *  @param ciphertext A pointer to a buffer of length ciphertext_len containing ciphertext from encoder
 *  @param ciphertext_len Legth of ciphertext
 *  @param key A pointer to a buffer containing the encryption key to be used in AES
 *  @param iv A pointer to a buffer containing the Initialization vector (IV) to be used in AES
 *  @param plaintext A pointer to a buffer containing the output of decryption, plaintext
 * 
 *  @return plaintext_len for error messages
 *******************************************************************************************************/
int aes_decrypt(uint8_t* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, uint8_t* plaintext);
 
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
int hash(void *data, size_t len, uint8_t *hash_out);

/******************************************************************************************************************
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
 *******************************************************************************************************************/
int compute_hmac(uint8_t *key, size_t key_len, uint8_t *message, size_t message_len, uint8_t *hmac_output);




#endif // ECTF_CRYPTO_HW_H
