/** @file user_settings.h
 *  @author Crypto Caballeros
 *  @brief Comprehensive side-channel resistant configuration for WolfSSL
 *  @date 2025
 */
#ifndef WOLFSSL_CONFIG_H
#define WOLFSSL_CONFIG_H

/* Core WolfSSL configuration */
#define SINGLE_THREADED     /* No threading support needed */
#define NO_FILESYSTEM
#define NO_WRITEV           /* Embedded system without writev() */
#define WOLFSSL_NO_CURRDIR  /* Don't use current directory */
#define TIME_T_NOT_64BIT    /* Use 32-bit time_t */

/* Optimization for embedded systems */
#define WOLFSSL_SMALL_STACK
#define SMALL_SESSION_CACHE
#define NO_SESSION_CACHE
#define WORD32_MASK 0xFFFFFFFF
#define WORD64_MASK 0xFFFFFFFFFFFFFFFF

/* Algorithm selection */
#define WOLFSSL_AES_DIRECT    /* Direct AES operations */
#define WOLFSSL_SHA256        /* Enables SHA 256 hash functions*/
#define NO_RC4                /* Disable unused algorithms */
#define NO_HC128
#define NO_RABBIT
#define NO_DSA
#define NO_MD4

/* Memory configuration */
#define WOLFSSL_NO_MALLOC        /* Don't use dynamic memory allocation */
#define WOLFSSL_STATIC_MEMORY    /* Use static memory buffers instead */

/* Side-channel resistance - timing protections */
#define TFM_TIMING_RESISTANT     /* Constant-time math operations */
#define ECC_TIMING_RESISTANT     /* Protect ECC operations */
#define WC_RSA_BLINDING          /* RSA blinding countermeasure */
#define HAVE_CONSTANT_TIME_IMPL  /* Use constant-time implementations */

/* Side-channel resistance - memory access protections */
#define WC_NO_CACHE_RESISTANT    /* Avoid cache-based attacks */
#define WC_NO_HARDEN            /* Disable hardware-specific optimizations that might leak */
#define TFM_NO_ASM              /* Avoid assembly optimizations that might have timing variations */

/* Specific algorithm hardening */
#define AES_COUNTER_ONLY         /* AES in counter mode only, which is more resistant */
#define GCM_TABLE_4BIT           /* Use smaller tables for AES-GCM to reduce cache footprint */

#endif /* WOLFSSL_CONFIG_H */