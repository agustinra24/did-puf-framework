/*
 * ML-DSA (FIPS 204) wrapper for ESP32
 *
 * Thin wrapper over mldsa-native providing ML-DSA-87 digital signatures
 * for the DID-PUF framework. First documented ESP32 port of mldsa-native.
 *
 * Key sizes (ML-DSA-87):
 *   Public key:  2592 bytes
 *   Secret key:  4896 bytes
 *   Signature:   4627 bytes
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef ML_DSA_H
#define ML_DSA_H

#include <stdint.h>
#include <stddef.h>

/* Pull in the mldsa-native public API (configured for ML-DSA-87) */
#include "mldsa_native.h"

/* Re-export key size constants with framework-friendly names */
#define ML_DSA_PK_BYTES   MLDSA87_PUBLICKEYBYTES   /* 2592 */
#define ML_DSA_SK_BYTES   MLDSA87_SECRETKEYBYTES   /* 4896 */
#define ML_DSA_SIG_BYTES  MLDSA87_BYTES            /* 4627 */
#define ML_DSA_SEED_BYTES MLDSA_SEEDBYTES          /* 32   */

/*
 * Generate an ML-DSA-87 keypair.
 *
 * pk: output public key  (ML_DSA_PK_BYTES)
 * sk: output secret key  (ML_DSA_SK_BYTES)
 *
 * Returns 0 on success, negative on error.
 */
static inline int ml_dsa_keygen(uint8_t *pk, uint8_t *sk)
{
    return crypto_sign_keypair(pk, sk);
}

/*
 * Sign a message with ML-DSA-87.
 *
 * sig:     output signature buffer  (ML_DSA_SIG_BYTES)
 * siglen:  output actual signature length
 * msg:     message to sign
 * msglen:  message length
 * ctx:     context string (for domain separation, may be NULL if ctxlen==0)
 * ctxlen:  context string length (max 255)
 * sk:      secret key (ML_DSA_SK_BYTES)
 *
 * Returns 0 on success, negative on error.
 */
static inline int ml_dsa_sign(uint8_t *sig, size_t *siglen,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *ctx, size_t ctxlen,
                              const uint8_t *sk)
{
    return crypto_sign_signature(sig, siglen, msg, msglen, ctx, ctxlen, sk);
}

/*
 * Verify an ML-DSA-87 signature.
 *
 * sig:     signature to verify
 * siglen:  signature length
 * msg:     original message
 * msglen:  message length
 * ctx:     context string (must match what was used for signing)
 * ctxlen:  context string length
 * pk:      public key (ML_DSA_PK_BYTES)
 *
 * Returns 0 if valid, negative on failure.
 */
static inline int ml_dsa_verify(const uint8_t *sig, size_t siglen,
                                const uint8_t *msg, size_t msglen,
                                const uint8_t *ctx, size_t ctxlen,
                                const uint8_t *pk)
{
    return crypto_sign_verify(sig, siglen, msg, msglen, ctx, ctxlen, pk);
}

#endif /* ML_DSA_H */
