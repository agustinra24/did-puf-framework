/*
 * ML-DSA configuration for ESP32 (Xtensa LX6)
 *
 * Custom config file for mldsa-native, used via MLD_CONFIG_FILE.
 * Targets ML-DSA-87 (NIST Level 5) on ESP32-WROOM-32D.
 *
 * Security notes:
 * - Uses the standard (non-REDUCE_RAM) config, covered by upstream
 *   CBMC formal proofs and valgrind constant-time verification.
 * - Internal buffers redirected to heap via CUSTOM_ALLOC because
 *   ML-DSA-87 needs ~100KB stack, but main task only has 12KB.
 * - RNG backed by ESP32 hardware TRNG (requires RF subsystem active).
 *
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef MLDSA_CONFIG_ESP32_H
#define MLDSA_CONFIG_ESP32_H

/* ML-DSA-87 (NIST Level 5, 256-bit post-quantum security) */
#ifndef MLD_CONFIG_PARAMETER_SET
#define MLD_CONFIG_PARAMETER_SET 87
#endif

/* Namespace prefix for symbols */
#define MLD_CONFIG_NAMESPACE_PREFIX mldsa_esp32

/* NOTE: MLD_CONFIG_REDUCE_RAM is intentionally NOT defined.
 * While it saves ~30KB of heap, it is marked experimental in upstream
 * and is NOT covered by CBMC formal verification proofs. Using the
 * standard config ensures memory safety and type safety guarantees
 * from upstream's CI. ESP32 has ~254KB free heap; the extra ~30KB
 * of temporary allocation during keygen is acceptable. */

/* Redirect large internal buffers to heap instead of stack.
 * Without this, ML-DSA-87 keygen needs ~100KB of stack,
 * but the main task only has 12KB.
 * heap_caps_malloc provides 4-byte alignment (not 32-byte like the
 * default aligned_alloc example). Safe because ESP32 uses only the
 * portable scalar C backend (no SIMD alignment requirements). */
#define MLD_CONFIG_CUSTOM_ALLOC_FREE
#if !defined(__ASSEMBLER__)
#include <stdlib.h>
#include "esp_heap_caps.h"
#define MLD_CUSTOM_ALLOC(v, T, N) \
    T* (v) = (T *)heap_caps_malloc(sizeof(T) * (N), MALLOC_CAP_8BIT)
#define MLD_CUSTOM_FREE(v, T, N) free(v)
#endif

/* Use custom randombytes backed by ESP-IDF's hardware TRNG.
 * esp_fill_random() produces cryptographically secure output when
 * the RF subsystem (WiFi or BT) is active, which is always the case
 * during enrollment (WiFi must be connected to reach the server).
 * When RF is off, output degrades to PRNG; never call keygen/sign
 * without WiFi enabled. */
#define MLD_CONFIG_CUSTOM_RANDOMBYTES
#if !defined(__ASSEMBLER__)
#include <stdint.h>
#include <stddef.h>
#include "esp_random.h"

static inline int mld_randombytes(uint8_t *ptr, size_t len)
{
    esp_fill_random(ptr, len);
    return 0;
}
#endif

#endif /* MLDSA_CONFIG_ESP32_H */
