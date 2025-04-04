// aegis_core.h - Core header file for Aegis prototype

#ifndef AEGIS_CORE_H
#define AEGIS_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define AEGIS_SUCCESS 0
#define AEGIS_ERROR_INVALID_PARAM -1
#define AEGIS_ERROR_BAD_ALLOC -2
#define AEGIS_ERROR_INSUFFICIENT_BUF -3
#define AEGIS_ERROR_VERIFICATION -4
#define AEGIS_ERROR_INTERNAL -5

// Function prototypes

/**
 * @brief Initialize the Aegis library
 */
int aegis_init(void);

/**
 * @brief Clean up and release resources
 */
int aegis_cleanup(void);

/**
 * @brief Generate a Kyber key pair
 */
int aegis_kyber_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk,
                       size_t *sk_len);

/**
 * @brief Encapsulate a shared secret using Kyber
 */
int aegis_kyber_encaps(uint8_t *ct, size_t *ct_len, uint8_t *ss, size_t *ss_len,
                       const uint8_t *pk, size_t pk_len);

/**
 * @brief Decapsulate a shared secret using Kyber
 */
int aegis_kyber_decaps(uint8_t *ss, size_t *ss_len, const uint8_t *ct,
                       size_t ct_len, const uint8_t *sk, size_t sk_len);

/**
 * @brief Generate a SPHINCS+ key pair
 */
int aegis_sphincs_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk,
                         size_t *sk_len);

/**
 * @brief Sign a message using SPHINCS+
 */
int aegis_sphincs_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                       size_t msg_len, const uint8_t *sk, size_t sk_len);

/**
 * @brief Verify a SPHINCS+ signature
 */
int aegis_sphincs_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg,
                         size_t msg_len, const uint8_t *pk, size_t pk_len);

/**
 * @brief Encrypt and sign a message
 */
int aegis_encrypt_and_sign(uint8_t *ciphertext, size_t *ciphertext_len,
                           uint8_t *encaps_ct, size_t *encaps_ct_len,
                           uint8_t *signature, size_t *signature_len,
                           const uint8_t *message, size_t message_len,
                           const uint8_t *recipient_kyber_pk,
                           size_t recipient_kyber_pk_len,
                           const uint8_t *sender_sphincs_sk,
                           size_t sender_sphincs_sk_len);

/**
 * @brief Verify and decrypt a message
 */
int aegis_verify_and_decrypt(uint8_t *message, size_t *message_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t *encaps_ct, size_t encaps_ct_len,
                             const uint8_t *signature, size_t signature_len,
                             const uint8_t *recipient_kyber_sk,
                             size_t recipient_kyber_sk_len,
                             const uint8_t *sender_sphincs_pk,
                             size_t sender_sphincs_pk_len);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_CORE_H */
