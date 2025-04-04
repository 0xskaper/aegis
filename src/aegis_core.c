// aegis_core.c - Core implementation for Aegis prototype

#include "aegis_core.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <oqs/oqs.h> // Open Quantum Safe library
#include <stdlib.h>
#include <string.h>

// Internal state
static int aegis_initialized = 0;
static OQS_KEM *kyber = NULL;
static OQS_SIG *sphincs = NULL;

// Initialize the library
int aegis_init(void) {
  if (aegis_initialized) {
    return AEGIS_SUCCESS;
  }

  // Initialize OpenSSL
  OpenSSL_add_all_algorithms();

  // Initialize OQS and get algorithm instances
  kyber = OQS_KEM_new(OQS_KEM_alg_kyber_768);
  if (kyber == NULL) {
    return AEGIS_ERROR_INTERNAL;
  }

  sphincs = OQS_SIG_new(OQS_SIG_alg_sphincs_shake256_128f_simple);
  if (sphincs == NULL) {
    OQS_KEM_free(kyber);
    kyber = NULL;
    return AEGIS_ERROR_INTERNAL;
  }

  aegis_initialized = 1;
  return AEGIS_SUCCESS;
}

// Clean up resources
int aegis_cleanup(void) {
  if (!aegis_initialized) {
    return AEGIS_SUCCESS;
  }

  if (kyber != NULL) {
    OQS_KEM_free(kyber);
    kyber = NULL;
  }

  if (sphincs != NULL) {
    OQS_SIG_free(sphincs);
    sphincs = NULL;
  }

  // Clean up OpenSSL
  EVP_cleanup();

  aegis_initialized = 0;
  return AEGIS_SUCCESS;
}

// Generate a Kyber key pair
int aegis_kyber_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk,
                       size_t *sk_len) {
  if (!aegis_initialized) {
    return AEGIS_ERROR_INTERNAL;
  }

  if (pk == NULL || pk_len == NULL || sk == NULL || sk_len == NULL) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (*pk_len < kyber->length_public_key ||
      *sk_len < kyber->length_secret_key) {
    *pk_len = kyber->length_public_key;
    *sk_len = kyber->length_secret_key;
    return AEGIS_ERROR_INSUFFICIENT_BUF;
  }

  OQS_STATUS result = OQS_KEM_keypair(kyber, pk, sk);
  if (result != OQS_SUCCESS) {
    return AEGIS_ERROR_INTERNAL;
  }

  *pk_len = kyber->length_public_key;
  *sk_len = kyber->length_secret_key;

  return AEGIS_SUCCESS;
}

// Encapsulate a shared secret using Kyber
int aegis_kyber_encaps(uint8_t *ct, size_t *ct_len, uint8_t *ss, size_t *ss_len,
                       const uint8_t *pk, size_t pk_len) {
  if (!aegis_initialized) {
    return AEGIS_ERROR_INTERNAL;
  }

  if (ct == NULL || ct_len == NULL || ss == NULL || ss_len == NULL ||
      pk == NULL) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (pk_len != kyber->length_public_key) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (*ct_len < kyber->length_ciphertext ||
      *ss_len < kyber->length_shared_secret) {
    *ct_len = kyber->length_ciphertext;
    *ss_len = kyber->length_shared_secret;
    return AEGIS_ERROR_INSUFFICIENT_BUF;
  }

  OQS_STATUS result = OQS_KEM_encaps(kyber, ct, ss, pk);
  if (result != OQS_SUCCESS) {
    return AEGIS_ERROR_INTERNAL;
  }

  *ct_len = kyber->length_ciphertext;
  *ss_len = kyber->length_shared_secret;

  return AEGIS_SUCCESS;
}

// Decapsulate a shared secret using Kyber
int aegis_kyber_decaps(uint8_t *ss, size_t *ss_len, const uint8_t *ct,
                       size_t ct_len, const uint8_t *sk, size_t sk_len) {
  if (!aegis_initialized) {
    return AEGIS_ERROR_INTERNAL;
  }

  if (ss == NULL || ss_len == NULL || ct == NULL || sk == NULL) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (ct_len != kyber->length_ciphertext ||
      sk_len != kyber->length_secret_key) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (*ss_len < kyber->length_shared_secret) {
    *ss_len = kyber->length_shared_secret;
    return AEGIS_ERROR_INSUFFICIENT_BUF;
  }

  OQS_STATUS result = OQS_KEM_decaps(kyber, ss, ct, sk);
  if (result != OQS_SUCCESS) {
    return AEGIS_ERROR_INTERNAL;
  }

  *ss_len = kyber->length_shared_secret;

  return AEGIS_SUCCESS;
}

// Generate a SPHINCS+ key pair
int aegis_sphincs_keygen(uint8_t *pk, size_t *pk_len, uint8_t *sk,
                         size_t *sk_len) {
  if (!aegis_initialized) {
    return AEGIS_ERROR_INTERNAL;
  }

  if (pk == NULL || pk_len == NULL || sk == NULL || sk_len == NULL) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (*pk_len < sphincs->length_public_key ||
      *sk_len < sphincs->length_secret_key) {
    *pk_len = sphincs->length_public_key;
    *sk_len = sphincs->length_secret_key;
    return AEGIS_ERROR_INSUFFICIENT_BUF;
  }

  OQS_STATUS result = OQS_SIG_keypair(sphincs, pk, sk);
  if (result != OQS_SUCCESS) {
    return AEGIS_ERROR_INTERNAL;
  }

  *pk_len = sphincs->length_public_key;
  *sk_len = sphincs->length_secret_key;

  return AEGIS_SUCCESS;
}

// Sign a message using SPHINCS+
int aegis_sphincs_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
                       size_t msg_len, const uint8_t *sk, size_t sk_len) {
  if (!aegis_initialized) {
    return AEGIS_ERROR_INTERNAL;
  }

  if (sig == NULL || sig_len == NULL || msg == NULL || sk == NULL) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (sk_len != sphincs->length_secret_key) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (*sig_len < sphincs->length_signature) {
    *sig_len = sphincs->length_signature;
    return AEGIS_ERROR_INSUFFICIENT_BUF;
  }

  size_t signature_len = *sig_len;
  OQS_STATUS result =
      OQS_SIG_sign(sphincs, sig, &signature_len, msg, msg_len, sk);
  if (result != OQS_SUCCESS) {
    return AEGIS_ERROR_INTERNAL;
  }

  *sig_len = signature_len;

  return AEGIS_SUCCESS;
}

// Verify a SPHINCS+ signature
int aegis_sphincs_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg,
                         size_t msg_len, const uint8_t *pk, size_t pk_len) {
  if (!aegis_initialized) {
    return AEGIS_ERROR_INTERNAL;
  }

  if (sig == NULL || msg == NULL || pk == NULL) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  if (pk_len != sphincs->length_public_key) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  OQS_STATUS result = OQS_SIG_verify(sphincs, msg, msg_len, sig, sig_len, pk);
  if (result != OQS_SUCCESS) {
    return AEGIS_ERROR_VERIFICATION;
  }

  return AEGIS_SUCCESS;
}

// Helper function for symmetric encryption with AES-GCM
static int encrypt_aes_gcm(const uint8_t *plaintext, size_t plaintext_len,
                           const uint8_t *key, size_t key_len,
                           uint8_t *ciphertext, size_t *ciphertext_len) {
  EVP_CIPHER_CTX *ctx;
  int len, ciphertext_len_int;
  uint8_t iv[12];  // 96-bit IV for AES-GCM
  uint8_t tag[16]; // 128-bit tag

  // Generate random IV
  if (RAND_bytes(iv, sizeof(iv)) != 1) {
    return AEGIS_ERROR_INTERNAL;
  }

  // Create and initialize context
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return AEGIS_ERROR_INTERNAL;
  }

  // Initialize encryption operation
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }

  // Set IV length (default is 12 bytes for GCM)
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }

  // Initialize key and IV
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }

  // Check output buffer size
  size_t required_len = plaintext_len + sizeof(iv) + sizeof(tag);
  if (*ciphertext_len < required_len) {
    *ciphertext_len = required_len;
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INSUFFICIENT_BUF;
  }

  // Copy IV to output buffer
  memcpy(ciphertext, iv, sizeof(iv));

  // Encrypt plaintext
  if (EVP_EncryptUpdate(ctx, ciphertext + sizeof(iv), &len, plaintext,
                        plaintext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }
  ciphertext_len_int = len;

  // Finalize encryption
  if (EVP_EncryptFinal_ex(ctx, ciphertext + sizeof(iv) + ciphertext_len_int,
                          &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }
  ciphertext_len_int += len;

  // Get the tag
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }

  // Copy tag to output buffer
  memcpy(ciphertext + sizeof(iv) + ciphertext_len_int, tag, sizeof(tag));

  // Set the final ciphertext length
  *ciphertext_len = sizeof(iv) + ciphertext_len_int + sizeof(tag);

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return AEGIS_SUCCESS;
}

// Helper function for symmetric decryption with AES-GCM
static int decrypt_aes_gcm(const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t *key, size_t key_len,
                           uint8_t *plaintext, size_t *plaintext_len) {
  EVP_CIPHER_CTX *ctx;
  int len, plaintext_len_int;
  const uint8_t *iv = ciphertext;
  const uint8_t *encrypted_data = ciphertext + 12;       // After IV
  const uint8_t *tag = ciphertext + ciphertext_len - 16; // Last 16 bytes
  size_t encrypted_data_len =
      ciphertext_len - 12 - 16; // Subtract IV and tag lengths

  // Check for minimum valid ciphertext length
  if (ciphertext_len < 12 + 16) { // IV + tag
    return AEGIS_ERROR_INVALID_PARAM;
  }

  // Check output buffer size
  if (*plaintext_len < encrypted_data_len) {
    *plaintext_len = encrypted_data_len;
    return AEGIS_ERROR_INSUFFICIENT_BUF;
  }

  // Create and initialize context
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    return AEGIS_ERROR_INTERNAL;
  }

  // Initialize decryption operation
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }

  // Set IV length
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }

  // Initialize key and IV
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }

  // Decrypt
  if (EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data,
                        encrypted_data_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }
  plaintext_len_int = len;

  // Set expected tag value
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return AEGIS_ERROR_INTERNAL;
  }

  // Finalize decryption - verify tag
  int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  if (ret <= 0) {
    // Verification failed
    return AEGIS_ERROR_VERIFICATION;
  }

  // Set output length
  *plaintext_len = plaintext_len_int + len;

  return AEGIS_SUCCESS;
}

// Encrypt and sign a message
int aegis_encrypt_and_sign(uint8_t *ciphertext, size_t *ciphertext_len,
                           uint8_t *encaps_ct, size_t *encaps_ct_len,
                           uint8_t *signature, size_t *signature_len,
                           const uint8_t *message, size_t message_len,
                           const uint8_t *recipient_kyber_pk,
                           size_t recipient_kyber_pk_len,
                           const uint8_t *sender_sphincs_sk,
                           size_t sender_sphincs_sk_len) {
  if (!aegis_initialized) {
    return AEGIS_ERROR_INTERNAL;
  }

  if (ciphertext == NULL || ciphertext_len == NULL || encaps_ct == NULL ||
      encaps_ct_len == NULL || signature == NULL || signature_len == NULL ||
      message == NULL || recipient_kyber_pk == NULL ||
      sender_sphincs_sk == NULL) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  // Kyber encapsulation to generate shared secret
  uint8_t shared_secret[OQS_KEM_kyber_768_length_shared_secret];
  size_t shared_secret_len = sizeof(shared_secret);
  size_t kyber_ct_len = kyber->length_ciphertext;

  if (*encaps_ct_len < kyber_ct_len) {
    *encaps_ct_len = kyber_ct_len;
    return AEGIS_ERROR_INSUFFICIENT_BUF;
  }

  int ret = aegis_kyber_encaps(encaps_ct, encaps_ct_len, shared_secret,
                               &shared_secret_len, recipient_kyber_pk,
                               recipient_kyber_pk_len);

  if (ret != AEGIS_SUCCESS) {
    return ret;
  }

  // Encrypt message with shared secret using AES-GCM
  ret = encrypt_aes_gcm(message, message_len, shared_secret, shared_secret_len,
                        ciphertext, ciphertext_len);

  if (ret != AEGIS_SUCCESS) {
    return ret;
  }

  // Sign the encrypted message
  ret =
      aegis_sphincs_sign(signature, signature_len, ciphertext, *ciphertext_len,
                         sender_sphincs_sk, sender_sphincs_sk_len);

  return ret;
}

// Verify and decrypt a message
int aegis_verify_and_decrypt(uint8_t *message, size_t *message_len,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             const uint8_t *encaps_ct, size_t encaps_ct_len,
                             const uint8_t *signature, size_t signature_len,
                             const uint8_t *recipient_kyber_sk,
                             size_t recipient_kyber_sk_len,
                             const uint8_t *sender_sphincs_pk,
                             size_t sender_sphincs_pk_len) {
  if (!aegis_initialized) {
    return AEGIS_ERROR_INTERNAL;
  }

  if (message == NULL || message_len == NULL || ciphertext == NULL ||
      encaps_ct == NULL || signature == NULL || recipient_kyber_sk == NULL ||
      sender_sphincs_pk == NULL) {
    return AEGIS_ERROR_INVALID_PARAM;
  }

  // Verify the signature first
  int ret =
      aegis_sphincs_verify(signature, signature_len, ciphertext, ciphertext_len,
                           sender_sphincs_pk, sender_sphincs_pk_len);

  if (ret != AEGIS_SUCCESS) {
    return ret;
  }

  // Kyber decapsulation to recover shared secret
  uint8_t shared_secret[OQS_KEM_kyber_768_length_shared_secret];
  size_t shared_secret_len = sizeof(shared_secret);

  ret = aegis_kyber_decaps(shared_secret, &shared_secret_len, encaps_ct,
                           encaps_ct_len, recipient_kyber_sk,
                           recipient_kyber_sk_len);

  if (ret != AEGIS_SUCCESS) {
    return ret;
  }

  // Decrypt message with shared secret
  ret = decrypt_aes_gcm(ciphertext, ciphertext_len, shared_secret,
                        shared_secret_len, message, message_len);

  return ret;
}
