#ifndef AES_CBC_H
#define AES_CBC_H

#include <stddef.h>   // size_t
#include <stdint.h>   // uint8_t

#define AES_256 32
#define IV_AES 16


struct aes_256_obj{
    uint8_t key[AES_256];
    unsigned int keybits;
    uint8_t iv[IV_AES];

};
void create_aes_256_obj(struct aes_256_obj *self, uint8_t *key);
void read_and_update_iv_aes(struct aes_256_obj *self, uint8_t *iv);
void update_iv_aes(struct aes_256_obj *self);


int aes_cbc_encrypt_pkcs7(const uint8_t *key, unsigned keybits,
                          const uint8_t iv_in[16],
                          const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t **ciphertext, size_t *ciphertext_len);

int aes_cbc_decrypt_pkcs7(const uint8_t *key, unsigned keybits,
                          const uint8_t iv_in[16],
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          uint8_t **plaintext, size_t *plaintext_len);

#endif // AES_CBC_H
