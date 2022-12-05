#include<stdio.h>
#include"aes.h"
#include"aes_cmac.h"
#define ECB 1
#define AES128 1

static struct AES_ctx ctx;

void aes_cmac_encrypt(uint8_t* data) {
    AES_ECB_encrypt(&ctx, data); // <-- this is the *external* AES encryption function with its own logic. you can use tiny-AES-c library from kokke
}

int main() {
    
    // 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c 
    uint8_t key[16] = { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
    AES_init_ctx(&ctx, key);
    struct AES_CMAC_ctx aes_cmac_ctx;
    /* provide the CMAC library with AES encryption callback function that will perform the actual AES encryption */
    AES_CMAC_init_ctx(&aes_cmac_ctx, &aes_cmac_encrypt);

    /* message to generate the CMAC from */
    uint8_t message[] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };

    /* generate the CMAC */
    uint8_t cmac[16];
    AES_CMAC_digest(&aes_cmac_ctx, message, sizeof(message), cmac);

    /* print out the resulting tag */
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02X ", cmac[i]);
    }
    return 0;
}