
#pragma once


#include <Windows.h>


#define AES_KEY_SIZE_128        16
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_256        32
#define AES_BLOCK_SIZE          16

typedef struct
{
    unsigned int        eK[60];
    unsigned int        dK[60];
    unsigned int   Nr;
} AesContext;


int
    AesInitialise
    (
        AesContext*         Context,                // [out]
        void const*         Key,                    // [in]
        unsigned int            KeySize                 // [in]
    );
void
    AesEncrypt
    (
        AesContext const*   Context,                    // [in]
        unsigned char const       Input [AES_BLOCK_SIZE],     // [in]
        unsigned char             Output [AES_BLOCK_SIZE]     // [out]
    );

void
    AesDecrypt
    (
        AesContext const*   Context,                    // [in]
        unsigned char const       Input [AES_BLOCK_SIZE],     // [in]
        unsigned char             Output [AES_BLOCK_SIZE]     // [out]
    );

void
    AesEncryptInPlace
    (
        AesContext const*   Context,                    // [in]
        unsigned char             Block [AES_BLOCK_SIZE]      // [in out]
    );

void
    AesDecryptInPlace
    (
        AesContext const*   Context,                    // [in]
        unsigned char             Block [AES_BLOCK_SIZE]      // [in out]
    );

void* my_memcpy(void* dest, const void* src, int num);