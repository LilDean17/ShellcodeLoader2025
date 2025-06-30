
#include <Windows.h>
#include "aes.h"


#define AES_CBC_IV_SIZE             AES_BLOCK_SIZE



typedef struct
{
    AesContext      Aes;
    unsigned char         PreviousCipherBlock [AES_BLOCK_SIZE];
} AesCbcContext;


void
    AesCbcInitialise
    (
        AesCbcContext*      Context,                // [out]
        AesContext const*   InitialisedAesContext,  // [in]
        unsigned char const       IV [AES_CBC_IV_SIZE]    // [in]
    );
int
    AesCbcInitialiseWithKey
    (
        AesCbcContext*      Context,                // [out]
        unsigned char const*      Key,                    // [in]
        unsigned int            KeySize,                // [in]
        unsigned char const       IV [AES_CBC_IV_SIZE]    // [in]
    );


int
    AesCbcDecrypt
    (
        AesCbcContext*      Context,                // [in out]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        unsigned int            Size                    // [in]
    );

int
    AesCbcEncryptWithKey
    (
        unsigned char const*      Key,                    // [in]
        unsigned int            KeySize,                // [in]
        unsigned char const       IV [AES_CBC_IV_SIZE],   // [in]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        unsigned int            BufferSize              // [in]
    );

int
    AesCbcDecryptWithKey
    (
        unsigned char const*      Key,                    // [in]
        unsigned int            KeySize,                // [in]
        unsigned char const       IV [AES_CBC_IV_SIZE],   // [in]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        unsigned int            BufferSize              // [in]
    );
