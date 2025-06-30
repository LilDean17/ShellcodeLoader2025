
#include "cbc.h"
#include "aes.h"


#define MIN( x, y ) ( ((x)<(y))?(x):(y) )

#define STORE64H( x, y )                                                       \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255);  (y)[7] = (unsigned char)((x)&255); }

static
void
    XorAesBlock
    (
        unsigned char*            Block1,          // [in out]
        unsigned char const*      Block2           // [in]
    )
{
    unsigned int    i;

    for( i=0; i<AES_BLOCK_SIZE; i++ )
    {
        Block1[i] ^= Block2[i];
    }
}

void
    AesCbcInitialise
    (
        AesCbcContext*      Context,                // [out]
        AesContext const*   InitialisedAesContext,  // [in]
        unsigned char const       IV [AES_CBC_IV_SIZE]    // [in]
    )
{

    Context->Aes = *InitialisedAesContext;
    my_memcpy( Context->PreviousCipherBlock, IV, sizeof(Context->PreviousCipherBlock) );
}
int
    AesCbcInitialiseWithKey
    (
        AesCbcContext*      Context,                // [out]
        unsigned char const*      Key,                    // [in]
        unsigned int            KeySize,                // [in]
        unsigned char const       IV [AES_CBC_IV_SIZE]    // [in]
    )
{
    AesContext aes;


    if( 0 != AesInitialise( &aes, Key, KeySize ) )
    {
        return -1;
    }


    AesCbcInitialise( Context, &aes, IV );
    return 0;
}


int
    AesCbcDecrypt
    (
        AesCbcContext*      Context,                // [in out]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        unsigned int            Size                    // [in]
    )
{
    unsigned int    numBlocks = Size / AES_BLOCK_SIZE;
    unsigned int    offset = 0;
    unsigned int    i;
    unsigned char     previousCipherBlock [AES_BLOCK_SIZE];

    if( 0 != Size % AES_BLOCK_SIZE )
    {

        return -1;
    }

    for( i=0; i<numBlocks; i++ )
    {

        my_memcpy( previousCipherBlock, Context->PreviousCipherBlock, AES_BLOCK_SIZE );
        my_memcpy( Context->PreviousCipherBlock, (unsigned char*)InBuffer + offset, AES_BLOCK_SIZE );

        AesDecrypt( &Context->Aes, Context->PreviousCipherBlock, (unsigned char*)OutBuffer + offset );

        XorAesBlock( (unsigned char*)OutBuffer + offset, previousCipherBlock );

        offset += AES_BLOCK_SIZE;
    }

    return 0;
}



int
    AesCbcDecryptWithKey
    (
        unsigned char const*      Key,                    // [in]
        unsigned int            KeySize,                // [in]
        unsigned char const       IV [AES_CBC_IV_SIZE],   // [in]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        unsigned int            BufferSize              // [in]
    )
{
    int             error;
    AesCbcContext   context;

    error = AesCbcInitialiseWithKey( &context, Key, KeySize, IV );
    if( 0 == error )
    {
        error = AesCbcDecrypt( &context, InBuffer, OutBuffer, BufferSize );
    }

    return error;
}
