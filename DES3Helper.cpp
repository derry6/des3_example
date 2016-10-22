
#include "DES3Helper.h"

#include <stdlib.h>
#include <string.h>

#ifdef DES3_DEBUG
#include <stdio.h>
void _dump(const char* info, const unsigned char* data, size_t size)
{
    fprintf(stderr, "%s: ", info);
    for(size_t i = 0; i < size; ++i ) {
        if( i % 16 == 0 )
            fprintf(stderr, "\n");
        fprintf(stderr, "0x%02x ", data[i]);
    }
    fprintf(stderr, "\n\n");
}
#else
void _dump(const char* , const byte* , size_t )
{
}
#endif

DES3Helper::DES3Helper(const std::string& aesKey) {
    //
    size_t len = aesKey.length();
    if( len > kKeySize ) {
        memcpy(key_, aesKey.c_str(), kKeySize);
    } else {
        memset(key_, 0x00, sizeof key_);
        memcpy(key_, aesKey.c_str(), len);
    }
    initialize();
}

void DES3Helper::initialize() {
    DES_set_key_unchecked((const_DES_cblock*)(key_+ 0), &ks1_);
    DES_set_key_unchecked((const_DES_cblock*)(key_+ 8), &ks2_);
    DES_set_key_unchecked((const_DES_cblock*)(key_+16), &ks3_);
}


std::vector<DES3Helper::byte> DES3Helper::cipher(const byte* plain, size_t size, int desType) {

    std::vector<byte> result;

    byte in[kBlockSize] = {0};
    byte out[kBlockSize]= {0};

    size_t left  = size % kBlockSize;
    size_t round = size / kBlockSize;

#ifdef DES3_DEBUG
    const char* str = "unknown";
    if( desType == DES_ENCRYPT ) {
        str = "encrypt";
    } else if( desType == DES_DECRYPT ) {
        str = "decrypt";
    }
    fprintf(stderr, "\n===========(%s %zd bytes)=========\n", str, size);
#endif

    _dump("input", plain, size );

    int need_bytes = kBlockSize;

    for( size_t i = 0; i < round; i++ ) {
        memcpy(in, plain + i * kBlockSize, kBlockSize);
        memset(out, 0, sizeof out);

        DES_ecb3_encrypt( (const_DES_cblock*)(&in[0]),
                         (DES_cblock*)(&out[0]),
                         &ks1_, &ks2_, &ks3_,
                         desType);

        if( desType == DES_DECRYPT && i == (round - 1)) {
            need_bytes = kBlockSize - static_cast<int>(out[7]);
        }
        std::copy(out, out+need_bytes, std::back_inserter(result));
    }

    if( desType == DES_ENCRYPT ) {
        memcpy(in, plain + size - left, left);
        memset(in + left, static_cast<byte>(kBlockSize-left), sizeof(in) - left);
        _dump("padding", in, sizeof in);
        memset(out, 0, sizeof out);
        DES_ecb3_encrypt( (const_DES_cblock*)(&in[0]),
                          (DES_cblock*)(&out[0]),
                          &ks1_, &ks2_, &ks3_,
                          desType);
        _dump("last_out", out, sizeof out);
        std::copy(out, out + kBlockSize, std::back_inserter(result) );
    }
    _dump("output", &result[0], result.size());
    return result;
}

