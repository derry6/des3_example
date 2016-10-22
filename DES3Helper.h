#ifndef DES3HELPER_H
#define DES3HELPER_H

#include <openssl/des.h>

#include <string>
#include <vector>

class DES3Helper {

    typedef unsigned char byte;

    public:
        enum {
            kBlockSize      = 8,
            kKeySize        = 24
        };

    public:
        DES3Helper(const std::string& aesKey);

        std::vector<byte> encrypt(const byte* plain, size_t size) {
            return cipher(plain, size, DES_ENCRYPT);
        }

        std::vector<byte> encrypt(const std::vector<byte>& plain) {
            return cipher(&plain[0], plain.size(), DES_ENCRYPT);
        }

        std::vector<byte> decrypt(const byte* encrypted, size_t size) {
            return cipher(encrypted, size, DES_DECRYPT);
        }

        std::vector<byte> decrypt(const std::vector<byte>& encrypted) {
             return cipher(&encrypted[0], encrypted.size(), DES_DECRYPT);
        }

    private:
        void initialize();

        std::vector<byte> cipher(const byte* plain, size_t size, int desType);
    private:
        byte key_[24];
        DES_key_schedule ks1_, ks2_, ks3_;
};

#endif // DES3HELPER_H
