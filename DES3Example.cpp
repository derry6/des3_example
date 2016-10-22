
#include <DES3Helper.h>
#include <iostream>

extern void _dump(const char* info, const unsigned char* data, size_t size);

int main(int argc, const char* argv[]){

    // 密钥长度24位，不够补0x00
    std::string aesKey = "abcdefghijklmnopqrstuvwx";

    unsigned char plain[] = {11,2,30,4,52,6,7,8,9,110, 98, 73};

    _dump("\norigin", plain, sizeof plain);

    DES3Helper helper(aesKey);
    std::vector<unsigned char> encrypted = helper.encrypt(plain, sizeof plain);

    _dump("\nencrypted", &encrypted[0], encrypted.size() );

    std::vector<unsigned char> plainText = helper.decrypt(&encrypted[0], encrypted.size());

    _dump("\nplain", &plainText[0], plainText.size() );

    return 0;
}
