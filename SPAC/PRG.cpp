#include "PRG.h"
#include "Parameter.h"

long long PRG::pms_G[2];
void PRG::Setup(int k)
{
    pms_G[0] = Parameter::pms_G[0];
    pms_G[1] = Parameter::pms_G[1];
}

// input hex(256bits), output hex
void PRG::Gen(const char *input, char *output)
{
    aes a;
    char iv[128 / 4] = {0};
    unsigned char key[2][128 / 8 / 2];

    unsigned char data_char[32];
    unsigned int bytelength = Parameter::hex2byte((char *)input, data_char, 64);
    char data_to_enc1[16];
    char data_to_enc2[16];
    char data_to_enc1_[16];
    char data_to_enc2_[16];

    for (int j = 0; j < 16; j++)
    {
        data_to_enc1_[j] = data_to_enc1[j] = data_char[j];
        data_to_enc2_[j] = data_to_enc2[j] = data_char[j + 16];
    }

    // set key
    Parameter::longlong2byte(pms_G[0], key[0]);
    Parameter::longlong2byte(pms_G[1], key[1]);

    aes_init(&a, MR_CBC, 16, (char *)key, iv);
    aes_encrypt(&a, data_to_enc1);

    aes_init(&a, MR_CBC, 16, (char *)key, data_to_enc1);
    aes_encrypt(&a, data_to_enc2);

    aes_init(&a, MR_CBC, 16, (char *)key, data_to_enc2);
    aes_encrypt(&a, data_to_enc1_);

    aes_init(&a, MR_CBC, 16, (char *)key, data_to_enc1_);
    aes_encrypt(&a, data_to_enc2_);

    char output_byte[64];

    memcpy(output_byte, data_to_enc1, 16);
    memcpy(output_byte + 16, data_to_enc2, 16);
    memcpy(output_byte + 32, data_to_enc1_, 16);
    memcpy(output_byte + 48, data_to_enc2_, 16);

    Parameter::byte2hex((unsigned char *)output_byte, output, 64);
}