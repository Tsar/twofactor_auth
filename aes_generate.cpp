#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>

#include <stdio.h>
#include <time.h>

#include "encoding.h"

using namespace encoding;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("passphrase is expected\n");
        return 1;
    }
    srand(time(0));

    ustring passphrase = (unsigned char*) argv[1];

    int key_length = 16;
    printf("passphrase: %s\n", passphrase.c_str());
    ustring indata = generate_random_sequence(key_length);

    sstring base64_indata = base64_encode(indata, key_length);
    printf("original\t: %s", base64_indata.c_str());

    ustring outdata = aes_encode(passphrase, indata, key_length);
    printf("encoded \t: %s", base64_encode(outdata, key_length).c_str());

    ustring decoded = aes_decode((unsigned char*) "123", outdata, key_length);
    printf("decoded \t: %s", base64_encode(decoded, key_length).c_str());

    ustring md5 = md5_hash(passphrase, indata);
    printf("md5-exp \t: %s", base64_encode(md5, md5.length()).c_str());
    ustring md5_c = md5_hash(passphrase, decoded);
    printf("md5-act \t: %s", base64_encode(md5_c, md5_c.length()).c_str());

    if (check_passphrase(md5, passphrase, decoded)) {
        printf("Sieg\n");
    } else {
        printf("Fail\n");
    }

    return 0;
}
