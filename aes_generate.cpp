#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>

#include <stdio.h>
#include <time.h>
#include <iostream>

#include "encoding.h"

using namespace encoding;

/** CODE FOR TESTING ENCRYPTION/DECRYPTION FUNCTIONS

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

*/

void print(const ustring& str) {
    for (size_t i = 0; i < str.length(); ++i) {
        printf("0x%02x ", str[i]);
    }
    printf("\n");
}

int main() {
    srand(time(0));

    sstring passphrase;
    std::cout << "Input passphrase: ";
    std::cin >> passphrase;
    std::cout << std::endl << "Passphrase: " << passphrase << std::endl;

    const int key_length = 16;
    const int md5_length = 16;
    ustring key = generate_random_sequence(key_length);
    std::cout << "Set as password for 'pam_unix':\t" << base64_encode(key) << std::endl;

    ustring encryptedKey = aes_encode(passphrase, key, key_length);
    ustring md5PlusEncKey = md5_hash(passphrase, key) + encryptedKey;
    sstring keyFileContents = base64_encode(md5PlusEncKey);
    std::cout << "Put to 'ptfa.key' file:\t\t" << keyFileContents << std::endl;

    /// CHECKING THAT EVERYTHING WORKS FINE
    ustring kfBin = base64_decode(keyFileContents);
    if (kfBin != md5PlusEncKey) {
        std::cerr << "ERROR: base64_decode(base64_encode(something)) != something" << std::endl;
        return 1;
    }
    ustring decryptedKey = aes_decode(passphrase, kfBin.substr(md5_length, key_length), key_length);
    if (key != decryptedKey) {
        std::cerr << "ERROR: generated key != decrypted key" << std::endl;
        return 2;
    }
    if (!encoding::check_passphrase(kfBin.substr(0, md5_length), passphrase, decryptedKey)) {
        std::cerr << "ERROR: passphrase check failed" << std::endl;
        return 3;
    }

    return 0;
}
