#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <string>

using std::string;
typedef std::basic_string<unsigned char> ustring;

ustring generate_random_sequence(int n) {
    ustring seq;
    for (int i = 0; i < n; ++i) {
        seq += (unsigned char)rand();
    }
    return seq;
}

ustring aes_encode(ustring const& passphrase, ustring const& indata, int length) {
    AES_KEY key;
    AES_set_encrypt_key(passphrase.c_str(), length, &key);
    unsigned char* outdata = new unsigned char[length];
    AES_encrypt(indata.c_str(), outdata, &key);
    ustring res(outdata);
    delete[] outdata;
    return res;
}

ustring aes_decode(ustring const& passphrase, ustring const& indata, int length) {
    AES_KEY key;
    AES_set_decrypt_key(passphrase.c_str(), length, &key);
    unsigned char* outdata = new unsigned char[length];
    AES_decrypt(indata.c_str(), outdata, &key);
    ustring res(outdata);
    delete[] outdata;
    return res;
}

string base64_encode(ustring const& input, int length) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input.c_str(), length);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    string buffer(bptr->data, bptr->length);
    buffer[bptr->length - 1] = 0;

    BIO_free_all(b64);

    return buffer;
}


ustring base64_decode(string const& input, int length) {
    unsigned char *buffer = new unsigned char[length];
    //memset(buffer, 0, length);  // what for?

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf((void*)input.c_str(), length);
    bmem = BIO_push(b64, bmem);

    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    ustring res(buffer);
    delete[] buffer;

    return res;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("passphrase is expected\n");
        return 1;
    }

    srand(time(0));

    ustring passphrase = (unsigned char*)argv[1];

    int key_length = 16;
    printf("passphrase: %s\n", passphrase.c_str());
    ustring indata = generate_random_sequence(key_length);

    printf("original\t: %s\n", base64_encode(indata, key_length).c_str());

    // FIX DECODE
    printf("original\t: %s\n", base64_encode(base64_decode(base64_encode(indata, key_length), key_length), key_length).c_str());

    ustring outdata = aes_encode(passphrase, indata, 8 * key_length);

    printf("encoded \t: %s\n", base64_encode(outdata, key_length).c_str());

    indata = aes_decode(passphrase, outdata, 8 * key_length);

    printf("decoded \t: %s\n", base64_encode(indata, key_length).c_str());

    return 0;
}
