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

void print_hex(const unsigned char* p) {
    for(int i = 0; *(p + i) != 0x00; i++) {
        printf("%X ", *(p + i));
    }
}

void print_str(const unsigned char* p) {
    for(int i = 0; *(p + i) != 0x00; i++) {
        printf("%c", *(p + i));
    }
}

unsigned char* generate_random_sequence(int n) {
    unsigned char* seq = new unsigned char[n];
    for (int i = 0; i < n; ++i) {
        seq[i] = (unsigned char) rand();
    }
    return seq;
}

unsigned char* aes_encode(const unsigned char* passphrase, const unsigned char* indata, int length) {
    AES_KEY key;
    AES_set_encrypt_key(passphrase, length, &key);
    unsigned char* outdata = new unsigned char[length];
    AES_encrypt(indata, outdata, &key);
    return outdata;
}

unsigned char* aes_decode(const unsigned char* passphrase, const unsigned char* indata, int length) {
    AES_KEY key;
    AES_set_decrypt_key(passphrase, length, &key);
    unsigned char* outdata = new unsigned char[length];
    AES_decrypt(indata, outdata, &key);
    return outdata;
}

unsigned char* base64_encode(const unsigned char *input, int length) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    unsigned char *buffer = (unsigned char *) malloc(bptr->length);
    memcpy(buffer, bptr->data, bptr->length-1);
    buffer[bptr->length-1] = 0;

    BIO_free_all(b64);

    return buffer;
}


unsigned char* base64_decode(const unsigned char* input, int length) {
    unsigned char *buffer = (unsigned char *)malloc(length);
    memset(buffer, 0, length);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf((void*) input, length);
    bmem = BIO_push(b64, bmem);

    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("passphrase is expected");
        return 1;
    }
    srand((unsigned int) time(NULL));
    const char* passphrase = argv[1];

    int key_length = 16;
    printf("passphrase: %s\n", passphrase);
    unsigned char* indata = generate_random_sequence(key_length);

    printf("original\t:");
    print_str(base64_encode(indata, key_length));
    printf("\n");

    unsigned char* outdata = aes_encode((unsigned char*)passphrase, indata, 8 * key_length);
    free(indata);

    printf("encoded \t:");
    print_str(base64_encode(outdata, key_length));
    printf("\n");

    indata = aes_decode((unsigned char*) passphrase, outdata, 8 * key_length);

    printf("decoded \t:");
    print_str(base64_decode(indata, key_length));
    printf("\n");
    free(outdata);
    free(indata);
    return 0;
}