#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>

#include "encoding.h"

namespace encoding {

    ustring sstring2ustring(sstring const& s) {
        return ustring((unsigned char*)s.c_str(), s.length());
    }

    ustring generate_random_sequence(int n) {
        ustring seq(n, 0);
        for (int i = 0; i < n; ++i) {
            seq[i] = (unsigned char) rand();
        }
        return seq;
    }

    ustring md5_hash(ustring const& passphrase, ustring const& indata) {
        ustring str = indata + passphrase;

        MD5_CTX md5handler;
        unsigned char md5digest[MD5_DIGEST_LENGTH];
        MD5(str.c_str(), str.length(), md5digest);

        return ustring(md5digest, MD5_DIGEST_LENGTH);
    }

    ustring md5_hash(sstring const& passphrase, ustring const& indata) {
        return md5_hash(sstring2ustring(passphrase), indata);
    }

    ustring aes_encode(ustring const& passphrase, ustring const& indata, int length) {
        AES_KEY key;
        AES_set_encrypt_key(passphrase.c_str(), 8 * length, &key);
        unsigned char* outdata = new unsigned char[length];
        AES_encrypt(indata.c_str(), outdata, &key);
        ustring res(outdata, length);
        delete[] outdata;
        return res;
    }

    ustring aes_encode(sstring const& passphrase, ustring const& indata, int length) {
        return aes_encode(sstring2ustring(passphrase), indata, length);
    }

    ustring aes_decode(ustring const& passphrase, ustring const& indata, int length) {
        AES_KEY key;
        AES_set_decrypt_key(passphrase.c_str(), 8 * length, &key);
        unsigned char* outdata = new unsigned char[length];
        AES_decrypt(indata.c_str(), outdata, &key);
        ustring res(outdata, length);
        delete[] outdata;
        return res;
    }

    ustring aes_decode(sstring const& passphrase, ustring const& indata, int length) {
        return aes_decode(sstring2ustring(passphrase), indata, length);
    }

    bool check_passphrase(ustring const& correct_hash, ustring const& passphrase, ustring const& indata) {
        return correct_hash == md5_hash(passphrase, indata);
    }

    bool check_passphrase(ustring const& correct_hash, sstring const& passphrase, ustring const& indata) {
        return check_passphrase(correct_hash, sstring2ustring(passphrase), indata);
    }

    sstring base64_encode(ustring const& input, int length) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, input.c_str(), length);
        BIO_flush(b64);

        BUF_MEM* bptr;
        BIO_get_mem_ptr(b64, &bptr);

        sstring buffer(bptr->data, bptr->length - 1);

        BIO_free_all(b64);

        return buffer;
    }

    static int base64_decode_length(sstring const& input) {
        int padding = 0;
        if (input[input.length() - 1] == '=') {
            ++padding;
        }
        if (input[input.length() - 2] == '=') {
            ++padding;
        }
        return (input.length() * 6 - 8 * padding) / 8;
    }

    ustring base64_decode(sstring const& input, int length) {
        BIO* b64 = BIO_new(BIO_f_base64());
        sstring str = input + "\n";
        BIO* bmem = BIO_new_mem_buf((void*) str.c_str(), length + 1);
        bmem = BIO_push(b64, bmem);

        unsigned char *buffer = new unsigned char[length];
        BIO_read(bmem, buffer, length);

        BIO_free_all(bmem);

        ustring res(buffer, base64_decode_length(input));
        delete[] buffer;

        return res;
    }
}
