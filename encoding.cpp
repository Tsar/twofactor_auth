#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/md5.h>

#include "encoding.h"

namespace encoding {

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

    ustring aes_encode(ustring const& passphrase, ustring const& indata, int length) {
        AES_KEY key;
        AES_set_encrypt_key(passphrase.c_str(), 8 * length, &key);
        unsigned char* outdata = new unsigned char[8 * length];
        AES_encrypt(indata.c_str(), outdata, &key);
        ustring res(outdata, 8 * length);
        delete[] outdata;
        return res;
    }

    ustring aes_decode(ustring const& passphrase, ustring const& indata, int length) {
        AES_KEY key;
        AES_set_decrypt_key(passphrase.c_str(), 8 * length, &key);
        unsigned char* outdata = new unsigned char[8 * length];
        AES_decrypt(indata.c_str(), outdata, &key);
        ustring res(outdata, length);
        delete[] outdata;
        return res;
    }

    bool check_passphrase(ustring const& correct_hash, ustring const& passphrase, ustring const& indata) {
        //print(correct_hash);
        //print(md5_hash(passphrase, indata));
        return correct_hash == md5_hash(passphrase, indata);
    }

    sstring base64_encode(ustring const& input, int length) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, input.c_str(), length);
        BIO_flush(b64);

        BUF_MEM* bptr;
        BIO_get_mem_ptr(b64, &bptr);

        sstring buffer(bptr->data, bptr->length);

        BIO_free_all(b64);

        return buffer;
    }


    ustring base64_decode(sstring const& input, int length) {
        unsigned char *buffer = new unsigned char[length];

        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new_mem_buf((void*)input.c_str(), length);
        bmem = BIO_push(b64, bmem);

        BIO_read(bmem, buffer, length);

        BIO_free_all(bmem);

        ustring res(buffer, length);
        delete[] buffer;

        return res;
    }
}
