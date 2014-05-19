#ifndef ENCODING_H
#define ENCODING_H

#include <string>

namespace encoding {

    typedef std::string sstring;
    typedef std::basic_string<unsigned char> ustring;

    ustring generate_random_sequence(int n);
    ustring md5_hash(ustring const& passphrase, ustring const& indata);
    ustring md5_hash(sstring const& passphrase, ustring const& indata);

    ustring aes_encode(ustring const& passphrase, ustring const& indata, int length);
    ustring aes_encode(sstring const& passphrase, ustring const& indata, int length);
    ustring aes_decode(ustring const& passphrase, ustring const& indata, int length);
    ustring aes_decode(sstring const& passphrase, ustring const& indata, int length);
    sstring base64_encode(ustring const& input);
    ustring base64_decode(sstring const& input);

    bool check_passphrase(ustring const& correct_hash, ustring const& passphrase, ustring const& indata);
    bool check_passphrase(ustring const& correct_hash, sstring const& passphrase, ustring const& indata);
}

#endif
