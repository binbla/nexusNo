#include "../include/crypto.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

using wg::ChainingKey;
using wg::Hash;
using wg::Hmac;
using wg::Mac;
using wg::Nonce;
using wg::PrivateKey;
using wg::PublicKey;
using wg::SharedSecret;
using wg::SymmetricKey;
using wg::Tag;
using wg::XNonce;

[[noreturn]] void fail(const std::string& msg) {
    throw std::runtime_error(msg);
}

void expect_true(bool cond, const std::string& msg) {
    if (!cond) {
        fail(msg);
    }
}

template <typename A, typename B>
void expect_eq(const A& a, const B& b, const std::string& msg) {
    if (!(a == b)) {
        fail(msg);
    }
}

template <typename A, typename B>
void expect_ne(const A& a, const B& b, const std::string& msg) {
    if (!(a != b)) {
        fail(msg);
    }
}

void fill_seq(std::span<uint8_t> out, uint8_t seed) {
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(seed + i);
    }
}

Nonce make_wg_nonce(uint64_t counter) {
    Nonce nonce{};
    nonce[4] = static_cast<uint8_t>(counter);
    nonce[5] = static_cast<uint8_t>(counter >> 8);
    nonce[6] = static_cast<uint8_t>(counter >> 16);
    nonce[7] = static_cast<uint8_t>(counter >> 24);
    nonce[8] = static_cast<uint8_t>(counter >> 32);
    nonce[9] = static_cast<uint8_t>(counter >> 40);
    nonce[10] = static_cast<uint8_t>(counter >> 48);
    nonce[11] = static_cast<uint8_t>(counter >> 56);
    return nonce;
}

void test_key_and_dh(wg::CryptoProvider& crypto) {
    PrivateKey a_priv{}, b_priv{};
    PublicKey a_pub{}, b_pub{};
    SharedSecret ss_ab{}, ss_ba{};

    crypto.generate_static_keypair(a_priv, a_pub);
    crypto.generate_ephemeral_keypair(b_priv, b_pub);

    expect_true(crypto.dh(a_priv, b_pub, ss_ab), "dh(a_priv,b_pub) failed");
    expect_true(crypto.dh(b_priv, a_pub, ss_ba), "dh(b_priv,a_pub) failed");
    expect_eq(ss_ab, ss_ba, "DH shared secrets mismatch");

    PublicKey derived{};
    crypto.derive_public_key(a_priv, derived);
    expect_eq(derived, a_pub, "derive_public_key mismatch");
}

void test_aead(wg::CryptoProvider& crypto) {
    SymmetricKey key{};
    fill_seq(key, 0x10);

    const Nonce nonce = make_wg_nonce(42);
    const std::array<uint8_t, 13> ad = {'h', 'e', 'a', 'd', 'e', 'r', '-',
                                        'd', 'a', 't', 'a', '-', 'x'};
    const std::array<uint8_t, 17> pt = {'n', 'e', 'x', 'u', 's', '-',
                                        'n', 'o', '-', 'p', 'a', 'y',
                                        'l', 'o', 'a', 'd', '!'};

    std::array<uint8_t, pt.size()> ct{};
    std::array<uint8_t, pt.size()> out{};
    Tag tag{};

    crypto.aead_encrypt(key, nonce, ad, pt, ct, tag);
    expect_true(crypto.aead_decrypt(key, nonce, ad, ct, tag, out),
                "aead_decrypt should succeed");
    expect_eq(out, pt, "aead decrypted plaintext mismatch");

    Tag bad_tag = tag;
    bad_tag[0] ^= 0x01;
    expect_true(!crypto.aead_decrypt(key, nonce, ad, ct, bad_tag, out),
                "aead_decrypt should fail with modified tag");

    Nonce bad_nonce = nonce;
    bad_nonce[0] = 1;
    expect_true(!crypto.aead_decrypt(key, bad_nonce, ad, ct, tag, out),
                "aead_decrypt should fail with non-wireguard nonce");
}

void test_xaead(wg::CryptoProvider& crypto) {
    SymmetricKey key{};
    fill_seq(key, 0x33);

    XNonce nonce{};
    fill_seq(nonce, 0x80);

    const std::array<uint8_t, 8> ad = {'x', 'a', 'e', 'a', 'd', '-', 'a', 'd'};
    const std::array<uint8_t, 9> pt = {'x', 'c', 'h', 'a', 'c',
                                       'h', 'a', '2', '0'};

    std::array<uint8_t, pt.size()> ct{};
    std::array<uint8_t, pt.size()> out{};
    Tag tag{};

    crypto.xaead_encrypt(key, nonce, ad, pt, ct, tag);
    expect_true(crypto.xaead_decrypt(key, nonce, ad, ct, tag, out),
                "xaead_decrypt should succeed");
    expect_eq(out, pt, "xaead decrypted plaintext mismatch");

    XNonce wrong_nonce = nonce;
    wrong_nonce[0] ^= 0x7f;
    expect_true(!crypto.xaead_decrypt(key, wrong_nonce, ad, ct, tag, out),
                "xaead_decrypt should fail with wrong nonce");
}

void test_hash_mac_hmac(wg::CryptoProvider& crypto) {
    const std::array<uint8_t, 6> data = {'n', 'e', 'x', 'u', 's', '0'};
    const std::array<uint8_t, 8> key = {'k', 'e', 'y', '-', 't', 'e', 's', 't'};

    Hash h1{}, h2{};
    crypto.hash(data, h1);
    crypto.hash(data, h2);
    expect_eq(h1, h2, "hash should be deterministic");

    Mac m1{}, m2{};
    crypto.mac(data, key, m1);
    crypto.mac(data, key, m2);
    expect_eq(m1, m2, "mac should be deterministic");

    Hmac hm1{}, hm2{};
    crypto.hmac(data, key, hm1);
    crypto.hmac(data, key, hm2);
    expect_eq(hm1, hm2, "hmac should be deterministic");

    std::array<uint8_t, 9> other_key = {'k', 'e', 'y', '-', 't',
                                        'e', 's', 't', '!'};
    Hmac hm3{};
    crypto.hmac(data, other_key, hm3);
    expect_ne(hm1, hm3, "hmac should change with key");
}

void test_kdf(wg::CryptoProvider& crypto) {
    ChainingKey ck{};
    fill_seq(ck, 1);
    const std::array<uint8_t, 14> data = {'k', 'd', 'f', '-', 'i', 'n', 'p',
                                          'u', 't', '-', 'd', 'a', 't', 'a'};

    ChainingKey out1_a{}, out1_b{}, out1_c{};
    SymmetricKey out2_a{}, out2_b{};
    SymmetricKey out3{};

    crypto.kdf1(ck, data, out1_a);
    crypto.kdf2(ck, data, out1_b, out2_a);
    crypto.kdf3(ck, data, out1_c, out2_b, out3);

    expect_eq(out1_a, out1_b, "kdf1 out1 should equal kdf2 out1");
    expect_eq(out1_a, out1_c, "kdf1 out1 should equal kdf3 out1");
    expect_eq(out2_a, out2_b, "kdf2 out2 should equal kdf3 out2");

    SymmetricKey out3_again{};
    ChainingKey throwaway{};
    SymmetricKey throwaway2{};
    crypto.kdf3(ck, data, throwaway, throwaway2, out3_again);
    expect_eq(out3, out3_again, "kdf3 should be deterministic");
}

void test_random(wg::CryptoProvider& crypto) {
    std::array<uint8_t, 32> r1{}, r2{};
    crypto.random_bytes(r1);
    crypto.random_bytes(r2);

    const bool all_zero_1 =
        std::all_of(r1.begin(), r1.end(), [](uint8_t v) { return v == 0; });
    const bool all_zero_2 =
        std::all_of(r2.begin(), r2.end(), [](uint8_t v) { return v == 0; });

    expect_true(!all_zero_1, "random_bytes produced all zeros (r1)");
    expect_true(!all_zero_2, "random_bytes produced all zeros (r2)");
    expect_ne(r1, r2, "random_bytes produced identical buffers twice");
}

}  // namespace

int main() {
    try {
        auto crypto = wg::create_libsodium_provider();
        if (!crypto) {
            std::cerr << "[FAIL] provider creation failed\n";
            return 1;
        }

        test_key_and_dh(*crypto);
        test_aead(*crypto);
        test_xaead(*crypto);
        test_hash_mac_hmac(*crypto);
        test_kdf(*crypto);
        test_random(*crypto);

        std::cout << "[OK] crypto unit tests passed\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] " << ex.what() << "\n";
        return 1;
    }
}
