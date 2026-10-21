/*
This source file is part of Kythera Lock
For the latest info, see https://github.com/gemmuse/KytheraLock

Copyright 2026 Kythera Lock Development Team

This program is free software : you can redistribute it and /or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see < https://www.gnu.org/licenses/>.
*/
#include "CryptoEngine.h"

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace kythera::core {

void CryptoEngine::Initialize() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium init failed");
    }
}

CryptoEngine::KDFBundle CryptoEngine::CreateKDFBundle(
    const std::string& password) const {
    // Used ONCE, when a brand new vault is created.
    KDFBundle b;

    // Step 1: a fresh random salt. Every vault gets its own, so two people
    // with the same password still end up with completely different keys.
    b.salt.resize(SALT_SIZE);
    randombytes_buf(b.salt.data(), b.salt.size());

    // Step 2: turn password + salt into the master key (slow on purpose).
    b.masterKey = DeriveMasterKey(password, b.salt);

    // Step 3: make the fingerprint we can store to check passwords later.
    b.verifier = ComputeVerifier(b.masterKey);
    return b;
}

SecureBuffer
CryptoEngine::DeriveMasterKey(const std::string& password,
    const std::vector<unsigned char>& salt) const {
    if (salt.size() != SALT_SIZE)
        throw std::runtime_error("Salt size invalid");

    SecureBuffer key(MASTER_KEY_SIZE);

    // This is the "slow scramble". The same password + salt ALWAYS gives the
    // same key (that is how unlocking works), but it is deliberately costly
    // to compute:
    //   opslimit = 3    : the scramble makes 3 passes over its memory.
    //   memlimit = 64MB : each attempt must use 64MB of RAM. This stops an
    //                     attacker running millions of guesses in parallel on
    //                     cheap graphics cards, which have little memory each.
    // A real user waits a fraction of a second. An attacker guessing a
    // billion passwords has to pay that cost a billion times.
    //
    // WARNING: these numbers are part of the vault's format. Changing them
    // produces a different key, so existing vaults would stop unlocking.
    // (Argon2id = the algorithm; the "id" variant resists both side-channel
    // and GPU attacks.)
    const std::uint64_t opslimit = 3;
    const size_t memlimit = 64ULL * 1024ULL * 1024ULL;

    if (crypto_pwhash(key.data(), key.size(),
        password.data(), password.size(),
        salt.data(),
        opslimit, memlimit,
        crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("crypto_pwhash failed (out of memory?)");
    }

    return key;
}

std::vector<unsigned char> CryptoEngine::ComputeVerifier(
    const SecureBuffer& masterKey) const {
    if (masterKey.size() != MASTER_KEY_SIZE)
        throw std::runtime_error("Master key size invalid");

    std::vector<unsigned char> out(VERIFIER_SIZE);

    // WHY A VERIFIER? We must never store the master key (that would be like
    // taping the key to the door). But we still need to know whether a typed
    // password was right. So we store a one-way "fingerprint" of the key.
    // At unlock we re-derive the key, fingerprint it, and compare. A hash
    // cannot be run backwards, so the fingerprint reveals nothing about the
    // key.
    //
    // Keyed BLAKE2b hash of a constant string.
    // If password is wrong, derived key differs => verifier differs.
    static const unsigned char msg[] = "vault-password-verifier-v1";

    crypto_generichash(out.data(), out.size(),
        msg, sizeof(msg) - 1,
        masterKey.data(), masterKey.size());

    return out;
}

std::string CryptoEngine::B64Encode(
    const std::vector<unsigned char>& bytes) const {
    size_t out_len = sodium_base64_ENCODED_LEN(bytes.size(),
                                               sodium_base64_VARIANT_ORIGINAL);
    std::string out(out_len, '\0');

    sodium_bin2base64(out.data(), out.size(),
        bytes.data(), bytes.size(),
        sodium_base64_VARIANT_ORIGINAL);

    // Trim the trailing null terminator(s) libsodium wrote, so the string
    // holds only the base64 text.
    out.resize(std::strlen(out.c_str()));
    return out;
}

std::vector<unsigned char>
CryptoEngine::B64Decode(std::string_view text) const {
    std::vector<unsigned char> out(text.size());
    size_t bin_len = 0;

    if (sodium_base642bin(out.data(), out.size(),
        text.data(), text.size(),
        nullptr, &bin_len, nullptr,
        sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("Base64 decode failed");
    }

    out.resize(bin_len);
    return out;
}

bool CryptoEngine::EqualsConstantTime(
    const std::vector<unsigned char>& a,
    const std::vector<unsigned char>& b) const {
    // WHY NOT JUST USE ==? A normal comparison stops at the first byte that
    // differs, so it finishes slightly faster when the guess is wrong early.
    // An attacker timing many attempts could use that to learn the correct
    // value one byte at a time. sodium_memcmp always checks every byte, so
    // the time taken reveals nothing. (Comparing lengths first is fine: the
    // lengths here are fixed and public.)
    if (a.size() != b.size()) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::vector<unsigned char> CryptoEngine::BuildContextBytes(
    const RecordContext& context) {
    // Layout (every field has a fixed size, or a size written in front of it):
    //   [version][algorithm][purpose][vault id: 8 bytes][id size: 4 bytes][id]
    // Numbers are written most-significant byte first.
    if (context.recordId.size() > UINT32_MAX)
        throw std::invalid_argument("Record id too long");

    const auto idSize = static_cast<std::uint32_t>(context.recordId.size());

    std::vector<unsigned char> bytes;
    bytes.reserve(2 + 1 + 8 + 4 + context.recordId.size());

    bytes.push_back(RECORD_VERSION);
    bytes.push_back(ALGORITHM_XCHACHA20_POLY1305);
    bytes.push_back(static_cast<unsigned char>(context.purpose));

    for (int shift = 56; shift >= 0; shift -= 8)
        bytes.push_back(static_cast<unsigned char>(
            (context.vaultId >> shift) & 0xFF));

    for (int shift = 24; shift >= 0; shift -= 8)
        bytes.push_back(static_cast<unsigned char>((idSize >> shift) & 0xFF));

    bytes.insert(bytes.end(), context.recordId.begin(),
                 context.recordId.end());

    return bytes;
}

std::vector<unsigned char> CryptoEngine::Seal(
    const SecureBuffer& key,
    const unsigned char* plaintext,
    size_t plaintextSize,
    const RecordContext& context) const {
    if (key.size() != RECORD_KEY_SIZE)
        throw std::invalid_argument("Record key size invalid");

    if (plaintext == nullptr && plaintextSize > 0)
        throw std::invalid_argument("Plaintext missing");

    if (plaintextSize > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX)
        throw std::invalid_argument("Plaintext too long");

    const auto contextBytes = BuildContextBytes(context);

    std::vector<unsigned char> record(RECORD_OVERHEAD + plaintextSize);
    record[0] = RECORD_VERSION;
    record[1] = ALGORITHM_XCHACHA20_POLY1305;

    // A brand new random nonce for every record. The nonce must never repeat
    // under the same key; 24 random bytes make a repeat practically
    // impossible, which is why this cipher was chosen (D2).
    unsigned char* nonce = record.data() + 2;
    randombytes_buf(nonce, NONCE_SIZE);

    unsigned long long ciphertextSize = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        record.data() + 2 + NONCE_SIZE, &ciphertextSize,
        plaintext, plaintextSize,
        contextBytes.data(), contextBytes.size(),
        nullptr, nonce, key.data());

    if (ciphertextSize != plaintextSize + TAG_SIZE)
        throw std::runtime_error("Unexpected ciphertext size");

    return record;
}

std::vector<unsigned char> CryptoEngine::Seal(
    const SecureBuffer& key,
    std::string_view plaintext,
    const RecordContext& context) const {
    return Seal(key,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                plaintext.size(), context);
}

SecureBuffer CryptoEngine::Open(
    const SecureBuffer& key,
    const std::vector<unsigned char>& record,
    const RecordContext& context) const {
    // A wrong-sized key is a mistake in our own code, not a property of the
    // data being opened, so it is reported differently.
    if (key.size() != RECORD_KEY_SIZE)
        throw std::invalid_argument("Record key size invalid");

    // Every way of failing to open a record gives the same message, so the
    // error never tells an attacker which check failed.
    static const char kCannotOpen[] = "Record could not be opened";

    if (record.size() < RECORD_OVERHEAD ||
        record[0] != RECORD_VERSION ||
        record[1] != ALGORITHM_XCHACHA20_POLY1305) {
        throw std::runtime_error(kCannotOpen);
    }

    const auto contextBytes = BuildContextBytes(context);

    const unsigned char* nonce = record.data() + 2;
    const unsigned char* ciphertext = nonce + NONCE_SIZE;
    const size_t ciphertextSize = record.size() - 2 - NONCE_SIZE;

    SecureBuffer plaintext(ciphertextSize - TAG_SIZE);

    // Checks the authentication tag first; only if it matches is anything
    // written to the output.
    unsigned long long plaintextSize = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintextSize,
            nullptr,
            ciphertext, ciphertextSize,
            contextBytes.data(), contextBytes.size(),
            nonce, key.data()) != 0) {
        throw std::runtime_error(kCannotOpen);
    }

    return plaintext;
}

}   // namespace kythera::core
