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
#ifndef CRYPTOENGINE_H_
#define CRYPTOENGINE_H_
#include <string>
#include <string_view>
#include <vector>
#include "sodium.h"

/**
 * @brief Cryptographic operations for the vault.
 *
 * This class will eventually:
 *  - Derive keys
 *  - Encrypt secrets
 *  - Decrypt secrets
 *
 * Currently stubbed for integration testing.
 */
class CryptoEngine {
 public:
    // THE BIG PICTURE: how a password becomes something we can check
    //
    //   password + salt --(slow scramble, Argon2id)--> master key
    //   master key      --(one-way hash)-----------> verifier
    //
    // The password is something a human can remember, but it is weak: there
    // are far fewer likely passwords than possible 32-byte keys. So we turn
    // it into a proper key (the "master key") using a deliberately slow
    // process.
    //
    // What is stored in the database, and what is not:
    //   salt      - STORED. Not secret. Just makes every vault's key unique.
    //   verifier  - STORED. A fingerprint of the key, used to check the
    //               password. It cannot be reversed to get the key back.
    //   masterKey - NEVER STORED. Re-created from the password every unlock
    //               and wiped from memory when the vault is locked.

    // Size in bytes of the random salt (16 bytes = 128 bits).
    static constexpr size_t SALT_SIZE = 16;
    // Size in bytes of the master key (32 bytes = 256 bits, the size
    // expected by modern symmetric ciphers).
    static constexpr size_t MASTER_KEY_SIZE = 32;
    // Size in bytes of the verifier (the stored fingerprint of the key).
    static constexpr size_t VERIFIER_SIZE = 32;

    // Key Derivation Function (KDF) bundle containing all necessary components
    // for vault unlocking.
    struct KDFBundle {
        std::vector<unsigned char> salt;       // 16 bytes - store this
        std::vector<unsigned char> masterKey;  // 32 bytes - NEVER store this
        std::vector<unsigned char> verifier;   // 32 bytes - store this
    };

    // Call once at program start
    void Initialize();

    // Init flow: create salt, derive master key, compute verifier
    KDFBundle CreateKDFBundle(const std::string& password) const;

    // Unlock flow: derive master key from password + salt, compute verifier
    std::vector<unsigned char> DeriveMasterKey(
        const std::string& password,
        const std::vector<unsigned char>& salt) const;

    std::vector<unsigned char> ComputeVerifier(
        const std::vector<unsigned char>& masterKey) const;

    // helpers for storing binary in TEXT columns
    std::string B64Encode(const std::vector<unsigned char>& bytes) const;
    std::vector<unsigned char> B64Decode(std::string_view text) const;

    // Compare two byte arrays in "constant time" - see the .cpp file for why
    // this matters. Always use this (never ==) when comparing secrets.
    bool EqualsConstantTime(const std::vector<unsigned char>& a,
                            const std::vector<unsigned char>& b) const;

    struct EncryptedBlob {
        std::string nonce;
        std::string ciphertext;
    };

    EncryptedBlob Encrypt(const std::string& plaintext);
    std::string Decrypt(const EncryptedBlob& blob);
};

#endif  // CRYPTOENGINE_H_
