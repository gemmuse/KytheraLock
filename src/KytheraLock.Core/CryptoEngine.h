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
#include <sodium.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "SecureBuffer.h"

namespace kythera::core {

/**
 * @brief Cryptographic operations for the vault.
 *
 * This class:
 *  - Derives keys from a password (Argon2id)
 *  - Seals data into a self-describing, authenticated record (XChaCha20-
 *    Poly1305) and opens it again
 *
 * Call Initialize() once at program start, before anything else.
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
        SecureBuffer masterKey;                // 32 bytes - NEVER store this
        std::vector<unsigned char> verifier;   // 32 bytes - store this
    };

    // Call once at program start
    void Initialize();

    // Init flow: create salt, derive master key, compute verifier
    KDFBundle CreateKDFBundle(const std::string& password) const;

    // Unlock flow: derive master key from password + salt, compute verifier
    SecureBuffer DeriveMasterKey(
        const std::string& password,
        const std::vector<unsigned char>& salt) const;

    std::vector<unsigned char> ComputeVerifier(
        const SecureBuffer& masterKey) const;

    // helpers for storing binary in TEXT columns
    std::string B64Encode(const std::vector<unsigned char>& bytes) const;
    std::vector<unsigned char> B64Decode(std::string_view text) const;

    // Compare two byte arrays in "constant time" - see the .cpp file for why
    // this matters. Always use this (never ==) when comparing secrets.
    bool EqualsConstantTime(const std::vector<unsigned char>& a,
                            const std::vector<unsigned char>& b) const;

    // ------------------------------------------------------------------
    // RECORDS (design document, D18)
    //
    // Everything stored in locked form is one "record", a single block of
    // bytes laid out as:
    //
    //   [ version ][ algorithm ][ nonce ][ ciphertext + authentication tag ]
    //     1 byte      1 byte     24 bytes    plaintext size + 16 bytes
    //
    // The nonce, algorithm and version travel with the data, so a record
    // can always be opened later without any other columns.
    //
    // WHAT IS "CONTEXT"? Where a record belongs (which vault, what kind of
    // record, which record) is mixed into the encryption as "additional
    // authenticated data". It is not stored in the record; the caller works
    // it out again when opening. If a record is copied to a different place,
    // or is used as the wrong kind of record, the context no longer matches
    // and opening it fails, instead of quietly giving back the wrong thing.
    // ------------------------------------------------------------------

    // Version of the record layout described above.
    static constexpr unsigned char RECORD_VERSION = 1;

    // Identifies the cipher: 1 = XChaCha20-Poly1305.
    static constexpr unsigned char ALGORITHM_XCHACHA20_POLY1305 = 1;

    // Size in bytes of the key used to seal and open records.
    static constexpr size_t RECORD_KEY_SIZE =
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES;

    // Size in bytes of the random nonce stored in every record.
    static constexpr size_t NONCE_SIZE =
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    // Size in bytes of the authentication tag added to every ciphertext.
    static constexpr size_t TAG_SIZE =
        crypto_aead_xchacha20poly1305_ietf_ABYTES;

    // Bytes a record adds on top of the plaintext: the two header bytes, the
    // nonce and the tag.
    static constexpr size_t RECORD_OVERHEAD = 2 + NONCE_SIZE + TAG_SIZE;

    // What kind of thing a record is. Part of the context, so a record of
    // one kind can never be passed off as another.
    enum class Purpose : unsigned char {
        SECRET = 1,
        WRAPPED_SECRET_KEY = 2,
        WRAPPED_VAULT_KEY = 3
    };

    // Where a record belongs. The same context must be given to Seal and to
    // Open.
    struct RecordContext {
        Purpose purpose;
        std::uint64_t vaultId;
        std::vector<unsigned char> recordId;
    };

    // Locks plaintext into a record. A new random nonce is used every time,
    // so sealing the same plaintext twice gives two different records.
    std::vector<unsigned char> Seal(const SecureBuffer& key,
                                    const unsigned char* plaintext,
                                    size_t plaintextSize,
                                    const RecordContext& context) const;

    std::vector<unsigned char> Seal(const SecureBuffer& key,
                                    std::string_view plaintext,
                                    const RecordContext& context) const;

    // Unlocks a record and returns the plaintext (held in secure memory).
    // Throws std::runtime_error if the record cannot be opened: wrong key,
    // wrong context, damaged or truncated data, or an unknown version or
    // algorithm. The message never says which, on purpose.
    SecureBuffer Open(const SecureBuffer& key,
                      const std::vector<unsigned char>& record,
                      const RecordContext& context) const;

 private:
    // Builds the bytes mixed into the encryption (see "WHAT IS CONTEXT").
    // The fields have fixed sizes or a length in front, so two different
    // contexts can never produce the same bytes. The version and algorithm
    // are included so they cannot be altered without being noticed.
    static std::vector<unsigned char> BuildContextBytes(
        const RecordContext& context);
};

}   // namespace kythera::core

#endif  // CRYPTOENGINE_H_
