/*
This source file is part of Kythera Lock
For the latest info, see https ://github.com/SwatKat1977/KytheraLock

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
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "Vault.h"

Vault::Vault(VaultStorageLayer& storage, CryptoEngine& crypto)
    : storage_(storage), crypto_(crypto) {
}

bool Vault::IsInitialised() {
    // The tables must exist before we can look inside them. CreateSchema
    // is safe to call repeatedly (CREATE TABLE IF NOT EXISTS).
    storage_.CreateSchema();
    return storage_.GetMeta("kdf_salt").has_value() &&
           storage_.GetMeta("kdf_verifier").has_value();
}

void Vault::InitialiseNewVault(const std::string& password) {
    storage_.CreateSchema();

    // If salt already exists, vault is already initialized - bail out early.
    if (storage_.GetMeta("kdf_salt").has_value() ||
        storage_.GetMeta("kdf_verifier").has_value()) {
        throw std::runtime_error("Vault already initialised");
    }

    // Create vault row only once we know we're initializing fresh.
    storage_.CreateDefaultVault();

    auto bundle = crypto_.CreateKDFBundle(password);

    storage_.SetMeta("kdf_salt", crypto_.B64Encode(bundle.salt));
    storage_.SetMeta("kdf_verifier", crypto_.B64Encode(bundle.verifier));

    unlocked_ = false;
}

void Vault::Unlock(const std::string& password) {
    // HOW UNLOCKING WORKS
    //   1. Load the stored salt and verifier from the database.
    //   2. Re-derive a key from the typed password + the stored salt.
    //   3. Fingerprint that key and compare it with the stored verifier.
    //   4. Same fingerprint => right password. Keep the key in memory.
    //      Different fingerprint => wrong password. Discard everything.
    // The password itself and the master key are never written to disk.
    auto saltText = storage_.GetMeta("kdf_salt");
    auto verifierText = storage_.GetMeta("kdf_verifier");

    if (!saltText || !verifierText) {
        throw std::runtime_error("Not a vault or not initialized");
    }

    auto salt = crypto_.B64Decode(*saltText);
    auto storedVerifier = crypto_.B64Decode(*verifierText);

    auto derivedKey = crypto_.DeriveMasterKey(password, salt);
    auto computedVerifier = crypto_.ComputeVerifier(derivedKey);

    if (!crypto_.EqualsConstantTime(computedVerifier, storedVerifier)) {
        throw std::runtime_error("Wrong password");
    }

    masterKey_ = std::move(derivedKey);
    unlocked_ = true;
}

void Vault::Lock() {
    // Locking = forgetting the key. sodium_memzero overwrites the bytes with
    // zeros; a plain clear() could leave the key sitting in memory (and the
    // compiler is allowed to optimise away a "pointless" ordinary wipe).
    if (!masterKey_.empty()) {
        sodium_memzero(masterKey_.data(), masterKey_.size());
        masterKey_.clear();
    }

    unlocked_ = false;
}

void Vault::RequireUnlocked() const {
    if (!unlocked_)
        throw std::runtime_error("Vault is locked");
}

void Vault::AddSecret(const std::string& name,
                      const std::string& plaintext) {
    RequireUnlocked();

    // Stub encryption
    // In reality this will use "envelope encryption":
    //  - Generate a fresh random data key just for this secret
    //  - Encrypt the plaintext with that data key
    //  - Wrap (encrypt) the data key with the vault key, and store the
    //    wrapped key beside the secret (the encrypted_secret_key columns)

    auto encrypted = crypto_.Encrypt(plaintext);

    std::string fake_encrypted_key = "encrypted_key_stub";
    std::string fake_encrypted_key_nonce = "key_nonce_stub";

    storage_.InsertSecretRecord(vaultId_,
                                name,
                                encrypted.nonce,
                                encrypted.ciphertext,
                                fake_encrypted_key,
                                fake_encrypted_key_nonce);
}

std::string Vault::GetSecret(const std::string& name) {
    RequireUnlocked();

    auto recordOpt = storage_.GetSecretRecord(vaultId_, name);

    if (!recordOpt)
        throw std::runtime_error("Secret not found");

    CryptoEngine::EncryptedBlob blob;
    blob.nonce = recordOpt->nonce;
    blob.ciphertext = recordOpt->ciphertext;

    return crypto_.Decrypt(blob);
}

std::vector<std::string> Vault::ListSecrets() {
    RequireUnlocked();
    return storage_.ListSecretNames(vaultId_);
}
