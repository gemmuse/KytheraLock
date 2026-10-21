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
#include "Vault.h"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace kythera::core {

namespace {

// Where a secret belongs, mixed into its encryption (see CryptoEngine.h).
// Interim: the secret's name stands in for the record id.
CryptoEngine::RecordContext SecretContext(int vaultId,
                                          const std::string& name) {
    return { CryptoEngine::Purpose::SECRET,
             static_cast<std::uint64_t>(vaultId),
             std::vector<unsigned char>(name.begin(), name.end()) };
}

}   // namespace

Vault::Vault(IVaultStorage& storage, CryptoEngine& crypto)
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
    // Locking = forgetting the key. Replacing the buffer with an empty one
    // destroys the old one, and a SecureBuffer overwrites its memory with
    // zeros when it is destroyed (a plain clear() on a vector would not).
    masterKey_ = SecureBuffer();

    unlocked_ = false;
}

void Vault::RequireUnlocked() const {
    if (!unlocked_)
        throw std::runtime_error("Vault is locked");
}

void Vault::AddSecret(const std::string& name,
                      const std::string& plaintext) {
    RequireUnlocked();

    // INTERIM DESIGN. The secret is sealed straight into one record using the
    // master key, and the record is kept (as base64 text) in the ciphertext
    // column. The other three columns are unused for now and left empty.
    //
    // The final design (D1, D18) is "envelope encryption":
    //  - Generate a fresh random data key just for this secret
    //  - Seal the plaintext with that data key
    //  - Wrap (seal) the data key with the vault key, and store the wrapped
    //    key beside the secret
    // and the record id will be a random id made by the client. Until that
    // exists, the secret's name (unique within a vault) stands in for it.
    auto record = crypto_.Seal(masterKey_, plaintext,
                               SecretContext(vaultId_, name));

    storage_.InsertSecretRecord(vaultId_,
                                name,
                                "",
                                crypto_.B64Encode(record),
                                "",
                                "");
}

std::string Vault::GetSecret(const std::string& name) {
    RequireUnlocked();

    auto recordOpt = storage_.GetSecretRecord(vaultId_, name);

    if (!recordOpt)
        throw std::runtime_error("Secret not found");

    auto record = crypto_.B64Decode(recordOpt->ciphertext);
    auto plaintext = crypto_.Open(masterKey_, record,
                                  SecretContext(vaultId_, name));

    return std::string(reinterpret_cast<const char*>(plaintext.data()),
                       plaintext.size());
}

std::vector<std::string> Vault::ListSecrets() {
    RequireUnlocked();
    return storage_.ListSecretNames(vaultId_);
}

}   // namespace kythera::core
