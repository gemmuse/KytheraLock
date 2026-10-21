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
#ifndef IVAULTSTORAGE_H_
#define IVAULTSTORAGE_H_
#include <optional>
#include <string>
#include <vector>

/// One stored secret, exactly as it is kept: already encrypted.
struct SecretRecord {
    int id;
    int vaultId;
    std::string name;
    std::string nonce;
    std::string ciphertext;
    std::string encryptedKey;
    std::string encryptedKeyNonce;
};

/**
 * @brief What the vault logic needs from "somewhere to keep encrypted data".
 *
 * This interface is the boundary between the Core library (cryptography and
 * vault logic) and whatever stores the data. Core knows only this interface,
 * never SQL, SQLite or the network. Today it is implemented by the SQLite
 * VaultStorageLayer; a client could later implement it by talking to a server.
 *
 * Everything passed through here is already encrypted. Implementations never
 * see keys or plaintext.
 */
class IVaultStorage {
 public:
    virtual ~IVaultStorage() = default;

    /// Creates all required storage structures. Safe to call repeatedly.
    virtual void CreateSchema() = 0;

    /// Insert or update a meta key/value pair.
    virtual void SetMeta(const std::string& key,
                         const std::string& value) = 0;

    /// Retrieve a meta value, or std::nullopt if the key does not exist.
    virtual std::optional<std::string> GetMeta(const std::string& key) = 0;

    /// Insert a secret record (already encrypted).
    virtual void InsertSecretRecord(int vaultId,
                                    const std::string& name,
                                    const std::string& nonce,
                                    const std::string& ciphertext,
                                    const std::string& encryptedKey,
                                    const std::string& encryptedKeyNonce) = 0;

    /// Return all secret names in a vault.
    virtual std::vector<std::string> ListSecretNames(int vaultId) = 0;

    /// Return one secret record, or std::nullopt if it does not exist.
    virtual std::optional<SecretRecord> GetSecretRecord(
        int vaultId,
        const std::string& name) = 0;

    /// Create the single default vault (v1 has only one).
    virtual void CreateDefaultVault() = 0;
};

#endif  // IVAULTSTORAGE_H_
