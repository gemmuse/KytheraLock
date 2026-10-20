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
#ifndef VAULTSTORAGELAYER_H_
#define VAULTSTORAGELAYER_H_
#include <optional>
#include <string>
#include <vector>
#include "SqliteDatabase.h"

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
 * @brief Provides storage operations for the vault database.
 *
 * VaultStorage is responsible for:
 *  - Creating the database schema
 *  - Storing and retrieving data
 *
 * It does NOT:
 *  - Perform cryptographic operations
 *  - Manage database file ownership
 */
class VaultStorageLayer {
 public:
    explicit VaultStorageLayer(SqliteDatabase& db);

    /**
     * @brief Creates all required database tables.
     *
     * Safe to call once when initializing a new vault.
     */
    void CreateSchema();

    /**
     * @brief Insert or update a meta key/value pair.
     */
    void SetMeta(const std::string& key, const std::string& value);

    /**
     * @brief Retrieve a meta value.
     *
     * Returns std::nullopt if the key does not exist.
     */
    std::optional<std::string> GetMeta(const std::string& key);

    /**
     * @brief Insert a secret record (already encrypted).
     *
     * This method assumes all crypto has already happened.
     */
    void InsertSecretRecord(int vaultId,
                            const std::string& name,
                            const std::string& nonce,
                            const std::string& ciphertext,
                            const std::string& encryptedKey,
                            const std::string& encryptedKeyNonce);

    /**
     * @brief Return all secret names in a vault.
     */
    std::vector<std::string> ListSecretNames(int vaultId);

    std::optional<SecretRecord> GetSecretRecord(int vaultId,
                                                const std::string& name);

    void CreateDefaultVault();

 private:
    SqliteDatabase& db_;
};

#endif  // VAULTSTORAGELAYER_H_
