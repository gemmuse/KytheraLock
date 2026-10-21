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
#include "IVaultStorage.h"
#include "SqliteDatabase.h"

namespace kythera::server {

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
 *
 * This is the SQLite implementation of the IVaultStorage interface that the
 * Core library depends on.
 */
class VaultStorageLayer : public core::IVaultStorage {
 public:
    explicit VaultStorageLayer(SqliteDatabase& db);

    /**
     * @brief Creates all required database tables.
     *
     * Safe to call once when initializing a new vault.
     */
    void CreateSchema() override;

    /**
     * @brief Insert or update a meta key/value pair.
     */
    void SetMeta(const std::string& key, const std::string& value) override;

    /**
     * @brief Retrieve a meta value.
     *
     * Returns std::nullopt if the key does not exist.
     */
    std::optional<std::string> GetMeta(const std::string& key) override;

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
                            const std::string& encryptedKeyNonce) override;

    /**
     * @brief Return all secret names in a vault.
     */
    std::vector<std::string> ListSecretNames(int vaultId) override;

    std::optional<core::SecretRecord> GetSecretRecord(
        int vaultId,
        const std::string& name) override;

    void CreateDefaultVault() override;

 private:
    SqliteDatabase& db_;
};

}   // namespace kythera::server

#endif  // VAULTSTORAGELAYER_H_
