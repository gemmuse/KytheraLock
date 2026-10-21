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
#ifndef TESTSUPPORT_H_
#define TESTSUPPORT_H_
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "IVaultStorage.h"

/**
 * @brief An IVaultStorage that keeps everything in memory.
 *
 * Lets the vault logic be tested without a database. The maps are public so a
 * test can look at exactly what the vault stored, or tamper with it.
 */
class InMemoryStorage : public kythera::core::IVaultStorage {
 public:
    std::map<std::string, std::string> meta;
    std::map<std::pair<int, std::string>, kythera::core::SecretRecord> secrets;
    bool defaultVaultCreated{ false };

    void CreateSchema() override {}

    void SetMeta(const std::string& key, const std::string& value) override {
        meta[key] = value;
    }

    std::optional<std::string> GetMeta(const std::string& key) override {
        auto found = meta.find(key);
        if (found == meta.end())
            return std::nullopt;
        return found->second;
    }

    void InsertSecretRecord(int vaultId,
                            const std::string& name,
                            const std::string& nonce,
                            const std::string& ciphertext,
                            const std::string& encryptedKey,
                            const std::string& encryptedKeyNonce) override {
        auto key = std::make_pair(vaultId, name);
        if (secrets.count(key) > 0)
            throw std::runtime_error("duplicate secret");

        kythera::core::SecretRecord record{ nextId_++, vaultId, name, nonce,
                                            ciphertext, encryptedKey,
                                            encryptedKeyNonce };
        secrets.emplace(key, record);
    }

    std::vector<std::string> ListSecretNames(int vaultId) override {
        std::vector<std::string> names;
        for (const auto& entry : secrets) {
            if (entry.first.first == vaultId)
                names.push_back(entry.first.second);
        }
        return names;
    }

    std::optional<kythera::core::SecretRecord> GetSecretRecord(
        int vaultId,
        const std::string& name) override {
        auto found = secrets.find(std::make_pair(vaultId, name));
        if (found == secrets.end())
            return std::nullopt;
        return found->second;
    }

    void CreateDefaultVault() override { defaultVaultCreated = true; }

 private:
    int nextId_{ 1 };
};

#endif  // TESTSUPPORT_H_
