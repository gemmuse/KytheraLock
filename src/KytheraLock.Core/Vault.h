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
#ifndef VAULT_H_
#define VAULT_H_
#include <string>
#include <vector>
#include "CryptoEngine.h"
#include "IVaultStorage.h"

namespace kythera::core {

/**
 * @brief High-level vault domain logic.
 *
 * The Vault class coordinates:
 *  - Lock/unlock state
 *  - Business logic
 *  - Calls into VaultStorage
 *
 * It does NOT directly perform SQL.
 * It does NOT yet perform crypto (stubbed for now).
 */
class Vault {
 public:
    explicit Vault(IVaultStorage& storage, CryptoEngine& crypto);

    /// True if a vault has already been created in this database
    bool IsInitialised();

    /// Create schema and initialize vault
    void InitialiseNewVault(const std::string& password);

    /// Unlock vault (stub for now)
    void Unlock(const std::string& password);

    /// Lock vault
    void Lock();

    /// Add a secret - plaintext for now... crypto comes later
    void AddSecret(const std::string& name, const std::string& plaintext);

    std::string GetSecret(const std::string& name);

    /// List all secret names
    std::vector<std::string> ListSecrets();

 private:
    void RequireUnlocked() const;

    IVaultStorage& storage_;
    CryptoEngine& crypto_;
    bool unlocked_{ false };
    int vaultId_{ 1 };  // v1: single vault
    SecureBuffer masterKey_;
};

}   // namespace kythera::core

#endif  // VAULT_H_
