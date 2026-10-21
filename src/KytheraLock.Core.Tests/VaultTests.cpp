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
#include <doctest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "CryptoEngine.h"
#include "TestSupport.h"
#include "Vault.h"

using kythera::core::CryptoEngine;
using kythera::core::Vault;

namespace {

// The vault stores its sealed record in the "ciphertext" column for now. The
// tests look at it there because they are checking what is kept on disk.
const int kVaultId = 1;

}   // namespace

TEST_CASE("Vault: a new database is not initialised until a vault is made") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);

    CHECK_FALSE(vault.IsInitialised());

    vault.InitialiseNewVault("password");

    CHECK(vault.IsInitialised());
    CHECK(storage.defaultVaultCreated);
}

TEST_CASE("Vault: creating a vault stores only the salt and verifier") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);

    vault.InitialiseNewVault("password");

    CHECK(storage.meta.count("kdf_salt") == 1);
    CHECK(storage.meta.count("kdf_verifier") == 1);
    CHECK(storage.meta.size() == 2);
}

TEST_CASE("Vault: a vault cannot be created twice") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");

    CHECK_THROWS_AS(vault.InitialiseNewVault("another"), std::runtime_error);
}

TEST_CASE("Vault: the right password unlocks and the wrong one does not") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");

    CHECK_THROWS_WITH_AS(vault.Unlock("wrong"), "Wrong password",
                         std::runtime_error);
    CHECK_THROWS_AS(vault.ListSecrets(), std::runtime_error);

    CHECK_NOTHROW(vault.Unlock("password"));
    CHECK_NOTHROW(vault.ListSecrets());
}

TEST_CASE("Vault: unlocking something that is not a vault fails") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);

    CHECK_THROWS_AS(vault.Unlock("password"), std::runtime_error);
}

TEST_CASE("Vault: a locked vault refuses every operation") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");

    CHECK_THROWS_WITH_AS(vault.AddSecret("a", "b"), "Vault is locked",
                         std::runtime_error);
    CHECK_THROWS_AS(vault.GetSecret("a"), std::runtime_error);
    CHECK_THROWS_AS(vault.ListSecrets(), std::runtime_error);
}

TEST_CASE("Vault: locking again refuses further access") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");
    vault.Unlock("password");
    vault.AddSecret("github", "my_password");

    vault.Lock();

    CHECK_THROWS_AS(vault.GetSecret("github"), std::runtime_error);

    vault.Unlock("password");
    CHECK(vault.GetSecret("github") == "my_password");
}

TEST_CASE("Vault: a secret can be stored and read back") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");
    vault.Unlock("password");

    vault.AddSecret("github", "my_password");
    vault.AddSecret("email", "another secret");

    CHECK(vault.GetSecret("github") == "my_password");
    CHECK(vault.GetSecret("email") == "another secret");

    auto names = vault.ListSecrets();
    REQUIRE(names.size() == 2);
    CHECK(names[0] == "email");
    CHECK(names[1] == "github");
}

TEST_CASE("Vault: asking for a secret that does not exist fails") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");
    vault.Unlock("password");

    CHECK_THROWS_WITH_AS(vault.GetSecret("missing"), "Secret not found",
                         std::runtime_error);
}

TEST_CASE("Vault: the stored secret is not readable") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");
    vault.Unlock("password");

    vault.AddSecret("github", "my_password");

    auto record = storage.GetSecretRecord(kVaultId, "github");
    REQUIRE(record.has_value());
    CHECK(record->ciphertext.find("my_password") == std::string::npos);
    CHECK(record->ciphertext != "my_password");
    CHECK_FALSE(record->ciphertext.empty());
}

TEST_CASE("Vault: the same secret stored twice looks different on disk") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");
    vault.Unlock("password");

    vault.AddSecret("first", "same value");
    vault.AddSecret("second", "same value");

    auto first = storage.GetSecretRecord(kVaultId, "first");
    auto second = storage.GetSecretRecord(kVaultId, "second");
    REQUIRE(first.has_value());
    REQUIRE(second.has_value());
    CHECK(first->ciphertext != second->ciphertext);
}

TEST_CASE("Vault: a damaged stored secret cannot be read") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");
    vault.Unlock("password");
    vault.AddSecret("github", "my_password");

    // Change one character in the middle of the stored record.
    auto& stored = storage.secrets.at({ kVaultId, "github" });
    size_t middle = stored.ciphertext.size() / 2;
    stored.ciphertext[middle] = (stored.ciphertext[middle] == 'A') ? 'B' : 'A';

    CHECK_THROWS_AS(vault.GetSecret("github"), std::runtime_error);
}

TEST_CASE("Vault: a secret copied under another name cannot be read") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    Vault vault(storage, crypto);
    vault.InitialiseNewVault("password");
    vault.Unlock("password");
    vault.AddSecret("cheap", "not important");
    vault.AddSecret("bank", "very important");

    // Someone with write access to the database copies one record over
    // another.
    storage.secrets.at({ kVaultId, "bank" }).ciphertext =
        storage.secrets.at({ kVaultId, "cheap" }).ciphertext;

    CHECK_THROWS_AS(vault.GetSecret("bank"), std::runtime_error);
    CHECK(vault.GetSecret("cheap") == "not important");
}

TEST_CASE("Vault: secrets stay readable across a lock and a new session") {
    InMemoryStorage storage;
    CryptoEngine crypto;
    {
        Vault vault(storage, crypto);
        vault.InitialiseNewVault("password");
        vault.Unlock("password");
        vault.AddSecret("github", "my_password");
    }

    Vault reopened(storage, crypto);
    CHECK(reopened.IsInitialised());
    reopened.Unlock("password");

    CHECK(reopened.GetSecret("github") == "my_password");
}
