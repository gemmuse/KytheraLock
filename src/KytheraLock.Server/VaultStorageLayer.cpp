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
#include <stdexcept>
#include <string>
#include <vector>
#include "VaultStorageLayer.h"
#include "Statement.h"


VaultStorageLayer::VaultStorageLayer(SqliteDatabase& db) : db_(db) {
}

// Database layout, one table per idea:
//   meta       - small settings, e.g. the salt and verifier used for unlocking
//   users      - PLANNED, not used yet: each user's public key plus their
//                private key (stored encrypted). For sharing vaults later.
//   vaults     - a named collection of secrets (v1 has just one)
//   vault_keys - PLANNED, not used yet: the vault's key, encrypted once per
//                user, so each user can open it with their own key
//   secrets    - the stored items. Each has its own encrypted data key
//                (encrypted_secret_key); nonce columns hold the one-time
//                random value each encryption needs.
void VaultStorageLayer::CreateSchema() {
    db_.Exec(R"sql(CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,
                                                    value TEXT NOT NULL);
                  )sql");

    db_.Exec(R"sql(CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            public_key TEXT NOT NULL,
            enc_private_key TEXT NOT NULL,
            priv_nonce TEXT NOT NULL);)sql");

    db_.Exec(R"sql(CREATE TABLE IF NOT EXISTS vaults (id INTEGER PRIMARY KEY,
                                                      name TEXT NOT NULL);
            )sql");

    db_.Exec(R"sql(CREATE TABLE IF NOT EXISTS vault_keys (
                vault_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                encrypted_vault_key TEXT NOT NULL,
                nonce TEXT NOT NULL,
                FOREIGN KEY (vault_id) REFERENCES vaults(id),
                FOREIGN KEY (user_id) REFERENCES users(id));)sql");

    db_.Exec(R"sql(CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            vault_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            encrypted_secret_key TEXT NOT NULL,
            encrypted_secret_key_nonce TEXT NOT NULL,
            UNIQUE(vault_id, name),
            FOREIGN KEY (vault_id) REFERENCES vaults(id));)sql");
}

void VaultStorageLayer::SetMeta(const std::string& key,
                                const std::string& value) {
    Statement statement(
        db_.Handle(),
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value");

    statement.BindText(1, key);
    statement.BindText(2, value);
    statement.Step();
}

std::optional<std::string> VaultStorageLayer::GetMeta(const std::string& key) {
    Statement statement(
        db_.Handle(),
        "SELECT value FROM meta WHERE key=?");

    statement.BindText(1, key);

    if (!statement.Step())
        return std::nullopt;

    return statement.ColumnText(0);
}

void VaultStorageLayer::InsertSecretRecord(
    int vaultId,
    const std::string& name,
    const std::string& nonce,
    const std::string& ciphertext,
    const std::string& encryptedKey,
    const std::string& encryptedKeyNonce) {
    Statement statement(
        db_.Handle(),
        "INSERT INTO secrets "
        "(vault_id, name, nonce, ciphertext, "
        " encrypted_secret_key, encrypted_secret_key_nonce) "
        "VALUES (?, ?, ?, ?, ?, ?)");

    statement.BindInt(1, vaultId);
    statement.BindText(2, name);
    statement.BindText(3, nonce);
    statement.BindText(4, ciphertext);
    statement.BindText(5, encryptedKey);
    statement.BindText(6, encryptedKeyNonce);

    statement.Step();
}

std::vector<std::string>
VaultStorageLayer::ListSecretNames(int vaultId) {
    Statement statement(
        db_.Handle(),
        "SELECT name FROM secrets WHERE vault_id=? ORDER BY name");

    statement.BindInt(1, vaultId);

    std::vector<std::string> results;

    while (statement.Step()) {
        results.push_back(statement.ColumnText(0));
    }

    return results;
}

std::optional<SecretRecord> VaultStorageLayer::GetSecretRecord(
    int vaultId,
    const std::string& name) {
    Statement statement(
        db_.Handle(),
        "SELECT id, vault_id, name, nonce, ciphertext, "
        "encrypted_secret_key, encrypted_secret_key_nonce "
        "FROM secrets "
        "WHERE vault_id=? AND name=?");

    statement.BindInt(1, vaultId);
    statement.BindText(2, name);

    if (!statement.Step())
        return std::nullopt;

    SecretRecord record;
    record.id = statement.ColumnInt(0);
    record.vaultId = statement.ColumnInt(1);
    record.name = statement.ColumnText(2);
    record.nonce = statement.ColumnText(3);
    record.ciphertext = statement.ColumnText(4);
    record.encryptedKey = statement.ColumnText(5);
    record.encryptedKeyNonce = statement.ColumnText(6);

    return record;
}

void VaultStorageLayer::CreateDefaultVault() {
    Statement statement(
        db_.Handle(),
        "INSERT OR IGNORE INTO vaults (id, name) VALUES (1, 'Default Vault')");

    statement.Step();
}
