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
#include <iostream>
#include "SqliteDatabase.h"
#include "Vault.h"
#include "VaultStorageLayer.h"
#include "CryptoEngine.h"
#include "Version.h"


int main(int argc, char* argv[]) {
    kythera::server::SqliteDatabase db("vault.db");
    kythera::server::VaultStorageLayer storage(db);
    kythera::core::CryptoEngine cryptoEngine;
    kythera::core::Vault vault(storage, cryptoEngine);

    std::cout << "Version " << kythera::server::version::ToString() << std::endl;

    cryptoEngine.Initialize();

    try {
        // Only create the vault the first time the program runs.
        if (!vault.IsInitialised()) {
            vault.InitialiseNewVault("Password");
        }

        vault.Unlock("Password");

        vault.AddSecret("github", "my_password");

        auto names = vault.ListSecrets();

        for (const auto& name : names) {
            std::cout << "Secret: " << name << "\n";
        }

        std::cout << vault.GetSecret("github") << "\n";

        vault.Lock();

        std::cout << vault.GetSecret("github") << "\n";
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
    }

    return 0;
}
