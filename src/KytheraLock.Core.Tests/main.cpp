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
// Test runner. doctest generates everything else; the only job here is to
// initialise libsodium once before any test runs.
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest.h>

#include "CryptoEngine.h"

int main(int argc, char** argv) {
    kythera::core::CryptoEngine().Initialize();

    doctest::Context context;
    context.applyCommandLine(argc, argv);
    return context.run();
}
