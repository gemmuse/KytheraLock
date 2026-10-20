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
#ifndef VERSION_H_
#define VERSION_H_

#include <string>
#include <tuple>
#include <optional>

namespace Version {

constexpr int MAJOR = 0;
constexpr int MINOR = 1;
constexpr int PATCH = 0;

// Use std::optional instead of None
// constexpr std::optional<const char*> PRE_RELEASE = "Dev Build #1";
constexpr std::optional<const char*> PRE_RELEASE = std::nullopt;

// Version tuple for comparisons
constexpr auto VERSION = std::make_tuple(MAJOR, MINOR, PATCH, PRE_RELEASE);

inline std::string ToString() {
    std::string version = "V" +
        std::to_string(MAJOR) + "." +
        std::to_string(MINOR) + "." +
        std::to_string(PATCH);

    if (PRE_RELEASE.has_value()) {
        version += "-";
        version += PRE_RELEASE.value();
    }

    return version;
}

}   // namespace Version

#endif  // VERSION_H_
