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

#include <cstring>
#include <utility>

#include "SecureBuffer.h"

using kythera::core::SecureBuffer;

TEST_CASE("SecureBuffer: a new buffer is filled with zeros") {
    SecureBuffer buffer(16);

    REQUIRE(buffer.size() == 16);
    bool allZero = true;
    for (size_t i = 0; i < buffer.size(); ++i)
        allZero = allZero && (buffer.data()[i] == 0);
    CHECK(allZero);
}

TEST_CASE("SecureBuffer: a default or zero-size buffer is empty") {
    SecureBuffer defaultBuffer;
    SecureBuffer zeroBuffer(0);

    CHECK(defaultBuffer.empty());
    CHECK(defaultBuffer.data() == nullptr);
    CHECK(zeroBuffer.empty());
    CHECK(zeroBuffer.data() == nullptr);
}

TEST_CASE("SecureBuffer: Random gives different bytes each time") {
    SecureBuffer first = SecureBuffer::Random(32);
    SecureBuffer second = SecureBuffer::Random(32);

    REQUIRE(first.size() == 32);
    REQUIRE(second.size() == 32);
    CHECK(std::memcmp(first.data(), second.data(), 32) != 0);
}

TEST_CASE("SecureBuffer: CopyOf holds a copy of the bytes") {
    unsigned char source[4] = { 9, 8, 7, 6 };

    SecureBuffer copy = SecureBuffer::CopyOf(source, 4);
    source[0] = 0;

    REQUIRE(copy.size() == 4);
    CHECK(copy.data()[0] == 9);
    CHECK(copy.data()[3] == 6);
}

TEST_CASE("SecureBuffer: moving transfers ownership") {
    unsigned char source[3] = { 1, 2, 3 };
    SecureBuffer original = SecureBuffer::CopyOf(source, 3);
    const unsigned char* memory = original.data();

    SecureBuffer moved = std::move(original);

    CHECK(original.empty());
    CHECK(original.data() == nullptr);
    CHECK(moved.size() == 3);
    CHECK(moved.data() == memory);

    SecureBuffer assigned;
    assigned = std::move(moved);

    CHECK(moved.empty());
    CHECK(assigned.size() == 3);
    CHECK(assigned.data() == memory);
}

TEST_CASE("SecureBuffer: assigning an empty buffer releases the memory") {
    SecureBuffer buffer = SecureBuffer::Random(32);

    buffer = SecureBuffer();

    CHECK(buffer.empty());
    CHECK(buffer.data() == nullptr);
}
