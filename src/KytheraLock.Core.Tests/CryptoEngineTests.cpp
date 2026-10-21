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
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "CryptoEngine.h"
#include "SecureBuffer.h"

using kythera::core::CryptoEngine;
using kythera::core::SecureBuffer;

namespace {

using Bytes = std::vector<unsigned char>;

const char kCannotOpen[] = "Record could not be opened";

std::string AsString(const SecureBuffer& buffer) {
    return std::string(reinterpret_cast<const char*>(buffer.data()),
                       buffer.size());
}

SecureBuffer NewKey() {
    return SecureBuffer::Random(CryptoEngine::RECORD_KEY_SIZE);
}

CryptoEngine::RecordContext NewContext() {
    Bytes recordId = { 1, 2, 3, 4 };
    return { CryptoEngine::Purpose::SECRET, 1, recordId };
}

}   // namespace

// ---------------------------------------------------------------------------
// Sealing and opening records
// ---------------------------------------------------------------------------

TEST_CASE("Records: sealing then opening gives back the plaintext") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();

    auto record = crypto.Seal(key, std::string_view("hello world"), context);

    CHECK(AsString(crypto.Open(key, record, context)) == "hello world");
}

TEST_CASE("Records: the layout is version, algorithm, nonce, ciphertext+tag") {
    CryptoEngine crypto;
    auto key = NewKey();

    auto record = crypto.Seal(key, std::string_view("hello world"),
                              NewContext());

    CHECK(record.size() == CryptoEngine::RECORD_OVERHEAD + 11);
    CHECK(record[0] == CryptoEngine::RECORD_VERSION);
    CHECK(record[1] == CryptoEngine::ALGORITHM_XCHACHA20_POLY1305);
    CHECK(CryptoEngine::RECORD_OVERHEAD ==
          2 + CryptoEngine::NONCE_SIZE + CryptoEngine::TAG_SIZE);
}

TEST_CASE("Records: the plaintext does not appear in the record") {
    CryptoEngine crypto;
    auto key = NewKey();

    auto record = crypto.Seal(key, std::string_view("find me if you can"),
                              NewContext());

    std::string text(record.begin(), record.end());
    CHECK(text.find("find me") == std::string::npos);
}

TEST_CASE("Records: empty plaintext works") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();

    auto record = crypto.Seal(key, std::string_view(""), context);

    CHECK(record.size() == CryptoEngine::RECORD_OVERHEAD);
    CHECK(crypto.Open(key, record, context).empty());
}

TEST_CASE("Records: a large plaintext works") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();
    std::string big(1000000, 'x');

    auto record = crypto.Seal(key, big, context);

    CHECK(AsString(crypto.Open(key, record, context)) == big);
}

TEST_CASE("Records: sealing the same plaintext twice gives different records") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();

    std::set<Bytes> nonces;
    std::set<Bytes> records;
    for (int i = 0; i < 200; ++i) {
        auto record = crypto.Seal(key, std::string_view("same"), context);
        records.insert(record);
        nonces.insert(Bytes(record.begin() + 2,
                            record.begin() + 2 + CryptoEngine::NONCE_SIZE));
    }

    CHECK(nonces.size() == 200);
    CHECK(records.size() == 200);
}

// ---------------------------------------------------------------------------
// Things that must NOT open
// ---------------------------------------------------------------------------

TEST_CASE("Records: the wrong key cannot open a record") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto otherKey = NewKey();
    auto context = NewContext();
    auto record = crypto.Seal(key, std::string_view("secret"), context);

    CHECK_THROWS_WITH_AS(crypto.Open(otherKey, record, context), kCannotOpen,
                         std::runtime_error);
}

TEST_CASE("Records: any change to the context stops a record opening") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();
    auto record = crypto.Seal(key, std::string_view("secret"), context);

    SUBCASE("a different purpose") {
        auto wrong = context;
        wrong.purpose = CryptoEngine::Purpose::WRAPPED_VAULT_KEY;
        CHECK_THROWS_AS(crypto.Open(key, record, wrong), std::runtime_error);
    }

    SUBCASE("a different vault") {
        auto wrong = context;
        wrong.vaultId = 2;
        CHECK_THROWS_AS(crypto.Open(key, record, wrong), std::runtime_error);
    }

    SUBCASE("a different record id") {
        auto wrong = context;
        wrong.recordId = Bytes{ 1, 2, 3, 5 };
        CHECK_THROWS_AS(crypto.Open(key, record, wrong), std::runtime_error);
    }

    SUBCASE("a shorter record id") {
        auto wrong = context;
        wrong.recordId = Bytes{ 1, 2, 3 };
        CHECK_THROWS_AS(crypto.Open(key, record, wrong), std::runtime_error);
    }

    SUBCASE("a longer record id") {
        auto wrong = context;
        wrong.recordId = Bytes{ 1, 2, 3, 4, 0 };
        CHECK_THROWS_AS(crypto.Open(key, record, wrong), std::runtime_error);
    }

    SUBCASE("the unchanged context still works") {
        CHECK_NOTHROW(crypto.Open(key, record, context));
    }
}

TEST_CASE("Records: changing any single byte stops a record opening") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();
    auto record = crypto.Seal(key, std::string_view("tamper with me"),
                              context);

    int notRejected = 0;
    for (size_t i = 0; i < record.size(); ++i) {
        auto damaged = record;
        damaged[i] ^= 0x01;
        try {
            crypto.Open(key, damaged, context);
            ++notRejected;
        } catch (const std::runtime_error&) {
        }
    }

    CHECK(notRejected == 0);
}

TEST_CASE("Records: a shortened or extended record cannot be opened") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();
    auto record = crypto.Seal(key, std::string_view("truncate me"), context);

    int notRejected = 0;
    for (size_t length = 0; length < record.size(); ++length) {
        Bytes cut(record.begin(), record.begin() + length);
        try {
            crypto.Open(key, cut, context);
            ++notRejected;
        } catch (const std::runtime_error&) {
        }
    }
    CHECK(notRejected == 0);

    auto longer = record;
    longer.push_back(0);
    CHECK_THROWS_AS(crypto.Open(key, longer, context), std::runtime_error);
}

TEST_CASE("Records: an unknown version or algorithm cannot be opened") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();
    auto record = crypto.Seal(key, std::string_view("v"), context);

    auto badVersion = record;
    badVersion[0] = 2;
    auto badAlgorithm = record;
    badAlgorithm[1] = 2;

    CHECK_THROWS_AS(crypto.Open(key, badVersion, context), std::runtime_error);
    CHECK_THROWS_AS(crypto.Open(key, badAlgorithm, context),
                    std::runtime_error);
}

TEST_CASE("Records: every way of failing gives the same message") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto otherKey = NewKey();
    auto context = NewContext();
    auto record = crypto.Seal(key, std::string_view("msg"), context);

    auto wrongContext = context;
    wrongContext.vaultId = 9;
    auto damaged = record;
    damaged.back() ^= 1;
    auto badVersion = record;
    badVersion[0] = 9;
    Bytes tooShort = { 1 };

    CHECK_THROWS_WITH_AS(crypto.Open(otherKey, record, context), kCannotOpen,
                         std::runtime_error);
    CHECK_THROWS_WITH_AS(crypto.Open(key, record, wrongContext), kCannotOpen,
                         std::runtime_error);
    CHECK_THROWS_WITH_AS(crypto.Open(key, damaged, context), kCannotOpen,
                         std::runtime_error);
    CHECK_THROWS_WITH_AS(crypto.Open(key, badVersion, context), kCannotOpen,
                         std::runtime_error);
    CHECK_THROWS_WITH_AS(crypto.Open(key, tooShort, context), kCannotOpen,
                         std::runtime_error);
}

TEST_CASE("Records: a key of the wrong size is rejected") {
    CryptoEngine crypto;
    auto key = NewKey();
    auto context = NewContext();
    auto record = crypto.Seal(key, std::string_view("x"), context);

    auto shortKey = SecureBuffer::Random(16);
    SecureBuffer emptyKey;

    CHECK_THROWS_AS(crypto.Seal(shortKey, std::string_view("x"), context),
                    std::invalid_argument);
    CHECK_THROWS_AS(crypto.Seal(emptyKey, std::string_view("x"), context),
                    std::invalid_argument);
    CHECK_THROWS_AS(crypto.Open(shortKey, record, context),
                    std::invalid_argument);
}

// ---------------------------------------------------------------------------
// Keys from passwords
// ---------------------------------------------------------------------------

TEST_CASE("Keys: the same password and salt always give the same key") {
    CryptoEngine crypto;

    auto bundle = crypto.CreateKDFBundle("correct horse");
    auto again = crypto.DeriveMasterKey("correct horse", bundle.salt);

    REQUIRE(bundle.masterKey.size() == CryptoEngine::MASTER_KEY_SIZE);
    CHECK(std::memcmp(again.data(), bundle.masterKey.data(),
                      CryptoEngine::MASTER_KEY_SIZE) == 0);
}

TEST_CASE("Keys: a different password gives a different key") {
    CryptoEngine crypto;

    auto bundle = crypto.CreateKDFBundle("correct horse");
    auto wrong = crypto.DeriveMasterKey("wrong horse", bundle.salt);

    CHECK(std::memcmp(wrong.data(), bundle.masterKey.data(),
                      CryptoEngine::MASTER_KEY_SIZE) != 0);
}

TEST_CASE("Keys: each new vault gets a different salt") {
    CryptoEngine crypto;

    auto first = crypto.CreateKDFBundle("same password");
    auto second = crypto.CreateKDFBundle("same password");

    CHECK_FALSE((first.salt == second.salt));
    CHECK(std::memcmp(first.masterKey.data(), second.masterKey.data(),
                      CryptoEngine::MASTER_KEY_SIZE) != 0);
}

TEST_CASE("Keys: the verifier matches the key it came from, and no other") {
    CryptoEngine crypto;

    auto bundle = crypto.CreateKDFBundle("correct horse");
    auto wrong = crypto.DeriveMasterKey("wrong horse", bundle.salt);

    CHECK(crypto.EqualsConstantTime(crypto.ComputeVerifier(bundle.masterKey),
                                    bundle.verifier));
    CHECK_FALSE(crypto.EqualsConstantTime(crypto.ComputeVerifier(wrong),
                                          bundle.verifier));
}

TEST_CASE("Keys: a salt of the wrong size is rejected") {
    CryptoEngine crypto;
    Bytes badSalt(8, 0);

    CHECK_THROWS_AS(crypto.DeriveMasterKey("password", badSalt),
                    std::runtime_error);
}

TEST_CASE("Keys: a derived master key can seal and open records") {
    CryptoEngine crypto;
    auto context = NewContext();

    auto bundle = crypto.CreateKDFBundle("correct horse");
    auto derived = crypto.DeriveMasterKey("correct horse", bundle.salt);
    auto record = crypto.Seal(derived, std::string_view("via master key"),
                              context);

    CHECK(AsString(crypto.Open(bundle.masterKey, record, context)) ==
          "via master key");
}

// ---------------------------------------------------------------------------
// Base64 and comparison helpers
// ---------------------------------------------------------------------------

TEST_CASE("Base64: encoding then decoding gives back the bytes") {
    CryptoEngine crypto;
    Bytes bytes = { 0, 1, 2, 250, 251, 252, 253, 254, 255 };

    auto text = crypto.B64Encode(bytes);

    CHECK((crypto.B64Decode(text) == bytes));
}

TEST_CASE("Base64: invalid text is rejected") {
    CryptoEngine crypto;

    CHECK_THROWS_AS(crypto.B64Decode("not*base64!"), std::runtime_error);
}

TEST_CASE("EqualsConstantTime: compares contents and length") {
    CryptoEngine crypto;
    Bytes a = { 1, 2, 3 };
    Bytes same = { 1, 2, 3 };
    Bytes different = { 1, 2, 4 };
    Bytes shorter = { 1, 2 };

    CHECK(crypto.EqualsConstantTime(a, same));
    CHECK_FALSE(crypto.EqualsConstantTime(a, different));
    CHECK_FALSE(crypto.EqualsConstantTime(a, shorter));
}
