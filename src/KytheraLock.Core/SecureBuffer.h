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
#ifndef SECUREBUFFER_H_
#define SECUREBUFFER_H_
#include <cstddef>

namespace kythera::core {

/**
 * @brief A block of memory for key material and other secrets.
 *
 * Unlike a std::vector, the memory comes from libsodium's sodium_malloc:
 *  - it is locked so the operating system will not write it to the swap file
 *  - it has guard pages around it, so an overrun or underrun crashes at once
 *    instead of quietly reading or damaging neighbouring memory
 *  - it is overwritten with zeros when the buffer is destroyed
 *
 * A SecureBuffer cannot be copied (that would leave extra copies of a key in
 * memory); it can only be moved. It deliberately has no way to be printed or
 * written to a stream, so a key cannot end up in a log by accident (D14).
 *
 * sodium_init() must have been called (CryptoEngine::Initialize) before a
 * non-empty SecureBuffer is created.
 */
class SecureBuffer {
 public:
    /// An empty buffer that holds no memory.
    SecureBuffer() = default;

    /// A buffer of the given size, filled with zeros.
    explicit SecureBuffer(std::size_t size);

    /// A buffer of the given size, filled with random bytes.
    static SecureBuffer Random(std::size_t size);

    /// A buffer holding a copy of the given bytes.
    static SecureBuffer CopyOf(const unsigned char* data, std::size_t size);

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    /// Overwrites the memory with zeros and releases it.
    ~SecureBuffer();

    unsigned char* data() { return data_; }
    const unsigned char* data() const { return data_; }
    std::size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

 private:
    void Release() noexcept;

    unsigned char* data_{ nullptr };
    std::size_t size_{ 0 };
};

}   // namespace kythera::core

#endif  // SECUREBUFFER_H_
