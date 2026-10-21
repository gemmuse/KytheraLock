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
#include "SecureBuffer.h"

#include <sodium.h>

#include <cstring>
#include <new>
#include <utility>

namespace kythera::core {

SecureBuffer::SecureBuffer(std::size_t size) {
    if (size == 0)
        return;

    data_ = static_cast<unsigned char*>(sodium_malloc(size));
    if (data_ == nullptr)
        throw std::bad_alloc();

    size_ = size;

    // sodium_malloc fills new memory with a recognisable junk pattern, so
    // start from a known state instead.
    sodium_memzero(data_, size_);
}

SecureBuffer SecureBuffer::Random(std::size_t size) {
    SecureBuffer buffer(size);

    if (size > 0)
        randombytes_buf(buffer.data_, buffer.size_);

    return buffer;
}

SecureBuffer SecureBuffer::CopyOf(const unsigned char* data,
                                  std::size_t size) {
    SecureBuffer buffer(size);

    if (size > 0)
        std::memcpy(buffer.data_, data, size);

    return buffer;
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        Release();
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }

    return *this;
}

SecureBuffer::~SecureBuffer() {
    Release();
}

void SecureBuffer::Release() noexcept {
    // sodium_free overwrites the memory with zeros before releasing it.
    if (data_ != nullptr) {
        sodium_free(data_);
        data_ = nullptr;
        size_ = 0;
    }
}

}   // namespace kythera::core
