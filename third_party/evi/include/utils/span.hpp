////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, CryptoLab, Inc.                                       //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <stdint.h>

#include <array>
#include <cstddef>
#include <exception>
#include <functional>
#include <vector>

#ifdef _WIN32
#include <malloc.h>
#endif

template <typename T, std::size_t Alignment>
struct AlignedAllocator {
    using value_type = T;

    AlignedAllocator() noexcept = default;

    template <typename U>
    AlignedAllocator(const AlignedAllocator<U, Alignment> &) noexcept {}

    T *allocate(std::size_t n) {
        void *ptr = nullptr;
#ifdef _WIN32
        ptr = _aligned_malloc(n * sizeof(T), Alignment);
        if (!ptr) {
            throw std::bad_alloc();
        }
#else
        if (posix_memalign(&ptr, Alignment, n * sizeof(T)) != 0) {
            throw std::bad_alloc();
        }
#endif
        return reinterpret_cast<T *>(ptr);
    }

    void deallocate(T *p, std::size_t) noexcept {
#ifdef _WIN32
        _aligned_free(p);
#else
        free(p);
#endif
    }

    template <typename U>
    struct rebind {
        using other = AlignedAllocator<U, Alignment>;
    };
};

template <typename T, typename U, std::size_t A>
inline bool operator==(const AlignedAllocator<T, A> &, const AlignedAllocator<U, A> &) {
    return true;
}
template <typename T, typename U, std::size_t A>
inline bool operator!=(const AlignedAllocator<T, A> &, const AlignedAllocator<U, A> &) {
    return false;
}

namespace evi {

template <typename T>
class span { // NOLINT(readability-identifier-naming)
public:
    constexpr span(const T *ptr, std::size_t size) noexcept : ptr_(ptr), size_(size) {}

    constexpr span(const T *ptr) : ptr_(ptr) {}

    constexpr span(const std::vector<T> &vec) : ptr_(vec.data()), size_(vec.size()) {}
    template <std::size_t A>
    constexpr span(const std::vector<T, AlignedAllocator<T, A>> &vec) : ptr_(vec.data()), size_(vec.size()) {}

    template <std::size_t N>
    constexpr span(const std::array<T, N> &arr) noexcept : ptr_(arr.data()), size_(N) {}

    constexpr const T *begin() const noexcept {
        return ptr_;
    }
    constexpr const T *end() const noexcept {
        return ptr_ + size_;
    }

    constexpr T *begin() noexcept {
        return const_cast<T *>(ptr_);
    }
    constexpr T *end() noexcept {
        return const_cast<T *>(ptr_ + size_);
    }

    constexpr std::size_t size() const noexcept {
        return size_;
    }

    constexpr T &operator[](std::size_t index) {
        return const_cast<T &>(ptr_[index]);
    }

    const T &operator[](std::size_t index) const {
        return ptr_[index];
    }

    constexpr T *data() const noexcept {
        return const_cast<T *>(ptr_);
    }

    constexpr span<T> subspan(std::size_t offset, std::size_t count = -1) const {
        if (offset >= size_)
            return span<T>(ptr_, 0);
        std::size_t new_size = (count == static_cast<std::size_t>(-1)) ? (size_ - offset) : count;
        return span<T>(ptr_ + offset, std::min(new_size, size_ - offset));
    }

private:
    const T *ptr_;
    std::size_t size_;
};

} // namespace evi
