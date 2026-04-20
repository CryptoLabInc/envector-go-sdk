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
#include "EVI/Export.hpp"
#include <cstddef>
#include <memory>

namespace evi {

namespace detail {
class Message;
}

/**
 * @class Message
 * @brief Represents a container for plaintext numerical data.
 *
 * The `Message` class manages a dynamic array of floating-point values.
 * It is typically used to store decrypted results or plaintext vectors
 * for encryption and evaluation in homomorphic computations.
 */
class EVI_API Message {
public:
    /**
     * @brief Constructs an empty `Message`.
     */
    Message();

    /**
     * @brief Constructs a `Message` from an internal implementation.
     * @param impl Shared pointer to the internal `detail::Message` object.
     */
    Message(std::shared_ptr<detail::Message> impl);

    /**
     * @brief Resizes the message buffer.
     * @param n New size of the buffer.
     */
    void resize(size_t n);

    /**
     * @brief Appends a value to the message.
     * @param value Floating-point value to append.
     */
    void push_back(float value); // NOLINT(readability-identifier-naming)

    /**
     * @brief Clears all data from the message.
     */
    void clear();

    /**
     * @brief Reserves capacity for at least `n` elements.
     * @param n Minimum number of elements to reserve.
     */
    void reserve(size_t n);

    /**
     * @brief Constructs and appends a value at the end.
     * @param value Floating-point value to insert.
     */
    void emplace_back(float value); // NOLINT(readability-identifier-naming)

    /**
     * @brief Returns a mutable pointer to the message data.
     * @return Pointer to the underlying float buffer.
     */
    float *data();

    /**
     * @brief Returns a const pointer to the message data.
     * @return Const pointer to the underlying float buffer.
     */
    const float *data() const;

    /**
     * @brief Returns the number of elements stored.
     * @return Size of the message.
     */
    size_t size() const;

    /**
     * @brief Accesses an element by index.
     * @param index Position of the element.
     * @return Reference to the element.
     */
    float &operator[](size_t index);

private:
    std::shared_ptr<detail::Message> impl_;
};

} // namespace evi
