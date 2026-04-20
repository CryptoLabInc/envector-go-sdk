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

#include <cstdarg>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace evi {

class EviError : public std::runtime_error {
public:
    explicit EviError(const std::string &message) : std::runtime_error(message) {}
    EviError(const EviError &) = default;
    EviError(EviError &&) noexcept = default;
    EviError &operator=(const EviError &) = default;
    EviError &operator=(EviError &&) noexcept = default;
    ~EviError() override = default;

    template <typename... Args, std::enable_if_t<(sizeof...(Args) >= 2), int> = 0>
    EviError(Args &&...args) : std::runtime_error(concat(std::forward<Args>(args)...)) {}

    virtual const char *errorName() const {
        return "EviError";
    }

    const char *what() const noexcept override {
        static std::string full_message;
        std::ostringstream oss;
        oss << "[" << errorName() << "] " << std::runtime_error::what();
        full_message = oss.str();
        return full_message.c_str();
    }

private:
    template <typename T, typename = void>
    struct IsStreamInsertable : std::false_type {};

    template <typename T>
    struct IsStreamInsertable<T,
                              std::void_t<decltype(std::declval<std::ostringstream &>() << std::declval<const T &>())>>
        : std::true_type {};

    template <typename T>
    static void appendArg(std::ostringstream &oss, T &&arg) {
        using ValueType = std::decay_t<T>;

        if constexpr (IsStreamInsertable<ValueType>::value) {
            oss << std::forward<T>(arg);
        } else if constexpr (std::is_base_of_v<std::exception, ValueType>) {
            oss << arg.what();
        } else {
            static_assert(IsStreamInsertable<ValueType>::value || std::is_base_of_v<std::exception, ValueType>,
                          "EviError arguments must be stream-insertable or derive from std::exception");
        }
    }

    template <typename... Args>
    static std::string concat(Args &&...args) {
        std::ostringstream oss;
        (appendArg(oss, std::forward<Args>(args)), ...);
        return oss.str();
    }
};

class EncryptionError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "EncryptionError";
    }
};

class FileNotFoundError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "FileNotFoundError";
    }
};

class KeyNotLoadedError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "KeyNotLoadedError";
    }
};

class DecryptionError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "DecryptionError";
    }
};

class NotSupportedError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "NotSupportedError";
    }
};

class InvalidInputError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "InvalidInputError";
    }
};

class InvalidAccessError : public EviError {
public:
    using EviError::EviError;

    const char *errorName() const override {
        return "InvalidAccessError";
    }
};

} // namespace evi
