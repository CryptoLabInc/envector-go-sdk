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

#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/ContextImpl.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"
#include "EVI/impl/Type.hpp"
#include "utils/Exceptions.hpp"
#include "utils/span.hpp"

#include <cstdint>
#include <functional>
#include <istream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// deb header
#include <deb/Decryptor.hpp>

namespace evi {

namespace detail {
class DecryptorInterface {
public:
    explicit DecryptorInterface(const Context &context);
    virtual ~DecryptorInterface() = default;

    virtual Message decrypt(const SearchResult ctxt, const SecretKey &key, bool is_score,
                            std::optional<double> scale = std::nullopt) = 0;
    virtual Message decrypt(const SearchResult ctxt, const std::string &key_path, bool is_score,
                            std::optional<double> scale = std::nullopt) = 0;
    virtual Message decrypt(const SearchResult ctxt, std::istream &key_stream, bool is_score,
                            std::optional<double> scale = std::nullopt) = 0;
    virtual Message decrypt(const Query &ctxt, const SecretKey &key, std::optional<double> scale = std::nullopt) = 0;
    virtual Message decrypt(const Query &ctxt, const std::string &key_path,
                            std::optional<double> scale = std::nullopt) = 0;
    virtual Message decrypt(const Query &ctxt, std::istream &key_stream,
                            std::optional<double> scale = std::nullopt) = 0;
    virtual Message decrypt(const int idx, const Query &ctxt, const SecretKey &key,
                            std::optional<double> scale = std::nullopt);

protected:
    deb::Decryptor deb_dec_;
    const Context context_;
};

class DecryptorFLAT : public DecryptorInterface {
public:
    explicit DecryptorFLAT(const Context &context);

    Message decrypt(const SearchResult ctxt, const SecretKey &key, bool is_score,
                    std::optional<double> scale = std::nullopt) override;
    Message decrypt(const SearchResult ctxt, const std::string &key_path, bool is_score,
                    std::optional<double> scale = std::nullopt) override;
    Message decrypt(const SearchResult ctxt, std::istream &key_stream, bool is_score,
                    std::optional<double> scale = std::nullopt) override;
    Message decrypt(const Query &ctxt, const SecretKey &key, std::optional<double> scale = std::nullopt) override;
    Message decrypt(const Query &ctxt, const std::string &key_path,
                    std::optional<double> scale = std::nullopt) override;
    Message decrypt(const Query &ctxt, std::istream &key_stream, std::optional<double> scale = std::nullopt) override;
};

class DecryptorRMP : public DecryptorFLAT {
public:
    explicit DecryptorRMP(const Context &context);

    using DecryptorFLAT::decrypt;

    Message decrypt(const int idx, const Query &ctxt, const SecretKey &key,
                    std::optional<double> scale = std::nullopt) override;
};

class DecryptorMM : public DecryptorInterface {
public:
    explicit DecryptorMM(const Context &context);

    Message decrypt(const SearchResult ctxt, const SecretKey &key, bool is_score,
                    std::optional<double> scale = std::nullopt) override;
    Message decrypt(const SearchResult ctxt, const std::string &key_path, bool is_score,
                    std::optional<double> scale = std::nullopt) override;
    Message decrypt(const SearchResult ctxt, std::istream &key_stream, bool is_score,
                    std::optional<double> scale = std::nullopt) override;
    Message decrypt(const Query &ctxt, const SecretKey &key, std::optional<double> scale = std::nullopt) override;
    Message decrypt(const Query &ctxt, const std::string &key_path,
                    std::optional<double> scale = std::nullopt) override;
    Message decrypt(const Query &ctxt, std::istream &key_stream, std::optional<double> scale = std::nullopt) override;
};

class Decryptor : public std::shared_ptr<DecryptorInterface> {
public:
    Decryptor(std::shared_ptr<DecryptorInterface> impl) : std::shared_ptr<DecryptorInterface>(std::move(impl)) {}
};

Decryptor makeDecryptor(const Context &context);

} // namespace detail
} // namespace evi
