////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "EVI/SealInfo.hpp"
#include "EVI/SecretKey.hpp"
#include "km/KeyEnvelope.hpp"
#include "km/ProviderMeta.hpp"

#include "nlohmann/json.hpp"

#include <istream>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace evi {

namespace detail {

class KeyProviderInterface {
public:
    virtual ~KeyProviderInterface() = default;

    virtual evi::ProviderEnvelope encapSecKey(const std::string &key_file_path) = 0;
    virtual evi::ProviderEnvelope encapEncKey(const std::string &key_file_path) = 0;
    virtual evi::ProviderEnvelope encapEvalKey(const std::string &key_file_path) = 0;
    virtual evi::ProviderEnvelope encapSecKey(std::istream &key_stream) = 0;
    virtual evi::ProviderEnvelope encapEncKey(std::istream &key_stream) = 0;
    virtual evi::ProviderEnvelope encapEvalKey(std::istream &key_stream) = 0;

    virtual void decapSecKey(const std::string &key_file_path, const std::string &out_file_path) = 0;
    virtual void decapEncKey(const std::string &key_file_path, const std::string &out_file_path) = 0;
    virtual void decapEvalKey(const std::string &key_file_path, const std::string &out_file_path) = 0;
    virtual void decapSecKey(std::istream &key_stream, std::ostream &out_stream) = 0;
    virtual void decapEncKey(std::istream &key_stream, std::ostream &out_stream) = 0;
    virtual void decapEvalKey(std::istream &key_stream, std::ostream &out_stream) = 0;
};

class KeyProvider : public std::shared_ptr<KeyProviderInterface> {
public:
    KeyProvider(std::shared_ptr<KeyProviderInterface> impl) : std::shared_ptr<KeyProviderInterface>(std::move(impl)) {}
};

} // namespace detail
} // namespace evi
