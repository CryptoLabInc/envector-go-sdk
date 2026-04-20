////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "EVI/SealInfo.hpp"
#include "EVI/SecretKey.hpp"
#include "km/KeyEnvelope.hpp"
#include "km/KeyProviderInterface.hpp"
#include "km/ProviderMeta.hpp"

#include "nlohmann/json.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace evi {
namespace detail {

class LocalKeyProvider : public KeyProviderInterface {
public:
    explicit LocalKeyProvider(LocalProviderMeta provider_meta);
    ~LocalKeyProvider() override = default;

    evi::ProviderEnvelope encapSecKey(const std::string &key_file_path) override;
    evi::ProviderEnvelope encapEncKey(const std::string &key_file_path) override;
    evi::ProviderEnvelope encapEvalKey(const std::string &key_file_path) override;
    evi::ProviderEnvelope encapSecKey(std::istream &key_stream) override;
    evi::ProviderEnvelope encapEncKey(std::istream &key_stream) override;
    evi::ProviderEnvelope encapEvalKey(std::istream &key_stream) override;

    void decapSecKey(const std::string &key_file_path, const std::string &out_file_path) override;
    void decapEncKey(const std::string &key_file_path, const std::string &out_file_path) override;
    void decapEvalKey(const std::string &key_file_path, const std::string &out_file_path) override;
    void decapSecKey(std::istream &key_stream, std::ostream &out_stream) override;
    void decapEncKey(std::istream &key_stream, std::ostream &out_stream) override;
    void decapEvalKey(std::istream &key_stream, std::ostream &out_stream) override;

private:
    LocalProviderMeta provider_meta_;
};

} // namespace detail
} // namespace evi
