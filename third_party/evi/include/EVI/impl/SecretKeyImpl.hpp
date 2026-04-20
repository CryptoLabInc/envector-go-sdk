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
#include "EVI/impl/Const.hpp"
#include "EVI/impl/ContextImpl.hpp"
#include "EVI/impl/NTT.hpp"
#include "EVI/impl/Type.hpp"
#include "utils/SealInfo.hpp"
#include "utils/crypto/TEEWrapper.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <istream>
#include <string>
#include <vector>

// deb header
#include <deb/CKKSTypes.hpp>
#include <deb/Serialize.hpp>

namespace evi {

namespace fs = std::filesystem;

namespace detail {
struct SecretKeyData {
    SecretKeyData(const evi::detail::Context &context);
    SecretKeyData(const std::string &path, const std::optional<SealInfo> &s_info = std::nullopt);
    SecretKeyData(std::istream &stream, const std::optional<SealInfo> &s_info = std::nullopt);

    void loadSecKey(const std::string &dir_path);
    void loadSecKey(std::istream &is);
    void saveSecKey(const std::string &dir_path) const;
    void saveSecKey(std::ostream &os) const;

    void loadSealedSecKey(const std::string &dir_path);
    void loadSealedSecKey(std::istream &is);
    void saveSealedSecKey(const std::string &dir_path);
    void saveSealedSecKey(std::ostream &os);

    void serialize(std::ostream &os) const;
    void deserialize(std::istream &is);

    s_poly &getCoeff() {
        return sec_coeff_;
    }
    poly &getKeyQ() {
        return sec_key_q_;
    }
    poly &getKeyP() {
        return sec_key_p_;
    }

    evi::ParameterPreset preset_;
    deb::SecretKey deb_sk_;

    s_poly sec_coeff_;
    poly sec_key_q_;
    poly sec_key_p_;

    bool sec_loaded_;

    std::optional<SealInfo> s_info_;
    std::optional<TEEWrapper> teew_;
};

class SecretKey : public std::shared_ptr<SecretKeyData> {
public:
    SecretKey() : std::shared_ptr<SecretKeyData>(NULL) {}
    SecretKey(std::shared_ptr<SecretKeyData> data) : std::shared_ptr<SecretKeyData>(data) {}
};

SecretKey makeSecKey(const evi::detail::Context &context);
SecretKey makeSecKey(const std::string &path, const std::optional<SealInfo> &s_info = std::nullopt);
SecretKey makeSecKey(std::istream &stream, const std::optional<SealInfo> &s_info = std::nullopt);

using MultiSecretKey = std::vector<std::shared_ptr<SecretKeyData>>;

} // namespace detail
} // namespace evi
