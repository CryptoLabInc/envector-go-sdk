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
#include "EVI/impl/Type.hpp"

#include "EVI/Enums.hpp"
#include "utils/Exceptions.hpp"
#include "utils/SealInfo.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// deb header
#include <deb/CKKSTypes.hpp>
#include <deb/Serialize.hpp>

namespace evi {

namespace fs = std::filesystem;

namespace detail {

class IKeyPack {
public:
    virtual ~IKeyPack() = default;

    virtual void saveEncKeyFile(const std::string &path) const = 0;
    virtual void getEncKeyBuffer(std::ostream &os) const = 0;
    virtual void loadEncKeyFile(const std::string &path) = 0;
    virtual void loadEncKeyBuffer(std::istream &is) = 0;

    virtual void saveEvalKeyFile(const std::string &path) const = 0;
    virtual void getEvalKeyBuffer(std::ostream &os) const = 0;
    virtual void loadEvalKeyFile(const std::string &path) = 0;
    virtual void loadEvalKeyBuffer(std::istream &is) = 0;
};

class KeyPackData : public IKeyPack {
public:
    KeyPackData() = delete;
    KeyPackData(const evi::detail::Context &context);
    KeyPackData(const evi::detail::Context &context, std::istream &in);
    KeyPackData(const evi::detail::Context &context, const std::string &dir_path);
    ~KeyPackData() = default;

    // override func
    void saveEncKeyFile(const std::string &path) const override;
    void getEncKeyBuffer(std::ostream &os) const override;
    void loadEncKeyFile(const std::string &path) override;
    void loadEncKeyBuffer(std::istream &is) override;

    void saveEvalKeyFile(const std::string &path) const override;
    void getEvalKeyBuffer(std::ostream &os) const override;
    void loadEvalKeyFile(const std::string &path) override;
    void loadEvalKeyBuffer(std::istream &is) override;

    void serialize(std::ostream &os) const;
    void deserialize(std::istream &is);

    void saveModPackKeyFile(const std::string &path) const;
    void getModPackKeyBuffer(std::ostream &os) const;
    void saveRelinKeyFile(const std::string &path) const;
    void getRelinKeyBuffer(std::ostream &os) const;

    void loadRelinKeyFile(const std::string &path);
    void loadRelinKeyBuffer(std::istream &is);
    void loadModPackKeyFile(const std::string &path);
    void loadModPackKeyBuffer(std::istream &is);

    void save(const std::string &path);

    FixedKeyType enckey;
    FixedKeyType relin_key;
    deb::SwitchKey deb_enc_key;
    deb::SwitchKey deb_relin_key;

    VariadicKeyType mod_pack_key;
    VariadicKeyType shared_a_mod_pack_key;
    VariadicKeyType cc_shared_a_mod_pack_key;
    VariadicKeyType switch_key;
    VariadicKeyType shared_a_key;
    VariadicKeyType reverse_switch_key;
    std::vector<VariadicKeyType> additive_shared_a_key;
    deb::SwitchKey deb_mod_pack_key;

    int num_shared_secret;

    bool shared_a_key_loaded_;
    bool shared_a_mod_pack_loaded_;
    bool cc_shared_a_mod_pack_loaded_;
    bool enc_loaded_;
    bool eval_loaded_;

private:
    const evi::detail::Context context_;
};

using KeyPack = std::shared_ptr<IKeyPack>;

KeyPack makeKeyPack(const evi::detail::Context &context);
KeyPack makeKeyPack(const evi::detail::Context &context, std::istream &in);
KeyPack makeKeyPack(const evi::detail::Context &context, const std::string &dir_path);

} // namespace detail
} // namespace evi
