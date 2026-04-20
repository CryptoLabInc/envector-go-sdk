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
#include "EVI/impl/KeyPackImpl.hpp"
#include "EVI/impl/NTT.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"
#include "EVI/impl/Type.hpp"

#include "utils/Exceptions.hpp"
#include "utils/Sampler.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// deb header
#include <deb/KeyGenerator.hpp>

namespace evi {
namespace detail {

class KeyGeneratorInterface {
public:
    virtual ~KeyGeneratorInterface() = default;
    virtual SecretKey genSecKey(std::optional<const int *> sec_coeff = std::nullopt) = 0;
    virtual void genEncKey(const SecretKey &seckey) = 0;
    virtual void genRelinKey(const SecretKey &seckey) = 0;
    virtual void genModPackKey(const SecretKey &seckey) = 0;
    virtual void genPubKeys(const SecretKey &seckey) = 0;
    virtual KeyPack &getKeyPack() = 0;

    virtual void genSharedASwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) = 0;
    virtual void genAdditiveSharedASwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) = 0;
    virtual void genSharedAModPackKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) = 0;
    virtual void genCCSharedAModPackKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) = 0;
    virtual std::vector<SecretKey> genMultiSecKey() = 0;
    virtual void genSwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) = 0;
};

template <EvalMode M>
class KeyGeneratorImpl : public KeyGeneratorInterface {
public:
    KeyGeneratorImpl(const Context &context, KeyPack &pack, const std::optional<std::vector<u8>> &seed = std::nullopt);
    KeyGeneratorImpl(const Context &context, const std::optional<std::vector<u8>> &seed = std::nullopt);

    KeyGeneratorImpl() = delete;
    ~KeyGeneratorImpl() override = default;

    SecretKey genSecKey(std::optional<const int *> sec_coeff = std::nullopt) override;
    void genEncKey(const SecretKey &sec_key) override;
    void genRelinKey(const SecretKey &sec_key) override;
    void genModPackKey(const SecretKey &sec_key) override;
    void genPubKeys(const SecretKey &sec_key) override;

    void genSharedASwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) override;
    void genAdditiveSharedASwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) override;
    void genSharedAModPackKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) override;
    void genCCSharedAModPackKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) override;
    std::vector<SecretKey> genMultiSecKey() override;
    void genSwitchKey(const SecretKey &sec_from, const std::vector<SecretKey> &sec_to) override;

    KeyPack &getKeyPack() override {
        return pack_iface_;
    }

private:
    void genSecKeyFromCoeff(SecretKey &sec_key, const int *sec_coeff);
    void genSwitchingKey(const SecretKey &sec_key, span<u64> from_s, span<u64> out_a_q, span<u64> out_a_p,
                         span<u64> out_b_q, span<u64> out_b_p);
    const Context context_;
    deb::KeyGenerator deb_keygen_;

    KeyPack pack_iface_;
    std::shared_ptr<KeyPackData> pack_;
    std::shared_ptr<KeyPack> gen_pack_;

    RandomSampler sampler_;
};

class MultiKeyGenerator final {
public:
    MultiKeyGenerator(std::vector<Context> &context, const std::string &store_path, SealInfo &s_info,
                      const std::optional<std::vector<u8>> &seed = std::nullopt);
    ~MultiKeyGenerator() = default;

    SecretKey generateKeys();
    SecretKey generateKeys(std::ostream &os);
    SecretKey generateKeys(std::ostream &seckey, std::ostream &enckey, std::ostream &evalkey);
    SecretKey generateSecKey();

    void generateKeysFromSecKey(const std::string &sec_key_path);
    void generatePubKey(SecretKey &sec_key);

    SecretKey saveEviSecKey();

    KeyPack &getKeyPack() {
        return evi_keypack_[0];
    }

    bool checkFileExist();

private:
    std::vector<Context> evi_context_;
    std::vector<KeyPack> evi_keypack_;

    std::shared_ptr<SealInfo> s_info_;
    std::optional<TEEWrapper> teew_;

    std::shared_ptr<alea_state> as_;

    std::vector<int> rank_list_;
    std::vector<std::pair<int, int>> inner_rank_list_;
    evi::ParameterPreset preset_;
    std::filesystem::path store_path_;

    void initialize();

    bool saveAllKeys(SecretKey &seckey);
    void saveEncKey();
    void saveEvalKey();

    void saveEviSecKey(SecretKey &sec_key);
};

class KeyGenerator : public std::shared_ptr<KeyGeneratorInterface> {
public:
    KeyGenerator(std::shared_ptr<KeyGeneratorInterface> ptr) : std::shared_ptr<KeyGeneratorInterface>(ptr) {}
    KeyGenerator &operator=(const std::shared_ptr<KeyGeneratorInterface> &other) {
        std::shared_ptr<KeyGeneratorInterface>::operator=(other);
        return *this;
    }
};

KeyGenerator makeKeyGenerator(const Context &context, KeyPack &pack,
                              const std::optional<std::vector<u8>> &seed = std::nullopt);
KeyGenerator makeKeyGenerator(const Context &context, const std::optional<std::vector<u8>> &seed = std::nullopt);

} // namespace detail
} // namespace evi
