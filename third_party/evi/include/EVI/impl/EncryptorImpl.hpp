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

#include "EVI/Enums.hpp"
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/ContextImpl.hpp"
#include "EVI/impl/KeyPackImpl.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"
#include "EVI/impl/Type.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Sampler.hpp"
#include "utils/span.hpp"

#include <cstdint>
#include <functional>
#include <istream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// deb header
#include <deb/CKKSTypes.hpp>
#include <deb/Encryptor.hpp>

namespace evi {
namespace detail {
class EncryptorInterface {
public:
    virtual ~EncryptorInterface() = default;
    virtual void loadEncKey(const std::string &dir_path) = 0;
    virtual void loadEncKey(std::istream &in) = 0;

    virtual Query encrypt(const span<float> msg, const EncodeType type = EncodeType::ITEM, const bool level = false,
                          std::optional<float> scale = std::nullopt) = 0;

    virtual Query encrypt(const span<float> msg, const SecretKey &seckey, const EncodeType type = EncodeType::ITEM,
                          const bool level = false, std::optional<float> scale = std::nullopt) = 0;

    virtual Query encrypt(const span<float> msg, const MultiSecretKey &seckey, const EncodeType type, const bool level,
                          std::optional<float> scale) = 0;

    virtual Query encrypt(const span<float> msg, const std::string &enckey_path,
                          const EncodeType type = EncodeType::ITEM, const bool level = false,
                          std::optional<float> scale = std::nullopt) = 0;
    virtual Query encrypt(const span<float> msg, std::istream &enckey_stream, const EncodeType type = EncodeType::ITEM,
                          const bool level = false, std::optional<float> scale = std::nullopt) = 0;

    virtual Query encrypt(const span<float> msg, const KeyPack &keypack, const EncodeType type = EncodeType::ITEM,
                          const bool level = false, std::optional<float> scale = std::nullopt) = 0;

    virtual std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg,
                                       const EncodeType type = EncodeType::ITEM, const bool level = false,
                                       std::optional<float> scale = std::nullopt) = 0;

    virtual std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const std::string &enckey_path,
                                       const EncodeType type = EncodeType::ITEM, const bool level = false,
                                       std::optional<float> scale = std::nullopt) = 0;
    virtual std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, std::istream &enckey_stream,
                                       const EncodeType type = EncodeType::ITEM, const bool level = false,
                                       std::optional<float> scale = std::nullopt) = 0;

    virtual std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const KeyPack &keypack,
                                       const EncodeType type = EncodeType::ITEM, const bool level = false,
                                       std::optional<float> scale = std::nullopt) = 0;

    virtual Query encode(const span<float> msg, const EncodeType type = EncodeType::ITEM, const bool level = false,
                         std::optional<float> scale = std::nullopt) = 0;

    virtual Query encode(const std::vector<std::vector<float>> &msg, const EncodeType type = EncodeType::QUERY,
                         const int level = 0, std::optional<float> scale = std::nullopt) = 0;

    virtual Blob encrypt(const span<float> msg, const int num_items, const bool level = false,
                         std::optional<float> scale = std::nullopt) = 0;
    virtual Blob encode(const span<float> msg, const int num_items, const bool level = false,
                        std::optional<float> scale = std::nullopt) = 0;

    virtual EvalMode getEvalMode() const = 0;
    virtual const Context &getContext() const = 0;
};

class RandomSampler;

template <EvalMode M>
class EncryptorImpl : public EncryptorInterface {
public:
    explicit EncryptorImpl(const Context &context, const std::optional<std::vector<u8>> &seed = std::nullopt);
    explicit EncryptorImpl(const Context &context, const KeyPack &keypack,
                           const std::optional<std::vector<u8>> &seed = std::nullopt);
    explicit EncryptorImpl(const Context &context, const std::string &path,
                           const std::optional<std::vector<u8>> &seed = std::nullopt);
    explicit EncryptorImpl(const Context &context, std::istream &in,
                           const std::optional<std::vector<u8>> &seed = std::nullopt);

    void loadEncKey(const std::string &dir_path) override;
    void loadEncKey(std::istream &in) override;
    void loadEncKey(const KeyPack &keypack);

    Query encrypt(const span<float> msg, const SecretKey &seckey, const EncodeType type = EncodeType::ITEM,
                  const bool level = false, std::optional<float> scale = std::nullopt) override;
    Query encrypt(const span<float> msg, const MultiSecretKey &seckey, const EncodeType type, const bool level,
                  std::optional<float> scale);
    Query encrypt(const span<float> msg, const EncodeType type = EncodeType::ITEM, const bool level = false,
                  std::optional<float> scale = std::nullopt) override;
    Query encrypt(const span<float> msg, const std::string &enckey_path, const EncodeType type, const bool level,
                  std::optional<float> scale) override;
    Query encrypt(const span<float> msg, std::istream &enckey_stream, const EncodeType type, const bool level,
                  std::optional<float> scale) override;
    Query encrypt(const span<float> msg, const KeyPack &keypack, const EncodeType type, const bool level,
                  std::optional<float> scale) override;

    // test feature batch encrypt
    std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const EncodeType type = EncodeType::ITEM,
                               const bool level = false, std::optional<float> scale = std::nullopt) override;

    std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const std::string &enckey_path,
                               const EncodeType type = EncodeType::ITEM, const bool level = false,
                               std::optional<float> scale = std::nullopt) override;
    std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, std::istream &enckey_stream,
                               const EncodeType type = EncodeType::ITEM, const bool level = false,
                               std::optional<float> scale = std::nullopt) override;

    std::vector<Query> encrypt(const std::vector<std::vector<float>> &msg, const KeyPack &keypack,
                               const EncodeType type = EncodeType::ITEM, const bool level = false,
                               std::optional<float> scale = std::nullopt) override;

    std::vector<Query> encryptMM(const std::vector<std::vector<float>> &msg, const EncodeType type = EncodeType::ITEM,
                                 const bool level = false, std::optional<float> scale = std::nullopt);

    Query encode(const span<float> msg, const EncodeType type, const bool level = false,
                 std::optional<float> scale = std::nullopt) override;

    Query encode(const std::vector<std::vector<float>> &msg, const EncodeType type, const int level,
                 std::optional<float> scale) override;

    EvalMode getEvalMode() const override {
        return context_->getEvalMode();
    }
    const Context &getContext() const override {
        return context_;
    }

    Blob encrypt(const span<float> msg, const int num_items, const bool level = false,
                 std::optional<float> scale = std::nullopt) override;
    Blob encode(const span<float> msg, const int num_items, const bool level = false,
                std::optional<float> scale = std::nullopt) override;
    // std::vector<polyvec128> plainQueryForLv0HERS(const span<float> msg, std::optional<float> scale =
    // std::nullopt);

    // std::vector<u64> packingWithModPackKey(KeyPack keys,
    //                                        std::vector<std::shared_ptr<evi::SingleCiphertext>> ciphers);
private:
    Query::SingleQuery innerEncrypt(const span<float> &msg, const bool level, const double scale,
                                    std::optional<const SecretKey> seckey = std::nullopt,
                                    std::optional<bool> ntt = true);
    Query::SingleQuery innerEncode(const span<float> &msg, const bool level, const double scale,
                                   std::optional<const u64> msg_size = std::nullopt, std::optional<bool> ntt = true);

    const Context context_;
    RandomSampler sampler_;
    deb::Encryptor deb_encryptor_;
    FixedKeyType encKey_;
    deb::SwitchKey deb_enc_key_;

    VariadicKeyType switch_key_;
    bool enc_loaded_ = false;
};

class Encryptor : public std::shared_ptr<EncryptorInterface> {
public:
    Encryptor(std::shared_ptr<EncryptorInterface> impl) : std::shared_ptr<EncryptorInterface>(std::move(impl)) {}
};

Encryptor makeEncryptor(const Context &context, const std::optional<std::vector<u8>> &seed = std::nullopt);
Encryptor makeEncryptor(const Context &context, const KeyPack &keypack,
                        const std::optional<std::vector<u8>> &seed = std::nullopt);
Encryptor makeEncryptor(const Context &context, const std::string &path,
                        const std::optional<std::vector<u8>> &seed = std::nullopt);
Encryptor makeEncryptor(const Context &context, std::istream &in,
                        const std::optional<std::vector<u8>> &seed = std::nullopt);
} // namespace detail
} // namespace evi
