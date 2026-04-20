////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "EVI/SealInfo.hpp"
#include "EVI/impl/KeyPackImpl.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"
#include "km/Enums.hpp"
#include "km/KeyManagerInterface.hpp"
#include "km/impl/KeyProviderImpl.hpp"

#include <istream>
#include <optional>
#include <ostream>
#include <string>

namespace evi {

namespace detail {

class KeyManagerV1 : public KeyManagerInterface {
public:
    explicit KeyManagerV1(KeyProvider provider);
    ~KeyManagerV1() override = default;

    // sec key
    void wrapSecKey(const std::string &key_id, const std::string key_path, const std::string &output_path) override;
    void wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) override;
    void wrapSecKey(const std::string &key_id, const SecretKey &seckey, std::ostream &out_stream) override;

    void unwrapSecKey(const std::string &file_path, const std::string &out_path, const SealInfo &s_info) override;
    void unwrapSecKey(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info) override;
    void unwrapSecKey(std::istream &key_stream, SecretKey &seckey, const SealInfo &s_info) override;

    // enc key
    void wrapEncKey(const std::string &key_id, const std::string key_path, const std::string &output_path) override;
    void wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) override;
    void wrapEncKey(const std::string &key_id, const IKeyPack &keypack, std::ostream &out_stream) override;

    void unwrapEncKey(const std::string &file_path, const std::string &out_path) override;
    void unwrapEncKey(std::istream &in_stream, std::ostream &out_stream) override;
    void unwrapEncKey(std::istream &key_stream, IKeyPack &keypack) override;

    // eval key
    void wrapEvalKey(const std::string &key_id, const std::string key_path, const std::string &output_path) override;
    void wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) override;

    void unwrapEvalKey(const std::string &file_path, const std::string &out_path) override;
    void unwrapEvalKey(std::istream &key_stream, std::ostream &out_stream) override;

    // all keys
    void wrapKeys(const std::string &key_id, const std::string &file_dir_path) override;
    void wrapKeys(const std::string &key_id, std::istream &file_stream) override;

    void unwrapKeys(const std::string &file_path, const std::string &out_path) override;
    void unwrapKeys(std::istream &key_stream, std::ostream &out_stream) override;

private:
    KeyProvider provider_;
};
} // namespace detail
} // namespace evi
