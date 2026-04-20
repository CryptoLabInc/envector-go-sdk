////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "EVI/SealInfo.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"
#include "km/Enums.hpp"
#include "km/ProviderMeta.hpp"

#include <istream>
#include <optional>
#include <ostream>
#include <string>

namespace evi {

namespace detail {

class KeyManagerInterface {
public:
    virtual ~KeyManagerInterface() = default;

    // sec key
    virtual void wrapSecKey(const std::string &key_id, const std::string key_path, const std::string &output_path) = 0;
    virtual void wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) = 0;
    virtual void wrapSecKey(const std::string &key_id, const SecretKey &seckey, std::ostream &out_stream) = 0;

    virtual void unwrapSecKey(const std::string &file_path, const std::string &output_path, const SealInfo &sInfo) = 0;
    virtual void unwrapSecKey(std::istream &key_stream, std::ostream &out_stream, const SealInfo &sInfo) = 0;
    virtual void unwrapSecKey(std::istream &key_stream, SecretKey &seckey, const SealInfo &s_info) = 0;

    // enc key
    virtual void wrapEncKey(const std::string &key_id, const std::string key_path, const std::string &output_path) = 0;
    virtual void wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) = 0;
    virtual void wrapEncKey(const std::string &key_id, const IKeyPack &keypack, std::ostream &out_stream) = 0;

    virtual void unwrapEncKey(const std::string &file_path, const std::string &output_path) = 0;
    virtual void unwrapEncKey(std::istream &key_stream, std::ostream &out_stream) = 0;
    virtual void unwrapEncKey(std::istream &key_stream, IKeyPack &keypack) = 0;

    // eval key
    virtual void wrapEvalKey(const std::string &key_id, const std::string key_path, const std::string &output_path) = 0;
    virtual void wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) = 0;

    virtual void unwrapEvalKey(const std::string &file_path, const std::string &output_path) = 0;
    virtual void unwrapEvalKey(std::istream &key_stream, std::ostream &out_stream) = 0;

    // all keys
    virtual void wrapKeys(const std::string &key_id, const std::string &file_dir_path) = 0;
    virtual void wrapKeys(const std::string &key_id, std::istream &key_stream) = 0;

    virtual void unwrapKeys(const std::string &key_dir_path, const std::string &output_dir_path) = 0;
    virtual void unwrapKeys(std::istream &key_stream, std::ostream &out_stream) = 0;
};

class KeyManager : public std::shared_ptr<KeyManagerInterface> {
public:
    KeyManager(std::shared_ptr<KeyManagerInterface> impl) : std::shared_ptr<KeyManagerInterface>(std::move(impl)) {}
};

KeyManager makeKeyManager(const ProviderMeta &provider_meta, const KeyFormatVersion version);
KeyManager makeKeyManager(const ProviderMeta &provider_meta);
KeyManager makeKeyManager();

} // namespace detail
} // namespace evi
