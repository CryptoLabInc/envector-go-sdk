////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "EVI/Export.hpp"
#include "EVI/KeyPack.hpp"
#include "EVI/SealInfo.hpp"
#include "EVI/SecretKey.hpp"
#include "km/ProviderMeta.hpp"

#include <istream>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace evi {

namespace detail {
class KeyManager;
}

class EVI_API KeyManager {
public:
    KeyManager() : impl_(nullptr) {}

    explicit KeyManager(std::shared_ptr<detail::KeyManager> impl) noexcept;

    // seckey
    void wrapSecKey(const std::string &key_id, const std::string &key_path, const std::string &output_path);
    void wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream);
    void wrapSecKey(const std::string &key_id, const evi::SecretKey &seckey, std::ostream &out_stream);

    void unwrapSecKey(const std::string &file_path, const std::string &output_path,
                      const std::optional<SealInfo> &s_info = std::nullopt);
    void unwrapSecKey(std::istream &key_stream, std::ostream &out_stream,
                      const std::optional<SealInfo> &s_info = std::nullopt);
    void unwrapSecKey(std::istream &key_stream, evi::SecretKey &seckey,
                      const std::optional<SealInfo> &s_info = std::nullopt);

    // enckey
    void wrapEncKey(const std::string &key_id, const std::string &key_path, const std::string &output_path);
    void wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream);
    void wrapEncKey(const std::string &key_id, const evi::KeyPack &keypack, std::ostream &out_stream);

    void unwrapEncKey(const std::string &file_path, const std::string &output_path);
    void unwrapEncKey(std::istream &key_stream, std::ostream &out_stream);
    void unwrapEncKey(std::istream &key_stream, evi::KeyPack &keypack);

    // evalkey
    void wrapEvalKey(const std::string &key_id, const std::string &key_path, const std::string &output_path);
    void wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream);

    void unwrapEvalKey(const std::string &file_path, const std::string &output_path);
    void unwrapEvalKey(std::istream &key_stream, std::ostream &out_stream);

    void wrapKeys(const std::string &key_id, const std::string &file_dir_path);
    void wrapKeys(const std::string &key_id, std::istream &file_stream);
    void unwrapKeys(const std::string &file_dir_path, const std::string &output_dir_path);
    void unwrapKeys(std::istream &key_stream, std::ostream &out_stream);

private:
    std::shared_ptr<detail::KeyManager> impl_;
};

EVI_API KeyManager makeKeyManager();
EVI_API KeyManager makeKeyManager(const ProviderMeta &provider_meta);

} // namespace evi
