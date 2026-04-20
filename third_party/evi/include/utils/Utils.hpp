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
#include "EVI/impl/KeyGeneratorImpl.hpp"

#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <sstream>
#include <string>

#include <openssl/buffer.h>
#include <openssl/evp.h>

#define getInnerRank(rank) (std::max(uint64_t(32), uint64_t(std::pow(2, std::floor(std::log2(rank) / 2)))))

namespace evi {
namespace detail {
namespace utils {
namespace fs = std::filesystem;

void serializeQueryTo(const Query &query, std::ostream &os);
Query deserializeQueryFrom(std::istream &is);

void serializeResultTo(const SearchResult &res, std::ostream &os);
SearchResult deserializeResultFrom(std::istream &is);

std::string encodeToBase64(const std::vector<uint8_t> &data);
std::string encodeToBase64(const std::string &str);
std::vector<uint8_t> decodeBase64(const std::string &encoded);

evi::ParameterPreset stringToPreset(const std::string &str);
evi::SealMode stringToSealMode(const std::string &str);

std::string assignParameterString(evi::ParameterPreset preset);
std::string assignEvalModeString(evi::EvalMode mode);
std::string assignSealModeString(evi::SealMode s_mode);

void serializeString(const std::string &str, std::ostream &out);
void serializeEvalKey(const std::string &dir_path, const std::string &out_path);

void deserializeString(std::istream &in, std::string &str);
void deserializeEvalKey(const std::string &key_path, const std::string &output_dir, bool delete_after = true);

void serializeKeyFiles(const std::string &key_dir, std::ostream &out);
void deserializeKeyFiles(std::istream &in, SecretKey &sec_key, KeyPack &keypack);

std::vector<std::pair<int, int>> adjustRankList(std::vector<int> &rank_list);

} // namespace utils
} // namespace detail
} // namespace evi
