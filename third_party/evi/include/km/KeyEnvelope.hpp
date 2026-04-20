////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
// This software and/or source code may be commercially used and/or           //
// disseminated only with the written permission of CryptoLab Inc,            //
// or in accordance with the terms and conditions stipulated in the           //
// agreement/contract under which the software and/or source code has been    //
// supplied by CryptoLab Inc. Any unauthorized commercial use and/or          //
// dissemination of this file is strictly prohibited and will constitute      //
// an infringement of copyright.                                              //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "utils/Exceptions.hpp"

#include "km/ProviderMeta.hpp"
#include "nlohmann/json.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace evi {

namespace detail {

// all
struct KeyV1Requester { // TODO : set
    std::string entity;
    std::string type;
    std::string method;
};

// all
struct KeyEntryParameter {
    uint64_t Q{0};
    uint64_t P{0};
    double DB_SCALE_FACTOR{0};
    double QUERY_SCALE_FACTOR{0};
    std::string preset;
};

// all
struct KeyEntryMetadata {
    KeyEntryParameter parameter;
    std::string eval_mode;          // for only eval mode
    std::optional<std::string> dim; // optional
};

struct KeyState {
    std::string value; // active | suspended | compromised | destroyed
    std::optional<std::string> reason;
    std::string updated_at;
};

} // namespace detail

struct ProviderEntry {
    std::string name;
    std::string format_version;
    std::string role;
    std::string hash;
    detail::KeyEntryMetadata metadata;
    std::string key_data;

    std::optional<std::string> alg; // -> for local wrap secretkey using kek
    std::optional<std::string> iv;
    std::optional<std::string> tag;
};

struct ProviderEnvelope {
    ProviderMeta provider_meta;
    std::vector<ProviderEntry> entries;
};

} // namespace evi
