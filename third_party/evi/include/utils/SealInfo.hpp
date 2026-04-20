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
#include <cstdint>
#include <string>
#include <vector>

#include "EVI/Enums.hpp"

namespace evi {
namespace detail {

struct SealInfo {
public:
    SealMode s_mode;
    int h_con_num = 0;
    int h_auth_id = 0;
    std::string h_auth_pw = "";
    std::vector<uint8_t> kek;

    SealInfo(SealMode m) : s_mode(m) {}
    SealInfo(SealMode m, std::vector<uint8_t> buf) : s_mode(m), kek(std::move(buf)) {}
    SealInfo(SealMode m, int cm, int id, std::string pw) : s_mode(m), h_con_num(cm), h_auth_id(id), h_auth_pw(pw) {}
};
} // namespace detail
} // namespace evi
