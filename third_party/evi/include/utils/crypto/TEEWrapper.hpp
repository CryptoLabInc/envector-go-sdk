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
#include "EVI/SealInfo.hpp"
#include "utils/crypto/AES.hpp"
#ifdef BUILD_YUBIHSM
#include "EVI/HSMWrapper.hpp"
#endif
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>

class TEEWrapper {

public:
    TEEWrapper(evi::detail::SealInfo &s_info);
    void saveSealedSecKey(std::ostream &os, evi::ParameterPreset preset, std::stringstream &seckey,
                          std::vector<uint8_t> &vec);
    void getUnsealedSecKey(std::istream &is, evi::ParameterPreset preset, std::stringstream &seckey,
                           std::vector<uint8_t> &vec);

#ifdef BUILD_YUBIHSM
    void saveSealedSecKeyHSM(std::ostream &os, int32_t *preset, std::stringstream &seckey);
    void getUnsealedSecKeyHSM(std::istream &is, int32_t *preset, std::stringstream &seckey);
#endif

private:
    evi::detail::SealInfo &s_info_;
#ifdef BUILD_YUBIHSM
    std::optional<HSMWrapper> hsmw_;
#endif
};
