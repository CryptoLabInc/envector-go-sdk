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
#include "EVI/impl/Const.hpp"

#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

class AES {
public:
    static bool encryptAESGCM(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                              std::vector<uint8_t> &iv, std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &tag);
    static bool decryptAESGCM(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key,
                              const std::vector<uint8_t> &iv, std::vector<uint8_t> &plaintext,
                              const std::vector<uint8_t> &tag);
};
