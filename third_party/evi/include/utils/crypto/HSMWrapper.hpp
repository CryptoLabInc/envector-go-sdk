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
#ifdef BUILD_YUBIHSM
#include <yubihsm.h>

#include "EVI/impl/Const.hpp"
#include "utils/SealInfo.hpp"
#include <iostream>
#include <string>

#define CONNECTOR_URL "http://localhost"
#define USB_URL "yhusb://serial"
#define LABEL "CRYPTOLAB"
#define DOMAIN 1

class HSMWrapper {
private:
    yh_connector *connector_ = nullptr;
    yh_session *session_ = nullptr;
    bool isInit_ = false;
    evi::detail::SealInfo &s_info_;

    yh_rc Initialize(int authId, const char *authPw, const char *addr);
    void Deinitialize();
    yh_rc GetRandomNum(uint8_t *buffer, size_t size);

public:
    HSMWrapper(evi::SealInfo &s_info);
    yh_rc GetWrapKek(uint16_t *objId, uint8_t *kek, size_t kekLen, uint8_t *wrapKek, size_t *wrapKekLen);
    yh_rc GetUnwrapKek(uint16_t objId, uint8_t *wrapKek, size_t wrapKekLen, uint8_t *kek, size_t *kekLen);
};
#endif
