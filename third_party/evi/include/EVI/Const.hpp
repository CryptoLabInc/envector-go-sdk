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

namespace evi {

constexpr uint64_t DEGREE = 4096;

constexpr int MIN_CONTEXT_SIZE_LOG = 5;
constexpr int MAX_CONTEXT_SIZE_LOG = 12;
constexpr int MIN_CONTEXT_SIZE = 1 << MIN_CONTEXT_SIZE_LOG;
constexpr int MAX_CONTEXT_SIZE = 1 << MAX_CONTEXT_SIZE_LOG;
constexpr int NUM_CONTEXT = MAX_CONTEXT_SIZE_LOG - MIN_CONTEXT_SIZE_LOG + 1;

constexpr int SEED_MIN_SIZE = 64;

} // namespace evi
