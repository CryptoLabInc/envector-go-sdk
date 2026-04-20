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

#include <string>

#ifndef USE_PROFILE
#define TRACE(...)
#define TRACE_BEGIN(...)
#define TRACE_END()
#else
#include <perfetto.h>

static constexpr const char *ctg = "EVI";
PERFETTO_DEFINE_CATEGORIES(perfetto::Category(ctg).SetDescription("EVI events"));

#define TRACE(...) TRACE_EVENT(ctg, __VA_ARGS__)
#define TRACE_BEGIN(...) TRACE_EVENT_BEGIN(ctg, __VA_ARGS__)
#define TRACE_END() TRACE_EVENT_END(ctg)

static constexpr int32_t TRACE_DURATION_MS = 0;
static constexpr int32_t FLUSH_PERIOD_MS = 1000;
static constexpr int32_t BUFFER_SIZE_KB = 128;
static constexpr int32_t PERFETTO_FILE_MODE = 0644;

class Perfetto {
public:
    Perfetto() = delete;
    Perfetto(const std::string &catgegory_name);

    void start();
    void start(const std::string &trace_file_name);
    void stop();

private:
    void startSession(const std::string &trace_file_name);
    bool inCtgs(const std::string &input) {
        return std::find(ctgs_.begin(), ctgs_.end(), input) != ctgs_.end();
    };

    std::vector<std::string> ctgs_ = {"EVI"}; // pre-defined Categories
    bool initialized_ = false;
    std::string ctg_name_;
    std::unique_ptr<perfetto::TracingSession> tracing_session_;
    int fd_ = -1;
};

#endif
