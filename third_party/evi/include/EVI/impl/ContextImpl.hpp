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
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/NTT.hpp"
#include "EVI/impl/Parameter.hpp"
#include "EVI/impl/Type.hpp"
#include "utils/span.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace evi {
namespace detail {

class ContextImpl {
public:
    ContextImpl(const evi::ParameterPreset preset, const evi::DeviceType device_type, const u64 rank,
                const evi::EvalMode eval_mode, std::optional<const int> device_id = std::nullopt);
    ContextImpl(evi::ParameterPreset preset, const u64 rank, u64 prime_q, u64 prime_p, u64 psi_q, u64 psi_p,
                double scale_factor, u32 hamming_weight);
    ~ContextImpl();

    void negateModQ(span<u64> p);
    void negateModP(span<u64> p);
    void addModQ(const span<u64> op1, const span<u64> op2, span<u64> res);
    void addModP(const span<u64> op1, const span<u64> op2, span<u64> res);
    void multModQ(const span<u64> op1, const span<u64> op2, span<u64> res);
    void multModP(const span<u64> op1, const span<u64> op2, span<u64> res);
    void madModQ(const span<u64> op1, const span<u64> op2, span<u64> res);
    void madModQ(const span<u64> op1, const u64 op2, span<u64> res);
    void madModP(const span<u64> op1, const span<u64> op2, span<u64> res);

    void nttModQ(span<u64> p);
    void nttModQMini(span<u64> p, const u64 pad_rank);
    void nttModP(span<u64> p);
    void nttModPMini(span<u64> p, const u64 pad_rank);
    void inttModQ(span<u64> p);
    void inttModQ(span<u64> p, u64 fullmod);
    void inttModP(span<u64> p);
    void precomputeShiftNTT();

    void shiftIndexQ(const u64 index, const span<u64> ptxt_q, span<u64> out_q);
    void shiftIndexP(const u64 index, const span<u64> ptxt_p, span<u64> out_p);
    void shiftIndexQ(const u64 index, const span<u64> ctxt_input_a, const span<u64> ctxt_input_b, span<u64> out_a,
                     span<u64> out_b);
    void shiftIndexP(const u64 index, const span<u64> ctxt_input_a, const span<u64> ctxt_input_b, span<u64> out_a,
                     span<u64> out_b);

    void modDown(span<u64> poly_q, span<u64> poly_p);
    void modUp(const span<u64> poly_q, span<u64> poly_p);
    void normalizeMod(const span<u64> in, span<u64> out, u64 mod_in, u64 mod_out, u64 barr_out);

    const u32 &getShowRank() const {
        return show_rank_;
    }
    const u32 &getRank() const {
        return rank_;
    }
    const u32 &getPadRank() const {
        return pad_rank_;
    }
    const u32 &getInnerRank() const {
        return rank_;
    }
    const u32 &getNumInputCtxt() const {
        return num_input_cipher_;
    }
    const u64 &getItemsPerCtxt() const {
        return items_per_ctxt_;
    }
    const DeviceType &getDeviceType() const {
        return dtype_;
    }
    const EvalMode &getEvalMode() const {
        return mode_;
    }
    const Parameter getParam() const {
        return param_;
    }
    double getScaleFactor() const {
        return param_->getScaleFactor();
    }
    int getDeviceId() const {
        return device_id_.value_or(0);
    }

    void addModQGpu(u64 *res, const u64 *op1, const u64 *op2, const u32 num_ctxt);
    void nttModQ(const u64 *in, u64 *out, const u32 num_ctxt = 1, bool on_gpu = false);
    void nttModP(const u64 *in, u64 *out, const u32 num_ctxt = 1, bool on_gpu = false);
    void inttModQ(const u64 *in, u64 *out, const u32 num_ctxt = 1, bool on_gpu = false);
    void inttModP(const u64 *in, u64 *out, const u32 num_ctxt = 1, bool on_gpu = false);

    void inttP2ModP(const u64 *in, u64 *out, const u32 num_ctxt);
    void inttP2ModQ(const u64 *in, u64 *out, const u32 num_ctxt);
    void inttP1ModP(u64 *out, const u32 num_ctxt);
    void inttP1ModQ(u64 *out, const u32 num_ctxt);
    void nttP1ModP(const u64 *in, u64 *out, const u32 num_ctxt);
    void nttP1ModQ(const u64 *in, u64 *out, const u32 num_ctxt);
    void nttP2ModP(u64 *out, const u32 num_ctxt);
    void nttP2ModQ(u64 *out, const u32 num_ctxt);
    void nttP2ModDown(u64 *in, u64 *out, const u32 num_ctxt);

    u64 *w_q_gpu_;
    u64 *w_p_gpu_;
    u64 *w_shoup_q_gpu_;
    u64 *w_shoup_p_gpu_;
    u64 *inv_w_q_gpu_;
    u64 *inv_w_p_gpu_;
    u64 *inv_w_shoup_q_gpu_;
    u64 *inv_w_shoup_p_gpu_;
    u64 *ntt_tmp;

#ifdef ENABLE_IVF
    void getShiftGPU();
    std::vector<u64 *> shift_ctxt_q_gpu;
    std::vector<u64 *> shift_ctxt_p_gpu;
    u64 *shift_q;
    u64 *shift_p;
    u64 *shift_tmp;
    void shiftAddTensor(const u64 *ptxt_q, const u64 *ptxt_p, u64 **in1, u64 **in2, u64 *out_a_q, u64 *out_a_p,
                        u64 *out_b_q, u64 *out_b_p, const u64 *shift_idx, const u32 size);
#endif // ENABLE_IVF

private:
    void initGPU();
    void releaseGPU();

    const evi::detail::Parameter param_;
    const evi::DeviceType dtype_;
    const evi::EvalMode mode_;

    std::vector<poly> shift_ctxt_q_;
    std::vector<poly> shift_ctxt_p_;

    std::optional<int> device_id_;

    NTT ntt_q_;
    NTT ntt_q_rank_;
    NTT ntt_p_;
    NTT ntt_p_rank_;

    u32 show_rank_;
    u32 rank_;
    u32 pad_rank_;
    u32 log_pad_rank_;
    u32 num_input_cipher_;
    u64 items_per_ctxt_;
};

class Context : public std::shared_ptr<ContextImpl> {
public:
    Context(std::shared_ptr<ContextImpl> ptr) : std::shared_ptr<ContextImpl>(ptr) {}
    Context &operator=(std::shared_ptr<ContextImpl> ptr) {
        std::shared_ptr<ContextImpl>::operator=(ptr);
        return *this;
    }

    const DeviceType &getDeviceType() const {
        return (*this)->getDeviceType();
    }

    double getScaleFactor() const {
        return (*this)->getScaleFactor();
    }

    u32 getPadRank() const {
        return (*this)->getPadRank();
    }

    u32 getShowRank() const {
        return (*this)->getShowRank();
    }

    EvalMode getEvalMode() const {
        return (*this)->getEvalMode();
    }
};

Context makeContext(evi::ParameterPreset preset, const evi::DeviceType device_type, const u64 rank,
                    const evi::EvalMode eval_mode, std::optional<const int> device_id = std::nullopt);

} // namespace detail
} // namespace evi
