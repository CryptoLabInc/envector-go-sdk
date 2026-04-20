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
#include "EVI/Export.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace evi {
namespace detail {
class Context;
}

/**
 * @class Context
 * @brief Represents the runtime context for homomorphic encryption operations.
 *
 * This class holds internal-related configuration and resources, such as device selection,
 * dimension, and parameter presets.
 *
 * To construct a Context instance, use the `makeContext` or `makeMultiContext` factory functions.
 */
class EVI_API Context {
public:
    /// @brief Empty handle; initialize with makeContext() or makeMultiContext() before use.
    Context() : impl_(nullptr) {}

    /**
     * @brief Constructs a Context from an internal implementation.
     * @param impl Shared pointer to the internal `detail::Context` object.
     */
    explicit Context(std::shared_ptr<detail::Context> impl) noexcept;

    /**
     * @brief Returns the device type (CPU/GPU) backing this Context.
     * @return The configured device type.
     */
    DeviceType getDeviceType();

    /**
     * @brief Returns the scaling factor used for encoding.
     * @return Scaling factor as a double.
     */
    double getScaleFactor() const;

    /**
     * @brief Returns the internal padded rank used.
     * @return The padded rank size.
     */
    double getPadRank() const;

    /**
     * @brief Returns the show rank, user-specified input vector length, for this Context.
     * @return The show rank size.
     */
    uint32_t getShowDim() const;

    /**
     * @brief Get the evaluation mode used in this context. (e.g FLAT, RMP, MM)
     * @return EvalMode The evaluation mode.
     */
    EvalMode getEvalMode() const;

private:
    std::shared_ptr<detail::Context> impl_;

    /// @cond INTERNAL
    friend std::shared_ptr<detail::Context> &getImpl(Context &) noexcept;
    friend const std::shared_ptr<detail::Context> &getImpl(const Context &) noexcept;
    /// @endcond
};

/**
 * @brief Creates a new Context instance with the given encryption parameters.
 *
 * @param preset Parameter preset for homomorphic encryption (e.g., IP0).
 * @param device_type Target device type (CPU or GPU).
 * @param dim Dimension of input vectors.
 * @param eval_mode Evaluation mode to use (RMP, FLAT).
 * @param device_id Optional device ID for GPU execution.
 * @return A configured `Context` object.
 */
EVI_API Context makeContext(evi::ParameterPreset preset, const evi::DeviceType device_type, const uint64_t dim,
                            const evi::EvalMode eval_mode, std::optional<const int> device_id = std::nullopt);

/**
 * @brief Creates multiple Context instances for use with multiple dimensions.
 *
 * @param preset Parameter preset for homomorphic encryption (e.g., IP0).
 * @param device_type Target device type (CPU or GPU).
 * @param eval_mode Evaluation mode to use (RMP, FLAT).
 * @param device_id Optional device ID for GPU execution.
 * @return A list of configured `Context` objects.
 */
EVI_API std::vector<Context> makeMultiContext(evi::ParameterPreset preset, evi::DeviceType device_type,
                                              evi::EvalMode eval_mode,
                                              std::optional<const int> device_id = std::nullopt);

} // namespace evi
