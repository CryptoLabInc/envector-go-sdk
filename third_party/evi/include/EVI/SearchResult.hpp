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
#include "EVI/Export.hpp"
#include <cstdint>
#include <istream>
#include <memory>
#include <optional>
#include <ostream>

namespace evi {

namespace detail {
class SearchResult;
}

/**
 * @class SearchResult
 * @brief Represents the encrypted result of a search operation.
 *
 * A `SearchResult` holds the encrypted data returned from a homomorphic
 * search. To interpret the result, it must be decrypted
 * using a `Decryptor` and a valid `SecretKey`.
 */
class EVI_API SearchResult {
public:
    /// @brief Default constructor creates an empty `SearchResult`.
    SearchResult() = default;

    /**
     * @brief Constructs a `SearchResult` from an internal implementation.
     * @param impl Shared pointer to the internal `detail::SearchResult` object.
     */
    explicit SearchResult(std::shared_ptr<detail::SearchResult> impl);

    /**
     * @brief Deserializes a `SearchResult` from an input stream.
     * @param is Input stream containing the serialized search result.
     * @return A deserialized `SearchResult` instance.
     */
    static SearchResult deserializeFrom(std::istream &is);

    /**
     * @brief Serializes a `SearchResult` to an output stream.
     * @param res The `SearchResult` instance to serialize.
     * @param os Output stream to write the serialized result.
     */
    static void serializeTo(const SearchResult &res, std::ostream &os);

    /**
     * @brief Returns the number of items currently stored.
     * @return Item count.
     */
    uint32_t getItemCount();

private:
    std::shared_ptr<detail::SearchResult> impl_;

    /// @cond INTERNAL
    friend std::shared_ptr<detail::SearchResult> &getImpl(SearchResult &) noexcept;
    friend const std::shared_ptr<detail::SearchResult> &getImpl(const SearchResult &) noexcept;
    /// @endcond
};

} // namespace evi
