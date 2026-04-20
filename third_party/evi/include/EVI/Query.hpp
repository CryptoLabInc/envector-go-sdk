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
#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

namespace evi {
namespace detail {
class Query;
}

/**
 * @class Query
 * @brief Represents an encoded query or encrypted data vector used in homomorphic encryption.
 *
 * The `Query` holds encoded data for either an encrypted item or a search query.
 * It is typically generated using an `Encryptor` when encoding or encrypting data, and is used
 * during search or evaluation operations.
 */
class EVI_API Query {
public:
    Query() noexcept : impl_(nullptr) {}

    /**
     * @brief Constructs a Query from an internal implementation.
     * @param impl Shared pointer to the internal `detail::Query` object.
     */
    explicit Query(std::shared_ptr<detail::Query> impl) noexcept;

    /**
     * @brief Returns the computation level of item.
     * @return Level indicator.
     */
    uint32_t getLevel() const;

    /**
     * @brief Returns the show rank, user-specified input vector length, for this Context.
     * @return The show rank size.
     */
    uint32_t getShowDim() const;

    /**
     * @brief Returns the inner single query item count.
     * @return The innter item count.
     */
    uint32_t getInnerItemCount() const;

    /**
     * @brief Returns the number of blocks in this Query.
     * @return Number of blocks.
     */
    std::size_t size() const;

    /**
     * @brief Returns the number of items in the inner single query.
     * @return The inner item count.
     */
    static Query deserializeFrom(std::istream &is);

    /**
     * @brief Reads a Query from a string.
     * @param data Input string containing serialized query.
     * @return Deserialized Query.
     */
    static Query deserializeFromString(const std::string &data);

    /**
     * @brief Writes a Query to a binary stream.
     * @param query Query to serialize.
     * @param os Output stream to receive serialized data.
     */
    static void serializeTo(const Query &query, std::ostream &os);

    /**
     * @brief Write Query to a string.
     * @param query Query to serialize.
     * @param out Output string to receive serialized data.
     */
    static void serializeToString(const Query &query, std::string &out);

    /**
     * @brief Writes multiple Query objects to a binary stream.
     * @param queries Sequence of queries to serialize.
     * @param os Output stream to receive serialized data.
     */
    static void serializeVectorTo(const std::vector<Query> &queries, std::ostream &os);

    /**
     * @brief Writes multiple Query objects to a string.
     * @param queries Sequence of queries to serialize.
     * @param out Output string to receive serialized data.
     */
    static void serializeVectorToString(const std::vector<Query> &queries, std::string &out);

    /**
     * @brief Reads multiple Query objects from a binary stream.
     * @param is Input stream containing serialized queries.
     * @return Deserialized query sequence.
     */
    static std::vector<Query> deserializeVectorFrom(std::istream &is);

    /**
     * @brief Reads multiple Query objects from a string.
     * @param data Input string containing serialized queries.
     * @return Deserialized query sequence.
     */
    static std::vector<Query> deserializeVectorFromString(const std::string &data);

private:
    std::shared_ptr<detail::Query> impl_;

    /// @cond INTERNAL
    friend std::shared_ptr<detail::Query> &getImpl(Query &) noexcept;
    friend const std::shared_ptr<detail::Query> &getImpl(const Query &) noexcept;
    /// @endcond
};

} // namespace evi
