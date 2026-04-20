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
#include "EVI/impl/Const.hpp"

#include "utils/Exceptions.hpp"
#include "utils/span.hpp"

#include <iostream>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace evi {
namespace detail {

#define LEVEL1 1
class Message : public std::vector<float> {
public:
    using std::vector<float>::vector;
    Message() : std::vector<float>() {}
    Message(u32 size, float val) : std::vector<float>(size, val) {}
};
using Coefficients = int *;

// #define alignment_byte 256
template <typename T, std::size_t N>
struct alignas(alignment_byte) AlignedArray : public std::array<T, N> {};

using s_poly = AlignedArray<i64, DEGREE>;
using poly = AlignedArray<u64, DEGREE>;

using polyvec = std::vector<u64, AlignedAllocator<u64, alignment_byte>>;
using polyvec128 = std::vector<u128, AlignedAllocator<u128, alignment_byte>>;
using polydata = u64 *;

struct IQuery {
public:
    u64 dim;
    u64 show_dim;
    u64 degree;
    u64 n;
    u64 scale_bit;
    evi::EncodeType encode_type;

    virtual void serializeTo(std::vector<u8> &buf) const = 0;
    virtual void deserializeFrom(const std::vector<u8> &buf) = 0;
    virtual void serializeTo(std::ostream &stream) const = 0;
    virtual void deserializeFrom(std::istream &stream) = 0;

    virtual poly &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) = 0;
    virtual const poly &getPoly(const int pos, const int level,
                                std::optional<const int> index = std::nullopt) const = 0;

    virtual polydata getPolyData(const int pos, const int level, std::optional<const int> index = std::nullopt) = 0;
    virtual polydata getPolyData(const int pos, const int level,
                                 std::optional<const int> index = std::nullopt) const = 0;

    virtual polyvec128 &getPoly() = 0;
    virtual u128 *getPolyData() = 0;

    virtual DataType &getDataType() = 0;
    virtual int &getLevel() = 0;
};

template <DataType T>
struct SingleBlock : IQuery {
public:
    SingleBlock(const int level);
    SingleBlock(const poly &a_q);
    SingleBlock(const poly &a_q, const poly &b_q);
    SingleBlock(const poly &a_q, const poly &a_p, const poly &b_q, const poly &b_p);

    SingleBlock(std::istream &stream);
    SingleBlock(std::vector<u8> &buf);

    poly &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) override;
    const poly &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) const override;
    polydata getPolyData(const int pos, const int leve, std::optional<const int> index = std::nullopt) override;
    polydata getPolyData(const int pos, const int level, std::optional<const int> index = std::nullopt) const override;

    void serializeTo(std::vector<u8> &buf) const override;
    void deserializeFrom(const std::vector<u8> &buf) override;
    void serializeTo(std::ostream &stream) const override;
    void deserializeFrom(std::istream &stream) override;

    DataType &getDataType() override {
        return dtype_;
    }
    int &getLevel() override {
        return level_;
    }

    // For SerializedQuery instantiaton
    [[noreturn]] polyvec128 &getPoly() override {
        throw InvalidAccessError("Not compatible type to access to 128-bit array");
    }
    [[noreturn]] u128 *getPolyData() override {
        throw InvalidAccessError("Not compatible type to access to 128-bit array");
    }

private:
    DataType dtype_;
    int level_;
    poly b_q_;
    poly b_p_;
    poly a_q_;
    poly a_p_;
};

template <DataType T>
struct SerializedSingleQuery : IQuery {
    SerializedSingleQuery(polyvec128 &ptxt);

    [[noreturn]] poly &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) override {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    }
    [[noreturn]] const poly &getPoly(const int pos, const int level,
                                     std::optional<const int> index = std::nullopt) const override {

        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    }
    [[noreturn]] polydata getPolyData(const int pos, const int leve,
                                      std::optional<const int> index = std::nullopt) override {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    }
    [[noreturn]] polydata getPolyData(const int pos, const int level,
                                      std::optional<const int> index = std::nullopt) const override {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    }

    polyvec128 &getPoly() override;
    u128 *getPolyData() override;

    void serializeTo(std::vector<u8> &buf) const override {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    }
    void deserializeFrom(const std::vector<u8> &buf) override {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    }
    void serializeTo(std::ostream &stream) const override {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    }
    void deserializeFrom(std::istream &stream) override {
        throw InvalidAccessError("Not compatible type to access to 64-bit array");
    }

    DataType &getDataType() override {
        return dtype_;
    }
    int &getLevel() override {
        return level_;
    }

private:
    DataType dtype_;
    int level_;
    polyvec128 ptxt_;
};

class Query {
public:
    using SingleQuery = std::shared_ptr<IQuery>;
    using SingleContainer = std::vector<SingleQuery>;

    Query() = default;

    explicit Query(SingleContainer container) : single_blocks_(std::move(container)) {}

    SingleContainer &single() {
        return single_blocks_;
    }
    const SingleContainer &single() const {
        return single_blocks_;
    }

    std::size_t size() const {
        return single_blocks_.size();
    }
    bool empty() const {
        return single_blocks_.empty();
    }
    void reserve(std::size_t count) {
        single_blocks_.reserve(count);
    }

    SingleQuery &operator[](std::size_t index) {
        return single_blocks_[index];
    }
    const SingleQuery &operator[](std::size_t index) const {
        return single_blocks_[index];
    }

    SingleQuery &at(std::size_t index) {
        return single_blocks_.at(index);
    }
    const SingleQuery &at(std::size_t index) const {
        return single_blocks_.at(index);
    }

    SingleQuery &front() {
        return single_blocks_.front();
    }
    const SingleQuery &front() const {
        return single_blocks_.front();
    }

    SingleQuery &back() {
        return single_blocks_.back();
    }
    const SingleQuery &back() const {
        return single_blocks_.back();
    }

    void push_back(const SingleQuery &value) { // NOLINT(readability-identifier-naming)
        single_blocks_.push_back(value);
    }
    void push_back(SingleQuery &&value) { // NOLINT(readability-identifier-naming)
        single_blocks_.push_back(std::move(value));
    }

    void append(const Query &other) {
        single_blocks_.insert(single_blocks_.end(), other.single_blocks_.begin(), other.single_blocks_.end());
    }

    SingleQuery &emplace_back(SingleQuery value) { // NOLINT(readability-identifier-naming)
        single_blocks_.emplace_back(std::move(value));
        return single_blocks_.back();
    }

    void clear() {
        single_blocks_.clear();
    }
    auto begin() {
        return single_blocks_.begin();
    }
    auto end() {
        return single_blocks_.end();
    }
    auto begin() const {
        return single_blocks_.begin();
    }
    auto end() const {
        return single_blocks_.end();
    }

    void setInnerItemCount(u32 count) {
        inner_item_count_ = count;
    }
    u32 getInnerItemCount() const {
        return inner_item_count_;
    }
    void setItemCount(u32 count) {
        total_item_count_ = count;
    }
    u32 getItemCount() const {
        return total_item_count_;
    }

private:
    SingleContainer single_blocks_;
    u32 inner_item_count_ = 0;
    u32 total_item_count_ = 0;
};

struct IData {
public:
    u64 dim;
    u64 degree;
    u64 n;

    virtual polyvec &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) = 0;
    virtual const polyvec &getPoly(const int pos, const int level,
                                   std::optional<const int> index = std::nullopt) const = 0;
    virtual polydata getPolyData(const int pos, const int level, std::optional<const int> index = std::nullopt) = 0;
    virtual polydata getPolyData(const int pos, const int level,
                                 std::optional<const int> index = std::nullopt) const = 0;

    virtual void serializeTo(std::vector<u8> &buf) const = 0;
    virtual void deserializeFrom(const std::vector<u8> &buf) = 0;
    virtual void serializeTo(std::ostream &stream) const = 0;
    virtual void deserializeFrom(std::istream &stream) = 0;

    virtual void setSize(const int size, std::optional<int> = std::nullopt) = 0;

    virtual DataType &getDataType() = 0;
    virtual int &getLevel() = 0;
};

template <DataType T>
struct Matrix : public IData {
public:
    Matrix(const int level);
    Matrix(polyvec q);
    Matrix(polyvec a_q, polyvec b_q);
    Matrix(polyvec a_q, polyvec a_p, polyvec b_q, polyvec b_p);

    polyvec &getPoly(const int pos, const int level, std::optional<const int> index = std::nullopt) override;
    polydata getPolyData(const int pos, const int level, std::optional<const int> index = std::nullopt) override;
    const polyvec &getPoly(const int pos, const int level,
                           std::optional<const int> index = std::nullopt) const override;
    polydata getPolyData(const int pos, const int level, std::optional<const int> index = std::nullopt) const override;

    void serializeTo(std::vector<u8> &buf) const override;
    void deserializeFrom(const std::vector<u8> &buf) override;
    void serializeTo(std::ostream &stream) const override;
    void deserializeFrom(std::istream &stream) override;

    void setSize(const int size, std::optional<int> = std::nullopt) override;
    DataType &getDataType() override {
        return dtype_;
    }
    int &getLevel() override {
        return level_;
    }

private:
    DataType dtype_;
    int level_;
    polyvec a_q_;
    polyvec a_p_;
    polyvec b_q_;
    polyvec b_p_;
};

struct IPSearchResult {
    std::shared_ptr<IData> ip_data;
};

class SearchResult {
public:
    SearchResult() : ipsearch_(std::make_shared<IPSearchResult>()) {}
    explicit SearchResult(std::shared_ptr<IPSearchResult> impl) : ipsearch_(std::move(impl)) {}

    // Getter (IP)
    IPSearchResult *operator->() noexcept {
        return ipsearch_.get();
    }
    const IPSearchResult *operator->() const noexcept {
        return ipsearch_.get();
    }

    std::shared_ptr<IPSearchResult> get() const {
        return ipsearch_;
    }
    std::shared_ptr<IData> getIP() const {
        return ipsearch_->ip_data;
    }

    // Setter (IP)
    void set(std::shared_ptr<IPSearchResult> impl) {
        ipsearch_ = std::move(impl);
    }
    void setIP(std::shared_ptr<IData> ip) {
        ipsearch_->ip_data = std::move(ip);
    }

    u32 getTotalItemCount() const {
        return total_item_count;
    }

    u32 total_item_count = 0;

private:
    std::shared_ptr<IPSearchResult> ipsearch_;
};

using DataState = std::shared_ptr<IData>;
using Blob = std::vector<DataState>;

struct VariadicKeyType : std::shared_ptr<Matrix<DataType::CIPHER>> {
    VariadicKeyType() : std::shared_ptr<Matrix<DataType::CIPHER>>(std::make_shared<Matrix<DataType::CIPHER>>(LEVEL1)) {}
    VariadicKeyType(const VariadicKeyType &to_copy) : std::shared_ptr<Matrix<DataType::CIPHER>>(to_copy) {}
};

struct FixedKeyType : std::shared_ptr<SingleBlock<DataType::CIPHER>> {
    FixedKeyType()
        : std::shared_ptr<SingleBlock<DataType::CIPHER>>(std::make_shared<SingleBlock<DataType::CIPHER>>(LEVEL1)) {}
    FixedKeyType(const FixedKeyType &to_copy) : std::shared_ptr<SingleBlock<DataType::CIPHER>>(to_copy) {}
};

template <DataType T>
struct PolyData {
    void setSize(const int size);
    int getSize() const;
    polydata &getPolyData(const int pos, const int level, std::optional<int> idx = std::nullopt);

    std::vector<polydata> a_q;
    std::vector<polydata> a_p;
    std::vector<polydata> b_q;
    std::vector<polydata> b_p;
};

template <DataType T>
using DeviceData = std::shared_ptr<PolyData<T>>;

} // namespace detail
} // namespace evi
