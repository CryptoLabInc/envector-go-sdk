
#pragma once

#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace evi {

struct LocalProviderMeta {
    std::string type = "LOCAL";
    std::string provider_version = "1";
    std::string version_id;
    std::string wrap_alg;

    nlohmann::ordered_json toJson(bool is_secret = false) const {
        return nlohmann::ordered_json{
            {"type", type},
            {"provider_version", provider_version},
            {"version_id", version_id},
            {"wrap_alg", wrap_alg},
        };
    }
};

enum class ProviderType {
    Local,
    AwsSecretManager,
};

struct ProviderMeta {
    ProviderType type{ProviderType::Local};
    std::variant<LocalProviderMeta> value{LocalProviderMeta{}};

    ProviderMeta() = default;

    ProviderMeta(const LocalProviderMeta &meta) : type(ProviderType::Local), value(meta) {}
    ProviderMeta(LocalProviderMeta &&meta) : type(ProviderType::Local), value(std::move(meta)) {}

    static ProviderMeta makeLocal(LocalProviderMeta meta) {
        return ProviderMeta(std::move(meta));
    }

    // casting local type
    LocalProviderMeta *asLocal() {
        return std::get_if<LocalProviderMeta>(&value);
    }
    const LocalProviderMeta *asLocal() const {
        return std::get_if<LocalProviderMeta>(&value);
    }

    nlohmann::ordered_json toJson(bool is_secret = false) const {
        return std::visit(
            [is_secret](auto const &meta) {
                return meta.toJson(is_secret);
            },
            value);
    }
};

} // namespace evi
