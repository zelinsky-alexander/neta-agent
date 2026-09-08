#pragma once

#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace neta::rules {

class JsonValue {
public:
    enum class Type { Null, Boolean, Number, String, Array, Object };

    using Array = std::vector<JsonValue>;
    using Object = std::map<std::string, JsonValue>;

    JsonValue() = default;
    explicit JsonValue(bool value) : type_(Type::Boolean), boolean_(value) {}
    explicit JsonValue(double value) : type_(Type::Number), number_(value) {}
    explicit JsonValue(std::string value) : type_(Type::String), string_(std::move(value)) {}
    explicit JsonValue(Array value) : type_(Type::Array), array_(std::move(value)) {}
    explicit JsonValue(Object value) : type_(Type::Object), object_(std::move(value)) {}

    [[nodiscard]] Type type() const noexcept { return type_; }
    [[nodiscard]] bool is_null() const noexcept { return type_ == Type::Null; }
    [[nodiscard]] bool is_boolean() const noexcept { return type_ == Type::Boolean; }
    [[nodiscard]] bool is_number() const noexcept { return type_ == Type::Number; }
    [[nodiscard]] bool is_string() const noexcept { return type_ == Type::String; }
    [[nodiscard]] bool is_array() const noexcept { return type_ == Type::Array; }
    [[nodiscard]] bool is_object() const noexcept { return type_ == Type::Object; }

    [[nodiscard]] bool as_boolean() const {
        require(Type::Boolean, "boolean");
        return boolean_;
    }

    [[nodiscard]] double as_number() const {
        require(Type::Number, "number");
        return number_;
    }

    [[nodiscard]] const std::string& as_string() const {
        require(Type::String, "string");
        return string_;
    }

    [[nodiscard]] const Array& as_array() const {
        require(Type::Array, "array");
        return array_;
    }

    [[nodiscard]] const Object& as_object() const {
        require(Type::Object, "object");
        return object_;
    }

    [[nodiscard]] const JsonValue& at(const std::string& key) const {
        const auto& object = as_object();
        const auto it = object.find(key);
        if (it == object.end()) throw std::runtime_error("missing JSON field: " + key);
        return it->second;
    }

    [[nodiscard]] const JsonValue* find(const std::string& key) const {
        const auto& object = as_object();
        const auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }

private:
    void require(Type expected, const char* label) const {
        if (type_ != expected) throw std::runtime_error(std::string("JSON value is not a ") + label);
    }

    Type type_{Type::Null};
    bool boolean_{false};
    double number_{0.0};
    std::string string_;
    Array array_;
    Object object_;
};

} // namespace neta::rules
