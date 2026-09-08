#pragma once

#include "neta/rules/json_value.hpp"

#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace neta::rules {

class JsonParser {
public:
    explicit JsonParser(std::string_view input) : input_(input) {}

    [[nodiscard]] JsonValue parse() {
        skip_ws();
        auto value = parse_value();
        skip_ws();
        if (pos_ != input_.size()) fail("unexpected trailing content");
        return value;
    }

private:
    [[noreturn]] void fail(const std::string& message) const {
        throw std::runtime_error("invalid JSON at byte " + std::to_string(pos_) + ": " + message);
    }

    void skip_ws() {
        while (pos_ < input_.size() &&
               std::isspace(static_cast<unsigned char>(input_[pos_])) != 0) {
            ++pos_;
        }
    }

    bool consume(char expected) {
        skip_ws();
        if (pos_ < input_.size() && input_[pos_] == expected) {
            ++pos_;
            return true;
        }
        return false;
    }

    void expect(char expected) {
        if (!consume(expected)) fail(std::string("expected '") + expected + "'");
    }

    JsonValue parse_value() {
        skip_ws();
        if (pos_ >= input_.size()) fail("unexpected end of input");
        switch (input_[pos_]) {
            case '{': return parse_object();
            case '[': return parse_array();
            case '"': return JsonValue(parse_string());
            case 't': parse_literal("true"); return JsonValue(true);
            case 'f': parse_literal("false"); return JsonValue(false);
            case 'n': parse_literal("null"); return JsonValue{};
            default:
                if (input_[pos_] == '-' || std::isdigit(static_cast<unsigned char>(input_[pos_])) != 0) {
                    return JsonValue(parse_number());
                }
                fail("unexpected token");
        }
    }

    JsonValue parse_object() {
        expect('{');
        JsonValue::Object object;
        skip_ws();
        if (consume('}')) return JsonValue(std::move(object));
        while (true) {
            skip_ws();
            if (pos_ >= input_.size() || input_[pos_] != '"') fail("object key must be a string");
            auto key = parse_string();
            expect(':');
            if (!object.emplace(key, parse_value()).second) fail("duplicate object key: " + key);
            if (consume('}')) break;
            expect(',');
        }
        return JsonValue(std::move(object));
    }

    JsonValue parse_array() {
        expect('[');
        JsonValue::Array array;
        skip_ws();
        if (consume(']')) return JsonValue(std::move(array));
        while (true) {
            array.push_back(parse_value());
            if (consume(']')) break;
            expect(',');
        }
        return JsonValue(std::move(array));
    }

    std::string parse_string() {
        if (pos_ >= input_.size() || input_[pos_] != '"') fail("expected string");
        ++pos_;
        std::string out;
        while (pos_ < input_.size()) {
            const char c = input_[pos_++];
            if (c == '"') return out;
            if (static_cast<unsigned char>(c) < 0x20) fail("control character in string");
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (pos_ >= input_.size()) fail("unterminated escape sequence");
            const char escaped = input_[pos_++];
            switch (escaped) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': parse_unicode_escape(out); break;
                default: fail("unsupported escape sequence");
            }
        }
        fail("unterminated string");
    }

    static void append_utf8(std::string& out, unsigned value) {
        if (value <= 0x7fU) {
            out.push_back(static_cast<char>(value));
        } else if (value <= 0x7ffU) {
            out.push_back(static_cast<char>(0xc0U | (value >> 6U)));
            out.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
        } else {
            out.push_back(static_cast<char>(0xe0U | (value >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((value >> 6U) & 0x3fU)));
            out.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
        }
    }

    void parse_unicode_escape(std::string& out) {
        if (pos_ + 4 > input_.size()) fail("short unicode escape");
        unsigned value = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = input_[pos_++];
            value <<= 4U;
            if (c >= '0' && c <= '9') value |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') value |= 10U + static_cast<unsigned>(c - 'a');
            else if (c >= 'A' && c <= 'F') value |= 10U + static_cast<unsigned>(c - 'A');
            else fail("invalid unicode escape");
        }
        if (value >= 0xd800U && value <= 0xdfffU) fail("surrogate escapes are not supported");
        append_utf8(out, value);
    }

    double parse_number() {
        const std::size_t begin = pos_;
        if (input_[pos_] == '-') ++pos_;
        if (pos_ >= input_.size()) fail("incomplete number");
        if (input_[pos_] == '0') {
            ++pos_;
        } else {
            if (!std::isdigit(static_cast<unsigned char>(input_[pos_]))) fail("invalid number");
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])) != 0) ++pos_;
        }
        if (pos_ < input_.size() && input_[pos_] == '.') {
            ++pos_;
            if (pos_ >= input_.size() || std::isdigit(static_cast<unsigned char>(input_[pos_])) == 0) fail("invalid fraction");
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])) != 0) ++pos_;
        }
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-')) ++pos_;
            if (pos_ >= input_.size() || std::isdigit(static_cast<unsigned char>(input_[pos_])) == 0) fail("invalid exponent");
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])) != 0) ++pos_;
        }
        const std::string text(input_.substr(begin, pos_ - begin));
        char* end = nullptr;
        const double value = std::strtod(text.c_str(), &end);
        if (end == nullptr || *end != '\0' || !std::isfinite(value)) fail("invalid finite number");
        return value;
    }

    void parse_literal(std::string_view literal) {
        if (input_.substr(pos_, literal.size()) != literal) fail("invalid literal");
        pos_ += literal.size();
    }

    std::string_view input_;
    std::size_t pos_{0};
};

} // namespace neta::rules
