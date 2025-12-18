#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <variant>
#include <memory>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <cstdint>
#include <cstring>

namespace nlohmann {

class json {
public:
    using object_t = std::unordered_map<std::string, json>;
    using array_t = std::vector<json>;
    using string_t = std::string;
    using boolean_t = bool;
    using number_integer_t = std::int64_t;
    using number_unsigned_t = std::uint64_t;
    using number_float_t = double;

    json() = default;
    json(std::nullptr_t) : m_type(type::null) {}
    json(bool val) : m_type(type::boolean), m_value(val) {}
    json(int val) : m_type(type::number_integer), m_value(static_cast<number_integer_t>(val)) {}
    json(unsigned int val) : m_type(type::number_unsigned), m_value(static_cast<number_unsigned_t>(val)) {}
    json(long long val) : m_type(type::number_integer), m_value(static_cast<number_integer_t>(val)) {}
    json(unsigned long long val) : m_type(type::number_unsigned), m_value(val) {}
    json(double val) : m_type(type::number_float), m_value(val) {}
    json(const char* val) : m_type(type::string), m_value(std::string(val)) {}
    json(const std::string& val) : m_type(type::string), m_value(val) {}
    json(const array_t& val) : m_type(type::array), m_value(val) {}
    json(const object_t& val) : m_type(type::object), m_value(val) {}

    // Type checking
    bool is_null() const noexcept { return m_type == type::null; }
    bool is_boolean() const noexcept { return m_type == type::boolean; }
    bool is_number() const noexcept { return is_number_integer() || is_number_unsigned() || is_number_float(); }
    bool is_number_integer() const noexcept { return m_type == type::number_integer; }
    bool is_number_unsigned() const noexcept { return m_type == type::number_unsigned; }
    bool is_number_float() const noexcept { return m_type == type::number_float; }
    bool is_object() const noexcept { return m_type == type::object; }
    bool is_array() const noexcept { return m_type == type::array; }
    bool is_string() const noexcept { return m_type == type::string; }

    // Value access
    template<typename T>
    T get() const;

    // Array access
    json& operator[](size_t idx) {
        if (!is_array()) m_value = array_t{};
        m_type = type::array;
        auto& arr = std::get<array_t>(m_value);
        if (idx >= arr.size()) arr.resize(idx + 1);
        return arr[idx];
    }

    const json& operator[](size_t idx) const {
        if (!is_array()) throw std::runtime_error("not an array");
        const auto& arr = std::get<array_t>(m_value);
        if (idx >= arr.size()) throw std::runtime_error("array index out of bounds");
        return arr[idx];
    }

    // Object access
    json& operator[](const std::string& key) {
        if (!is_object()) m_value = object_t{};
        m_type = type::object;
        return std::get<object_t>(m_value)[key];
    }

    const json& operator[](const std::string& key) const {
        if (!is_object()) throw std::runtime_error("not an object");
        const auto& obj = std::get<object_t>(m_value);
        auto it = obj.find(key);
        if (it == obj.end()) throw std::runtime_error("key not found");
        return it->second;
    }

    // Contains and access with default
    bool contains(const std::string& key) const {
        if (!is_object()) return false;
        const auto& obj = std::get<object_t>(m_value);
        return obj.find(key) != obj.end();
    }

    json value(const std::string& key, const json& default_value) const {
        if (!is_object()) return default_value;
        const auto& obj = std::get<object_t>(m_value);
        auto it = obj.find(key);
        return (it != obj.end()) ? it->second : default_value;
    }

    // Iteration
    class iterator {
    public:
        using value_type = std::pair<const std::string, json>;

        iterator(object_t::iterator it) : m_it(it) {}

        value_type operator*() const { return *m_it; }
        iterator& operator++() { ++m_it; return *this; }
        bool operator!=(const iterator& other) const { return m_it != other.m_it; }

    private:
        object_t::iterator m_it;
    };

    iterator begin() {
        if (!is_object()) throw std::runtime_error("not an object");
        return iterator(std::get<object_t>(m_value).begin());
    }

    iterator end() {
        if (!is_object()) throw std::runtime_error("not an object");
        return iterator(std::get<object_t>(m_value).end());
    }

    // Size
    size_t size() const {
        if (is_array()) return std::get<array_t>(m_value).size();
        if (is_object()) return std::get<object_t>(m_value).size();
        return 0;
    }

    // Array operations
    void push_back(const json& val) {
        if (!is_array()) m_value = array_t{};
        m_type = type::array;
        std::get<array_t>(m_value).push_back(val);
    }

    // Serialization
    std::string dump(int indent = -1, char indent_char = ' ', bool ensure_ascii = false) const {
        std::stringstream ss;
        dump_internal(ss, indent, indent_char, 0, ensure_ascii);
        return ss.str();
    }

    // Parsing
    static json parse(const std::string& s) {
        json result;
        parse_internal(s, result);
        return result;
    }

private:
    enum class type {
        null,
        boolean,
        number_integer,
        number_unsigned,
        number_float,
        string,
        array,
        object
    };

    type m_type = type::null;
    std::variant<std::nullptr_t, boolean_t, number_integer_t, number_unsigned_t,
                 number_float_t, string_t, array_t, object_t> m_value;

    void dump_internal(std::stringstream& ss, int indent, char indent_char, int current_indent, bool ensure_ascii) const;
    static void parse_internal(const std::string& s, json& result);
};

// Template specializations for get()
template<> inline std::nullptr_t json::get<std::nullptr_t>() const {
    if (!is_null()) throw std::runtime_error("not null");
    return nullptr;
}

template<> inline bool json::get<bool>() const {
    if (!is_boolean()) throw std::runtime_error("not boolean");
    return std::get<boolean_t>(m_value);
}

template<> inline int json::get<int>() const {
    if (is_number_integer()) return static_cast<int>(std::get<number_integer_t>(m_value));
    if (is_number_unsigned()) return static_cast<int>(std::get<number_unsigned_t>(m_value));
    if (is_number_float()) return static_cast<int>(std::get<number_float_t>(m_value));
    throw std::runtime_error("not a number");
}

template<> inline std::int64_t json::get<std::int64_t>() const {
    if (is_number_integer()) return std::get<number_integer_t>(m_value);
    if (is_number_unsigned()) return static_cast<std::int64_t>(std::get<number_unsigned_t>(m_value));
    if (is_number_float()) return static_cast<std::int64_t>(std::get<number_float_t>(m_value));
    throw std::runtime_error("not a number");
}

template<> inline double json::get<double>() const {
    if (is_number_float()) return std::get<number_float_t>(m_value);
    if (is_number_integer()) return static_cast<double>(std::get<number_integer_t>(m_value));
    if (is_number_unsigned()) return static_cast<double>(std::get<number_unsigned_t>(m_value));
    throw std::runtime_error("not a number");
}

template<> inline std::string json::get<std::string>() const {
    if (!is_string()) throw std::runtime_error("not a string");
    return std::get<string_t>(m_value);
}

template<> inline json::array_t json::get<json::array_t>() const {
    if (!is_array()) throw std::runtime_error("not an array");
    return std::get<array_t>(m_value);
}

template<> inline json::object_t json::get<json::object_t>() const {
    if (!is_object()) throw std::runtime_error("not an object");
    return std::get<object_t>(m_value);
}

// Simplified dump implementation
inline void json::dump_internal(std::stringstream& ss, int indent, char indent_char, int current_indent, bool ensure_ascii) const {
    std::string indent_str(current_indent, indent_char);

    switch (m_type) {
        case type::null:
            ss << "null";
            break;
        case type::boolean:
            ss << (std::get<boolean_t>(m_value) ? "true" : "false");
            break;
        case type::number_integer:
            ss << std::get<number_integer_t>(m_value);
            break;
        case type::number_unsigned:
            ss << std::get<number_unsigned_t>(m_value);
            break;
        case type::number_float:
            ss << std::get<number_float_t>(m_value);
            break;
        case type::string:
            ss << "\"" << std::get<string_t>(m_value) << "\"";
            break;
        case type::array: {
            ss << "[";
            const auto& arr = std::get<array_t>(m_value);
            for (size_t i = 0; i < arr.size(); ++i) {
                if (i > 0) ss << ",";
                if (indent >= 0) ss << "\n" << indent_str << std::string(indent, indent_char);
                arr[i].dump_internal(ss, indent, indent_char, current_indent + indent, ensure_ascii);
            }
            if (indent >= 0 && !arr.empty()) ss << "\n" << indent_str;
            ss << "]";
            break;
        }
        case type::object: {
            ss << "{";
            const auto& obj = std::get<object_t>(m_value);
            size_t i = 0;
            for (const auto& [key, value] : obj) {
                if (i++ > 0) ss << ",";
                if (indent >= 0) ss << "\n" << indent_str << std::string(indent, indent_char);
                ss << "\"" << key << "\":";
                if (indent >= 0) ss << " ";
                value.dump_internal(ss, indent, indent_char, current_indent + indent, ensure_ascii);
            }
            if (indent >= 0 && !obj.empty()) ss << "\n" << indent_str;
            ss << "}";
            break;
        }
    }
}

// Simplified parse implementation
inline void json::parse_internal(const std::string& s, json& result) {
    // Very basic JSON parser - in a real implementation, you'd want a proper parser
    std::string trimmed = s;
    trimmed.erase(trimmed.begin(), std::find_if(trimmed.begin(), trimmed.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    trimmed.erase(std::find_if(trimmed.rbegin(), trimmed.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), trimmed.end());

    if (trimmed == "null") {
        result = nullptr;
    } else if (trimmed == "true") {
        result = true;
    } else if (trimmed == "false") {
        result = false;
    } else if (trimmed[0] == '"') {
        result = trimmed.substr(1, trimmed.size() - 2);
    } else if (trimmed[0] == '{') {
        // Basic object parsing
        result.m_type = type::object;
        result.m_value = object_t{};
        // Simplified - would need proper parsing
    } else if (trimmed[0] == '[') {
        // Basic array parsing
        result.m_type = type::array;
        result.m_value = array_t{};
        // Simplified - would need proper parsing
    } else {
        // Try to parse as number
        try {
            if (trimmed.find('.') != std::string::npos) {
                result = std::stod(trimmed);
            } else {
                // Check if it fits in signed int64
                std::int64_t val = std::stoll(trimmed);
                result = val;
            }
        } catch (...) {
            result = trimmed; // Fallback to string
        }
    }
}

} // namespace nlohmann
