#include "types.hpp"

namespace mcp_server_pcileech {

json Tool::to_json() const {
    return {
        {"name", name},
        {"description", description},
        {"inputSchema", input_schema}
    };
}

json TextContent::to_json() const {
    return {
        {"type", type},
        {"text", text}
    };
}

json ToolCall::to_json() const {
    json args_obj = json::object();
    for (const auto& [k, v] : arguments) {
        args_obj[k] = variant_to_json(v);
    }

    return {
        {"name", name},
        {"arguments", args_obj}
    };
}

json ToolResponse::to_json() const {
    json content_array = json::array();
    for (const auto& c : content) {
        content_array.push_back(c.to_json());
    }

    return {
        {"content", content_array}
    };
}

json variant_to_json(const JsonValue& value) {
    return value;
}

JsonValue json_to_variant(const json& j) {
    return j;
}

}
