#include "ScenarioInput.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <initializer_list>
#include <istream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <nlohmann/json.hpp>

namespace {
using Json = nlohmann::json;

void requireFields(const Json& object, std::initializer_list<std::string_view> fields)
{
    if (!object.is_object())
    {
        throw std::invalid_argument("Expected a JSON object");
    }
    for (const std::string_view field : fields)
    {
        if (!object.contains(field))
        {
            throw std::invalid_argument("Missing field '" + std::string(field) + "'");
        }
    }
    for (auto field = object.begin(); field != object.end(); ++field)
    {
        if (std::find(fields.begin(), fields.end(), field.key()) == fields.end())
        {
            throw std::invalid_argument("Unknown field '" + field.key() + "'");
        }
    }
}

std::string textField(const Json& object, const char* name)
{
    const Json& value = object.at(name);
    if (!value.is_string())
    {
        throw std::invalid_argument(std::string(name) + " must be a string");
    }
    return value.get<std::string>();
}

int positiveField(const Json& object, const char* name, int maximum)
{
    const Json& value = object.at(name);
    if (value.is_number_unsigned())
    {
        const auto number = value.get<std::uint64_t>();
        if (number > 0 && number <= static_cast<std::uint64_t>(maximum))
        {
            return static_cast<int>(number);
        }
    }
    else if (value.is_number_integer())
    {
        const auto number = value.get<std::int64_t>();
        if (number > 0 && number <= maximum)
        {
            return static_cast<int>(number);
        }
    }
    throw std::invalid_argument(std::string(name) + " must be an integer from 1 to " +
                                std::to_string(maximum));
}

Action readAction(const Json& object, const char* field)
{
    const std::string text = textField(object, field);
    if (text == "ALLOW")
    {
        return Action::ALLOW;
    }
    if (text == "BLOCK")
    {
        return Action::BLOCK;
    }
    throw std::invalid_argument(std::string(field) + " must be ALLOW or BLOCK");
}

Protocol readProtocol(const Json& object)
{
    const std::string text = textField(object, "protocol");
    if (text == "TCP")
    {
        return Protocol::TCP;
    }
    if (text == "UDP")
    {
        return Protocol::UDP;
    }
    throw std::invalid_argument("protocol must be TCP or UDP");
}

int decimalInRange(std::string_view text, int maximum, const char* field)
{
    if (!text.empty() && text.front() >= '0' && text.front() <= '9')
    {
        int number = 0;
        const auto end = text.data() + text.size();
        const auto conversion = std::from_chars(text.data(), end, number);
        if (conversion.ec == std::errc{} && conversion.ptr == end && number <= maximum)
        {
            return number;
        }
    }
    throw std::invalid_argument(std::string(field) + " has an invalid IPv4 component");
}

std::uint32_t readAddress(std::string_view text, const char* field)
{
    std::uint32_t address = 0;
    for (int octet = 0; octet < 4; ++octet)
    {
        const auto dot = text.find('.');
        if ((dot == std::string_view::npos) != (octet == 3))
        {
            throw std::invalid_argument(std::string(field) + " must have four IPv4 octets");
        }
        const auto component = text.substr(0, dot);
        if (component.size() > 1 && component.front() == '0')
        {
            throw std::invalid_argument(std::string(field) + " contains a leading zero");
        }
        address = (address << 8) | static_cast<std::uint32_t>(decimalInRange(component, 255, field));
        if (dot != std::string_view::npos)
        {
            text.remove_prefix(dot + 1);
        }
    }
    return address;
}

IPv4Prefix readPrefix(const Json& object, const char* field)
{
    const std::string text = textField(object, field);
    const std::string_view prefix(text);
    const auto slash = prefix.find('/');
    if (slash == std::string_view::npos)
    {
        throw std::invalid_argument(std::string(field) + " must be an IPv4 prefix with /length");
    }
    return IPv4Prefix(readAddress(prefix.substr(0, slash), field),
                      decimalInRange(prefix.substr(slash + 1), 32, field));
}

Json readJson(std::istream& input)
{
    try
    {
        return Json::parse(input);
    }
    catch (const Json::parse_error& error)
    {
        throw std::invalid_argument(std::string("Invalid JSON: ") + error.what());
    }
}

FirewallRule readRule(const Json& rule)
{
    requireFields(rule, {"id", "src_prefix", "dst_prefix", "protocol", "dst_port", "action"});
    return {positiveField(rule, "id", std::numeric_limits<int>::max()),
            readPrefix(rule, "src_prefix"), readPrefix(rule, "dst_prefix"),
            readProtocol(rule), positiveField(rule, "dst_port", 65535), readAction(rule, "action")};
}

TrafficQuery readQuery(const Json& query)
{
    requireFields(query, {"src_ip", "dst_ip", "src_port", "dst_port", "protocol"});
    return {readAddress(textField(query, "src_ip"), "src_ip"),
            readAddress(textField(query, "dst_ip"), "dst_ip"),
            positiveField(query, "src_port", 65535), positiveField(query, "dst_port", 65535),
            readProtocol(query)};
}
}

FirewallPolicy readPolicy(std::istream& input)
{
    const Json policy = readJson(input);
    requireFields(policy, {"default_action", "rules"});
    const Action defaultAction = readAction(policy, "default_action");
    const Json& entries = policy.at("rules");
    if (!entries.is_array())
    {
        throw std::invalid_argument("rules must be an array");
    }

    std::vector<FirewallRule> rules;
    rules.reserve(entries.size());
    for (const Json& entry : entries)
    {
        rules.push_back(readRule(entry));
    }
    return {rules, defaultAction};
}

ScenarioInput readScenario(std::istream& input)
{
    const Json scenario = readJson(input);
    requireFields(scenario, {"queries", "proposal"});
    const Json& proposal = scenario.at("proposal");
    requireFields(proposal, {"rule_id", "action"});
    const Json& entries = scenario.at("queries");
    if (!entries.is_array() || entries.empty())
    {
        throw std::invalid_argument("queries must be a non-empty array");
    }

    std::vector<TrafficQuery> queries;
    queries.reserve(entries.size());
    for (const Json& entry : entries)
    {
        queries.push_back(readQuery(entry));
    }
    return {std::move(queries), positiveField(proposal, "rule_id", std::numeric_limits<int>::max()),
            readAction(proposal, "action")};
}
