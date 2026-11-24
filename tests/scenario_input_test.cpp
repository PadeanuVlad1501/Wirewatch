#undef NDEBUG
#include <cassert>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "ScenarioInput.h"

namespace {
void expectInvalidPolicy(std::string_view text, std::string_view message)
{
    std::istringstream input{std::string(text)};
    bool rejected = false;
    try
    {
        static_cast<void>(readPolicy(input));
    }
    catch (const std::invalid_argument& error)
    {
        rejected = std::string_view(error.what()).find(message) != std::string_view::npos;
    }
    assert(rejected);
}
}

void testScenarioInput()
{
    std::ifstream policyFile("assets/policy.json");
    std::ifstream scenarioFile("assets/scenario.json");
    assert(policyFile && scenarioFile);
    const FirewallPolicy baseline = readPolicy(policyFile);
    const auto [queries, ruleID, newAction] = readScenario(scenarioFile);

    FirewallPolicy proposal(baseline);
    proposal.changeRuleAction(ruleID, newAction);
    const auto results = baseline.compare(proposal, queries);
    assert(results.size() == 3);
    assert(results[0].verdictChanged());
    assert(results[0].getBefore().getVerdict() == Action::ALLOW);
    assert(results[0].getAfter().getVerdict() == Action::BLOCK);
    assert(results[0].getBefore().getMatchingRuleID() == 1);
    assert(results[0].getAfter().getMatchingRuleID() == 1);
    assert(!results[1].verdictChanged());
    assert(results[1].getAfter().getVerdict() == Action::ALLOW);
    assert(results[1].getAfter().getMatchingRuleID() == 2);
    assert(!results[2].verdictChanged());
    assert(results[2].getAfter().getVerdict() == Action::BLOCK);
    assert(!results[2].getAfter().getMatchingRuleID().has_value());

    const FirewallPolicy allowByDefault({}, Action::ALLOW);
    const auto movedDecision = baseline.compare(allowByDefault, {queries.front()});
    assert(!movedDecision.front().verdictChanged());
    std::ostringstream output;
    output << movedDecision.front();
    assert(output.str().find("[same verdict, different decision source]") != std::string::npos);

    expectInvalidPolicy(R"({"rules":[]})", "default_action");
    expectInvalidPolicy("{", "Invalid JSON");
    expectInvalidPolicy(R"({"default_action":"BLOCK","rules":[{
        "id":1,"src_prefix":"10.10.256.0/24","dst_prefix":"10.10.20.10/32",
        "protocol":"TCP","dst_port":88,"action":"ALLOW"
    }]})", "src_prefix");
    expectInvalidPolicy(R"({"default_action":"BLOCK","rules":[{
        "id":1,"src_prefix":"10.10.10.0/24","dst_prefix":"10.10.20.10/32",
        "protocol":"TCP","dst_port":18446744073709551615,"action":"ALLOW"
    }]})", "dst_port");
    expectInvalidPolicy(R"({"default_action":"BLOCK","rules":[{
        "id":1,"src_prefix":"10.10.10.0/24","dst_prefix":"10.10.20.10/32",
        "protocol":"TCP","src_port":50000,"dst_port":88,"action":"ALLOW"
    }]})", "Unknown field 'src_port'");

    std::istringstream invalidScenario(R"({"proposal":{"rule_id":1,"action":"BLOCK"},"queries":[]})");
    bool emptyQueriesRejected = false;
    try
    {
        static_cast<void>(readScenario(invalidScenario));
    }
    catch (const std::invalid_argument& error)
    {
        emptyQueriesRejected = std::string_view(error.what()).find("queries") != std::string_view::npos;
    }
    assert(emptyQueriesRejected);
}
