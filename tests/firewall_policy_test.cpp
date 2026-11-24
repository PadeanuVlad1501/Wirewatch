#undef NDEBUG

#include <cassert>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "FirewallPolicy.h"

void testFirewallPolicy()
{
    IPv4Prefix source(0x0A0A0A00, 24);
    IPv4Prefix destination(0x0A0A1400, 24);

    FirewallRule allowRule(
        1,
        source,
        destination,
        Protocol::TCP,
        88,
        Action::ALLOW
    );

    FirewallRule blockRule(
        2,
        source,
        destination,
        Protocol::TCP,
        88,
        Action::BLOCK
    );

    TrafficQuery query(
        0x0A0A0A2A,
        0x0A0A140A,
        50000,
        88,
        Protocol::TCP
    );

    std::vector<FirewallRule> rules1 = {
        allowRule,
        blockRule
    };

    FirewallPolicy policy1(rules1, Action::BLOCK);

    EvaluationResult result1 = policy1.evaluate(query);

    assert(result1.getVerdict() == Action::ALLOW);
    assert(result1.getMatchingRuleID() == 1);

    std::vector<FirewallRule> rules2 = {
        blockRule,
        allowRule
    };

    FirewallPolicy policy2(rules2, Action::ALLOW);

    EvaluationResult result2 = policy2.evaluate(query);

    assert(result2.getVerdict() == Action::BLOCK);
    assert(result2.getMatchingRuleID() == 2);


    TrafficQuery unmatchedQuery(
        0x0A0A0A2A,
        0x0A0A140A,
        50000,
        443,
        Protocol::TCP
    );

    EvaluationResult result3 = policy2.evaluate(unmatchedQuery);

    assert(result3.getVerdict() == Action::ALLOW);
    assert(!result3.getMatchingRuleID().has_value());


    bool duplicateCaught = false;

    try
    {
        std::vector<FirewallRule> duplicateRules = {
            allowRule,
            allowRule
        };

        FirewallPolicy invalidPolicy(
            duplicateRules,
            Action::BLOCK
        );
    }
    catch (const std::invalid_argument&)
    {
        duplicateCaught = true;
    }

    assert(duplicateCaught);


    std::vector<FirewallRule> emptyRules;

    FirewallPolicy emptyPolicy(
        emptyRules,
        Action::BLOCK
    );

    EvaluationResult result5 = emptyPolicy.evaluate(query);

    assert(result5.getVerdict() == Action::BLOCK);
    assert(!result5.getMatchingRuleID().has_value());

    FirewallPolicy proposal(policy1);
    proposal.changeRuleAction(1, Action::BLOCK);
    const EvaluationResult changedResult = proposal.evaluate(query);
    assert(changedResult.getVerdict() == Action::BLOCK);
    assert(changedResult.getMatchingRuleID() == 1);
    assert(policy1.evaluate(query).getVerdict() == Action::ALLOW);

    std::ostringstream resultOutput;
    resultOutput << changedResult << " / " << result3;
    assert(resultOutput.str() == "BLOCK (rule #1) / ALLOW (default action)");

    std::ostringstream beforeFailure;
    beforeFailure << proposal;
    assert(beforeFailure.str() ==
           "Default action: BLOCK\n"
           "Rules (first match wins):\n"
           "  Rule #1: BLOCK TCP 10.10.10.0/24 -> 10.10.20.0/24:88\n"
           "  Rule #2: BLOCK TCP 10.10.10.0/24 -> 10.10.20.0/24:88");

    bool missingRuleCaught = false;
    try
    {
        proposal.changeRuleAction(99, Action::ALLOW);
    }
    catch (const std::out_of_range&)
    {
        missingRuleCaught = true;
    }
    assert(missingRuleCaught);

    std::ostringstream afterFailure;
    afterFailure << proposal;
    assert(afterFailure.str() == beforeFailure.str());

    proposal = policy1;
    const EvaluationResult restoredResult = proposal.evaluate(query);
    assert(restoredResult.getVerdict() == Action::ALLOW);
    assert(restoredResult.getMatchingRuleID() == 1);

    proposal.changeRuleAction(1, Action::BLOCK);
    assert(policy1.evaluate(query).getVerdict() == Action::ALLOW);
}
