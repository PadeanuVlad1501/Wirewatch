#include "FirewallPolicy.h"

#include <ostream>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace {
const char* actionName(Action action)
{
    return action == Action::ALLOW ? "ALLOW" : "BLOCK";
}
}

EvaluationResult::EvaluationResult(
    Action verdict, std::optional<int> matchingRuleID
) noexcept
    : verdict_(verdict), matchingRuleID_(matchingRuleID)
{
}

Action EvaluationResult::getVerdict() const noexcept
{
    return verdict_;
}

std::optional<int> EvaluationResult::getMatchingRuleID() const noexcept
{
    return matchingRuleID_;
}

std::ostream& operator<<(std::ostream& os, const EvaluationResult& result)
{
    os << actionName(result.getVerdict());
    if (const auto ruleID = result.getMatchingRuleID())
    {
        return os << " (rule #" << *ruleID << ')';
    }

    return os << " (default action)";
}

QueryComparison::QueryComparison(const TrafficQuery& query,
                                 const EvaluationResult& before,
                                 const EvaluationResult& after)
    : query_(query), before_(before), after_(after)
{
}

const EvaluationResult& QueryComparison::getBefore() const noexcept
{
    return before_;
}

const EvaluationResult& QueryComparison::getAfter() const noexcept
{
    return after_;
}

bool QueryComparison::verdictChanged() const noexcept
{
    return before_.getVerdict() != after_.getVerdict();
}

std::ostream& operator<<(std::ostream& os, const QueryComparison& comparison)
{
    os << comparison.query_ << ": " << comparison.getBefore() << " -> "
       << comparison.getAfter();
    if (comparison.verdictChanged())
    {
        return os << " [verdict changed]";
    }
    if (comparison.getBefore().getMatchingRuleID() != comparison.getAfter().getMatchingRuleID())
    {
        return os << " [same verdict, different decision source]";
    }
    return os << " [unchanged]";
}

FirewallPolicy::FirewallPolicy(
    const std::vector<FirewallRule>& rules,
    Action defaultAction
)
    : rules_(rules),
      defaultAction_(defaultAction)
{
    std::unordered_set<int> seenIDs;

    for (const FirewallRule& rule : rules_)
    {
        int currentID = rule.getID();
   
        if (!seenIDs.insert(currentID).second)
        {
            throw std::invalid_argument("Duplicate firewall rule ID");
        }
    }
}

FirewallPolicy::FirewallPolicy(const FirewallPolicy& other) = default;
FirewallPolicy& FirewallPolicy::operator=(const FirewallPolicy& other) = default;
FirewallPolicy::~FirewallPolicy() = default;

EvaluationResult FirewallPolicy::evaluate(const TrafficQuery& query) const
{
    for (const FirewallRule& rule : rules_)
    {
        if (rule.matches(query))
        {
            return {rule.getAction(), rule.getID()};
        }
    }   

    return {defaultAction_, std::nullopt};
}

void FirewallPolicy::changeRuleAction(int ruleID, Action newAction)
{
    for (FirewallRule& rule : rules_)
    {
        if (rule.getID() == ruleID)
        {
            rule.setAction(newAction);
            return;
        }
    }

    throw std::out_of_range("No firewall rule with ID " + std::to_string(ruleID));
}

std::vector<QueryComparison> FirewallPolicy::compare(
    const FirewallPolicy& proposal, const std::vector<TrafficQuery>& queries
) const
{
    std::vector<QueryComparison> results;
    results.reserve(queries.size());
    for (const TrafficQuery& query : queries)
    {
        results.emplace_back(query, evaluate(query), proposal.evaluate(query));
    }
    return results;
}

std::ostream& operator<<(std::ostream& os, const FirewallPolicy& policy)
{
    os << "Default action: " << actionName(policy.defaultAction_) << '\n'
       << "Rules (first match wins):";
    for (const FirewallRule& rule : policy.rules_)
    {
        os << "\n  " << rule;
    }

    return os;
}
