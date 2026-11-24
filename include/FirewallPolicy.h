#ifndef FIREWALLPOLICY_H
#define FIREWALLPOLICY_H

#include <vector>
#include <optional>
#include <iosfwd>

#include "FirewallRule.h"

class EvaluationResult {
    Action verdict_;
    std::optional<int> matchingRuleID_;

public:
    EvaluationResult(Action verdict, std::optional<int> matchingRuleID) noexcept;

    Action getVerdict() const noexcept;
    std::optional<int> getMatchingRuleID() const noexcept;
};

std::ostream& operator<<(std::ostream& os, const EvaluationResult& result);

class QueryComparison {
    TrafficQuery query_;
    EvaluationResult before_;
    EvaluationResult after_;

public:
    QueryComparison(const TrafficQuery& query,
                    const EvaluationResult& before,
                    const EvaluationResult& after);

    const EvaluationResult& getBefore() const noexcept;
    const EvaluationResult& getAfter() const noexcept;
    bool verdictChanged() const noexcept;

    friend std::ostream& operator<<(std::ostream& os, const QueryComparison& comparison);
};

class FirewallPolicy{

    std::vector<FirewallRule> rules_;
    Action defaultAction_;

public:
    FirewallPolicy(const std::vector<FirewallRule>& rules, Action defaultAction);
    FirewallPolicy(const FirewallPolicy& other);
    FirewallPolicy& operator=(const FirewallPolicy& other);
    ~FirewallPolicy();

    EvaluationResult evaluate(const TrafficQuery& query) const;
    void changeRuleAction(int ruleID, Action newAction);
    std::vector<QueryComparison> compare(const FirewallPolicy& proposal,
                                         const std::vector<TrafficQuery>& queries) const;

    friend std::ostream& operator<<(std::ostream& os, const FirewallPolicy& policy);
};

#endif
