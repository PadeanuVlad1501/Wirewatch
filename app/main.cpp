#include "ScenarioInput.h"

#include <cstddef>
#include <exception>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
std::ifstream openInput(const char* path)
{
    std::ifstream input(path);
    if (!input)
    {
        throw std::runtime_error("Cannot open input file");
    }
    return input;
}
}

int main(int argc, char* argv[])
{
    if (argc != 1 && argc != 3)
    {
        std::cerr << "Usage: oop_main [policy.json scenario.json]\n";
        return 1;
    }

    const char* policyPath = argc == 3 ? argv[1] : "assets/policy.json";
    const char* scenarioPath = argc == 3 ? argv[2] : "assets/scenario.json";
    const char* currentInput = policyPath;

    try
    {
        auto policyFile = openInput(policyPath);
        const FirewallPolicy baseline = readPolicy(policyFile);
        currentInput = scenarioPath;
        auto scenarioFile = openInput(scenarioPath);
        const auto [queries, ruleID, newAction] = readScenario(scenarioFile);

        FirewallPolicy proposal(baseline);
        proposal.changeRuleAction(ruleID, newAction);
        const auto results = baseline.compare(proposal, queries);

        std::cout << "Wirewatch - firewall policy simulation\n\n"
                  << "Baseline\n" << baseline << "\n\n"
                  << "Proposal (requested action for rule #" << ruleID << ")\n" << proposal << "\n\n"
                  << "Results (permission under the evaluated policy)\n";

        std::size_t changed = 0;
        for (const QueryComparison& result : results)
        {
            std::cout << "  " << result << '\n';
            if (result.verdictChanged())
            {
                ++changed;
            }
        }
        std::cout << "\nVerdicts changed: " << changed << " of " << results.size() << '\n';

        proposal = baseline;
        std::cout << "After resetting the proposal to baseline: "
                  << queries.front() << ": " << proposal.evaluate(queries.front()) << '\n';
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "Wirewatch: " << currentInput << ": " << error.what() << '\n';
        return 1;
    }
}
