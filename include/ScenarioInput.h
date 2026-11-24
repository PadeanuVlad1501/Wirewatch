#ifndef SCENARIO_INPUT_H
#define SCENARIO_INPUT_H

#include <iosfwd>
#include <tuple>
#include <vector>

#include "FirewallPolicy.h"

using ScenarioInput = std::tuple<std::vector<TrafficQuery>, int, Action>;

FirewallPolicy readPolicy(std::istream& input);
ScenarioInput readScenario(std::istream& input);

#endif
