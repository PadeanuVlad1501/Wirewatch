#undef NDEBUG
#include <cassert>
#include <sstream>
#include <stdexcept>

#include "FirewallRule.h"

void testFirewallRule()
{
    IPv4Prefix source(0x0A0A0A00, 24); // 10.10.10.0/24
    IPv4Prefix destination(0x0A0A1400, 24); // 10.10.20.0/24

    FirewallRule rule(
        1,
        source,
        destination,
        Protocol::TCP,
        88,
        Action::ALLOW
    );


    TrafficQuery query(0x0A0A0A0A, 0x0A0A1414, 88, 88, Protocol::TCP);
    assert(rule.matches(query));

    TrafficQuery query1(0x0A0A0A0A, 0x0A0A1414, 88, 88, Protocol::UDP);
    assert(!rule.matches(query1));

    TrafficQuery query2(0x0A0A0B0A, 0x0A0A1414, 88, 88, Protocol::TCP);
    assert(!rule.matches(query2));

    TrafficQuery query3(0x0A0A0A0A, 0x0A0A1E14, 88, 88, Protocol::TCP);
    assert(!rule.matches(query3));

    TrafficQuery query4(0x0A0A0A0A, 0x0A0A1414, 88, 443, Protocol::TCP);
    assert(!rule.matches(query4));

    TrafficQuery query5(0x0A0A0A0A, 0x0A0A1414, 50000, 88, Protocol::TCP);
    assert(rule.matches(query5));

    FirewallRule rule1(
        1,
        source,
        destination,
        Protocol::TCP,
        88,
        Action::BLOCK
    );

    
    assert(rule1.matches(query));

    std::ostringstream output;

    output<<rule;

    assert(output.str() == "Rule #1: ALLOW TCP 10.10.10.0/24 -> 10.10.20.0/24:88");

    output.str("");

    output<<rule1;
    assert(output.str() == "Rule #1: BLOCK TCP 10.10.10.0/24 -> 10.10.20.0/24:88");

    bool invalidId0Caught = false;

    try {
        FirewallRule invalidRule(
            0,
            source,
            destination,
            Protocol::TCP,
            88,
            Action::ALLOW
        );
    }
    catch (const std::invalid_argument&) {
        invalidId0Caught = true;
    }

    assert(invalidId0Caught);

    bool invalidId1Caught = false;

    try {
        FirewallRule invalidRule(
            -1,
            source,
            destination,
            Protocol::TCP,
            88,
            Action::ALLOW
        );
    }
    catch (const std::invalid_argument&) {
        invalidId1Caught = true;
    }

    assert(invalidId1Caught);

    bool invalidport0Caught = false;

    try {
        FirewallRule invalidRule(
            1,
            source,
            destination,
            Protocol::TCP,
            0,
            Action::ALLOW
        );
    }
    catch (const std::invalid_argument&) {
        invalidport0Caught = true;
    }

    assert(invalidport0Caught);


    bool invalidport1Caught = false;

    try {
        FirewallRule invalidRule(
            1,
            source,
            destination,
            Protocol::TCP,
            65536,
            Action::ALLOW
        );
    }
    catch (const std::invalid_argument&) {
        invalidport1Caught = true;
    }

    assert(invalidport1Caught);


}   