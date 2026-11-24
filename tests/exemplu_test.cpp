#undef NDEBUG
#include <cassert>
#include <stdexcept>
#include <sstream>

#include "IPv4Prefix.h"
#include "TrafficQuery.h"

void testFirewallRule();
void testFirewallPolicy();
void testScenarioInput();

int main() {

    IPv4Prefix prefix(0x0A0A0A2A, 24);

    assert(prefix.contains(0x0A0A0AC8));
    assert(!prefix.contains(0x0A0A0B01));


    bool exception1Caught = false;

    try{
        IPv4Prefix invalid_object1(0x0A0A0A2A, 33);
    }
    catch (const std::invalid_argument&)
    {
        exception1Caught = true;
    }

    bool exception2Caught = false;
    try {
        IPv4Prefix invalid_object2(0x0A0A0A2A, -1);
    }
    catch (const std::invalid_argument&)
    {
        exception2Caught = true;
    }

    assert(exception1Caught);
    assert(exception2Caught);


    IPv4Prefix prefix1(0x0A0A0A2A, 0);
    IPv4Prefix prefix2(0x0A0A0A2A, 32);

    assert(prefix1.contains(0xC0000201));
    assert(prefix2.contains(0x0A0A0A2A));
    assert(!prefix2.contains(0x0A0A0A2B));

    std::ostringstream outputPrefix;

    outputPrefix<<prefix;

    assert(outputPrefix.str() == "10.10.10.0/24");

    outputPrefix.str("");

    outputPrefix<<prefix1;

    assert(outputPrefix.str() == "0.0.0.0/0");

    outputPrefix.str("");

    outputPrefix<<prefix2;

    assert(outputPrefix.str() == "10.10.10.42/32");

    outputPrefix.str("");


    TrafficQuery query1(
    0x0A0A0A2A,
    0x0A0A140A,
    50000,
    88,
    Protocol::TCP
    );


    std::ostringstream outputQuery;

    outputQuery<<query1;

    assert(outputQuery.str() == "TCP 10.10.10.42:50000 -> 10.10.20.10:88");


    bool exception2_caught = false, exception3_caught = false;

    try
    {
        TrafficQuery query2(
        0x0A0A0A2A,
        0x0A0A140A,
        -1,
        88,
        Protocol::TCP
        );
    }
    catch(const std::invalid_argument&)
    {
        exception2_caught  = true;
    }

    try
    {
        TrafficQuery query3(
        0x0A0A0A2A,
        0x0A0A140A,
        50000,
        65536,
        Protocol::TCP
        );
    }
    catch(const std::invalid_argument&)
    {
        exception3_caught  = true;
    }

    assert(exception2_caught);
    assert(exception3_caught);


    testFirewallRule();
    testFirewallPolicy();
    testScenarioInput();
    return 0;
}
