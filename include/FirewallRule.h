#ifndef FIREWALLRULE_H
#define FIREWALLRULE_H

#include <cstdint>
#include <iosfwd>
#include "IPv4Prefix.h"
#include "TrafficQuery.h"

enum class Action{
    ALLOW,
    BLOCK
};

class FirewallRule{
    int ID_;
    IPv4Prefix srcprefix_;
    IPv4Prefix destprefix_;
    Protocol protocol_;
    std::uint16_t port_;
    Action action_;

public:
    FirewallRule(
        int ID,
        const IPv4Prefix& srcprefix,
        const IPv4Prefix& destprefix,
        Protocol protocol,
        int port,
        Action action
    );

    bool matches(const TrafficQuery& query) const;

    friend std::ostream& operator<<(std::ostream& os, const FirewallRule& rule);

    int getID() const;
    Action getAction() const;
    void setAction(Action newAction) noexcept;
};

#endif
