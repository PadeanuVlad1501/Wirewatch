#include "FirewallRule.h"

#include <stdexcept>
#include <ostream>


FirewallRule::FirewallRule(
        int ID,
        const IPv4Prefix& srcprefix,
        const IPv4Prefix& destprefix,
        Protocol protocol,
        int port,
        Action action
    )
    : srcprefix_(srcprefix),
      destprefix_(destprefix),
      protocol_(protocol),
      action_(action)
      {
        if (ID > 0)
            ID_ = ID;
        else throw std::invalid_argument("Invalid ID");

        if (port <= 0 || port > 65535)
            throw std::invalid_argument("Invalid Port Number");
        else port_ = static_cast<std::uint16_t>(port);
      }

bool FirewallRule::matches(const TrafficQuery& query) const{
    return srcprefix_.contains(query.srcAddress()) &&
           destprefix_.contains(query.destAddress()) &&
           protocol_ == query.getProtocol() &&
           port_ == query.destPort();
}


std::ostream& operator<<(std::ostream& os, const FirewallRule& rule)
{
    os<< "Rule #"<< rule.ID_<<": ";

    if (rule.action_ == Action::ALLOW)
        os<<"ALLOW ";
    else os<<"BLOCK ";

    if (rule.protocol_ == Protocol::TCP)
        os<<"TCP ";
    else os<<"UDP ";

    os<<rule.srcprefix_<<" -> "<< rule.destprefix_<<":"<<rule.port_;
    return os;
}

int FirewallRule::getID() const{
    return ID_;
}

Action FirewallRule::getAction() const{
    return action_;
}

void FirewallRule::setAction(Action newAction) noexcept
{
    action_ = newAction;
}
