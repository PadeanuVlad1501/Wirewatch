#include "TrafficQuery.h"

#include <ostream>
#include <stdexcept>

namespace{
    bool portValid(int port) {
        return port>=1 && port<=65535;
    }
}

TrafficQuery::TrafficQuery(
    std::uint32_t srcaddress, 
    std::uint32_t destaddress, 
    int srcport,
    int destport,
    Protocol protocol
)
    : srcaddress_(srcaddress),
      destaddress_(destaddress),
      protocol_(protocol)
{
    if (portValid(srcport) && portValid(destport))
    {
        srcport_ = static_cast<std::uint16_t>(srcport);
        destport_ = static_cast<std::uint16_t>(destport);
    }
    else 
    {
        throw std::invalid_argument("Invalid source or destination Port");
    }
}

std::ostream& operator<<(std::ostream& os, const TrafficQuery& query)
{
    if (query.protocol_ == Protocol::TCP)
        os<<"TCP ";
    else os<<"UDP ";

    std::uint16_t byte1, byte2, byte3, byte4;

    byte1 = query.srcaddress_>>24;
    byte2 = (query.srcaddress_>>16) & 0xFFu;
    byte3 = (query.srcaddress_>>8) & 0xFFu;
    byte4 = query.srcaddress_ & 0xFFu;

    os<<byte1<<"."<<byte2<<"."<<byte3<<"."<<byte4<<":"<<query.srcport_;
    os<<" -> ";

    byte1 = query.destaddress_>>24;
    byte2 = (query.destaddress_>>16) & 0xFFu;
    byte3 = (query.destaddress_>>8) & 0xFFu;
    byte4 = query.destaddress_ & 0xFFu;

    os<<byte1<<"."<<byte2<<"."<<byte3<<"."<<byte4<<":"<<query.destport_;

    return os;
}

std::uint32_t TrafficQuery::srcAddress() const{
    return srcaddress_;
}
std::uint32_t TrafficQuery::destAddress() const{
    return destaddress_;
}
std::uint16_t TrafficQuery::destPort() const{
    return destport_;
}
Protocol TrafficQuery::getProtocol() const{
    return protocol_;
}