#ifndef TRAFFICQUERY_H
#define TRAFFICQUERY_H

#include <cstdint>
#include <iosfwd>

enum class Protocol{
    TCP,
    UDP
};

class TrafficQuery{
    std::uint32_t srcaddress_, destaddress_;
    std::uint16_t srcport_, destport_;
    
    Protocol protocol_;


public: 

    TrafficQuery(
        std::uint32_t srcaddress,
        std::uint32_t destaddress,
        int srcport,
        int destport,
        Protocol protocol
    );

    friend std::ostream& operator<<(
        std::ostream& os,
        const TrafficQuery& query
    );

    std::uint32_t srcAddress() const;
    std::uint32_t destAddress() const;
    std::uint16_t destPort() const;
    Protocol getProtocol() const;
};


#endif