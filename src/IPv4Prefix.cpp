#include "IPv4Prefix.h"
#include <stdexcept>
#include <ostream>


std::uint32_t IPv4Prefix::calculateMask(int length){
        
    if ( length < 0 || length > 32)
    {
    throw std::invalid_argument("IPv4 prefix length must be between 0 and 32");
    }

    if (length == 0) return 0;
    return (0xFFFFFFFFu << (32-length));
}



IPv4Prefix::IPv4Prefix(std::uint32_t address, int length) : length_(length){
    
    std::uint32_t mask = calculateMask(length);
    address_ = address & mask;
    
}

bool IPv4Prefix::contains(std::uint32_t address) const{
    std::uint32_t mask = calculateMask(length_);
    return address_ == (address & mask);
}

std::ostream& operator<<(std::ostream& os, const IPv4Prefix& prefix)
{
    std::uint16_t byte1, byte2, byte3, byte4;

    byte1 = prefix.address_>>24;
    byte2 = (prefix.address_>>16) & 0xFFu;
    byte3 = (prefix.address_>>8) & 0xFFu;
    byte4 = prefix.address_ & 0xFFu;

    return os<<byte1<<"."<<byte2<<"."<<byte3<<"."<<byte4<<"/"<<prefix.length_;
}