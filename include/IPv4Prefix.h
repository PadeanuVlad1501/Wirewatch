#ifndef IPV4PREFIX_H
#define IPV4PREFIX_H

#include <cstdint>
#include <iosfwd>

class IPv4Prefix{
    std::uint32_t address_;
    int length_;

    static std::uint32_t calculateMask(int length);
public:
    explicit IPv4Prefix(std::uint32_t address, int length);

    bool contains(std::uint32_t address) const;

    friend std::ostream& operator<<(std::ostream& os, const IPv4Prefix& prefix);
};

#endif