#pragma once
#include <string>
#include <map>

typedef struct filesystems_s
{
    std::string Name;
    std::string FSType;
    uint32_t Type;
    bool IsNetwork;
    bool IsLocal;
    bool IsSpecial;

    filesystems_s(std::string && name, std::string && fstype, uint32_t type, bool network, bool local, bool special) : 
        Name(name), FSType(fstype), Type(type), IsNetwork(network), IsLocal(local), IsSpecial(special) { }
} filesystems_t;


extern const std::map<uint32_t, filesystems_t> filesystems;