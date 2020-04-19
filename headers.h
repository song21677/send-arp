#include <stdint.h>

#pragma pack(push, 1)
struct Etherheader {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t etype;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ARPheader {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hal;
    uint8_t pal;
    uint16_t opcode;
    uint8_t smac[6];
    uint32_t sip;
    uint8_t tmac[6];
    uint32_t tip;
};
#pragma pack(pop)
