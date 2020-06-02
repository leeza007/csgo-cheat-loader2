#pragma once
#include <stdint.h>

// Your DLL as a byte array
// I need to find a way to download this dll from a server and convert it to a uint8_t array :(
// mini tutorial : use the pe2hex python file to get the representation of the dll and put the dll representation here

static const uint8_t binary[] = {
	0x6e, 0x69, 0x67, 0x67, 0x61, 0x62, 0x79, 0x74, 0x65,
};
