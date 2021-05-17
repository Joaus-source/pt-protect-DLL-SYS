#pragma once
#include <Windows.h>
typedef DWORD32 uint32_t;
int make_crc32_table();
uint32_t make_crc(uint32_t crc, unsigned char* string, uint32_t size);
void MmProtect_init();
bool check_crc32();
