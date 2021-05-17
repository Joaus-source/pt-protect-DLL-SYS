#include "MmProtect.h"
#include "PEOperation.h"


DWORD crc32 = 0;

uint32_t crc32_table[256];

int make_crc32_table()
{
	uint32_t c;
	int i = 0;
	int bit = 0;

	for (i = 0; i < 256; i++)
	{
		c = (uint32_t)i;

		for (bit = 0; bit < 8; bit++)
		{
			if (c & 1)
			{
				c = (c >> 1) ^ (0xEDB88320);
			}
			else
			{
				c = c >> 1;
			}

		}
		crc32_table[i] = c;
	}
	return c;

}
uint32_t make_crc(uint32_t crc, unsigned char* string, uint32_t size)
{

	while (size--)
		crc = (crc >> 8) ^ (crc32_table[(crc ^ *string++) & 0xff]);

	return crc;
}
void MmProtect_init()
{
	HANDLE pebase = GetModuleHandle(NULL);
	IMAGE_NT_HEADERS* ntheader;
	ntheader = GetNtHeader((PBYTE)pebase);
	DWORD crc_base = ntheader->OptionalHeader.BaseOfCode;
	DWORD crc_size = ntheader->OptionalHeader.SizeOfCode;
	make_crc32_table();
	crc32 = make_crc(0xffffffff, (unsigned char *)pebase + crc_base, crc_size);
}

bool check_crc32()
{
	bool bret = true;
	HANDLE pebase = GetModuleHandle(NULL);
	IMAGE_NT_HEADERS* ntheader;
	ntheader = GetNtHeader((PBYTE)pebase);
	DWORD crc_base = ntheader->OptionalHeader.BaseOfCode;
	DWORD crc_size = ntheader->OptionalHeader.SizeOfCode;
	if (crc32 != make_crc(0xffffffff, (unsigned char*)pebase + crc_base, crc_size))
	{
		bret = false;
	}
	return bret;
}