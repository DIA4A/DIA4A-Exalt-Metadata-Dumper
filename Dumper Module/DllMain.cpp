#include <iostream>
#include <windows.h>
#include <psapi.h>

#include "MinHook.h"


#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define GETBITS( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define GETBYTE( x )    (GETBITS(x[0]) << 4 | GETBITS(x[1]))

DWORD64 FindPattern(DWORD64 m_dwAddress, const std::string& m_strPattern)
{
	const char* m_szPattern = m_strPattern.c_str();
	DWORD64 m_dwFirstMatch = 0;

	MODULEINFO m_pModuleInformation;
	K32GetModuleInformation(GetCurrentProcess(), (HMODULE)m_dwAddress, &m_pModuleInformation, sizeof(MODULEINFO));
	DWORD64 m_dwEndAddress = m_dwAddress + m_pModuleInformation.SizeOfImage;

	for (DWORD64 m_dwCurrentAddress = m_dwAddress; m_dwCurrentAddress < m_dwEndAddress; m_dwCurrentAddress++)
	{
		if (!*m_szPattern)
		{
			return m_dwFirstMatch;
		}

		if (*(PBYTE)m_szPattern == '\?' || *(BYTE*)m_dwCurrentAddress == GETBYTE(m_szPattern))
		{
			if (!m_dwFirstMatch)
			{
				m_dwFirstMatch = m_dwCurrentAddress;
			}

			if (!m_szPattern[2])
			{
				return m_dwFirstMatch;
			}

			(*(PWORD)m_szPattern == '\?\?' || *(PBYTE)m_szPattern != '\?') ? m_szPattern += 3 : m_szPattern += 2;
		}
		else
		{
			m_szPattern = m_strPattern.c_str();
			m_dwFirstMatch = 0;
		}
	}

	return 0;
}

void* DecryptMetadataHeaderOriginal = nullptr;
void* __stdcall DecryptMetadataHeader(void* a1, DWORD64 m_dwHeaderSize, void* a3, void* a4)
{
    void* m_pResult = ((decltype(&DecryptMetadataHeader))DecryptMetadataHeaderOriginal)(a1, m_dwHeaderSize, a3, a4);

	FILE* m_pDecryptedMetadataHeaderFile = nullptr;
	fopen_s(&m_pDecryptedMetadataHeaderFile, "DIA4A\\decrypted-metadata-header.dat", "wb");
	fwrite(m_pResult, 1, m_dwHeaderSize, m_pDecryptedMetadataHeaderFile);
	fclose(m_pDecryptedMetadataHeaderFile);

	return m_pResult;
}

BOOL APIENTRY DllMain(HMODULE m_pModule, DWORD m_dwReason, LPVOID m_pReserved)
{
	if (m_dwReason == DLL_PROCESS_ATTACH)
	{
		DWORD64 m_dwGameAssemblyAddress = (DWORD64)LoadLibraryA("GameAssembly.dll");

		DWORD64 m_dwXXTEADecrypt = FindPattern(m_dwGameAssemblyAddress, "4C 89 4C 24 ? 53 55 48 83 EC ? 41");
		if (m_dwXXTEADecrypt == 0)
		{
			MessageBoxA(NULL, "Failed To Find The xxtea Decrypt Function", "Dumper Module", MB_OK);
			return TRUE;
		}

		MH_Initialize();

		MH_CreateHook((void*)m_dwXXTEADecrypt, DecryptMetadataHeader, &DecryptMetadataHeaderOriginal);

		MH_EnableHook(MH_ALL_HOOKS);
	}
    return TRUE;
}

