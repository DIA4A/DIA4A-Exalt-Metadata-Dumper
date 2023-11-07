#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <windows.h>

std::vector<unsigned char> LoadFileBuffer(const std::string& m_strFile)
{
	std::vector<unsigned char> m_pBuffer;
	std::ifstream m_pFile(m_strFile.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

	std::streamsize m_nSize = 0;
	if (m_pFile.seekg(0, std::ios::end).good())
	{
		m_nSize = m_pFile.tellg();
	}

	if (m_pFile.seekg(0, std::ios::beg).good())
	{
		m_nSize -= m_pFile.tellg();
	}

	if (m_nSize > 0)
	{
		m_pBuffer.resize((std::size_t)m_nSize);
		m_pFile.read((char*)(&m_pBuffer[0]), m_nSize);
	}

	return m_pBuffer;
}

int main()
{
	CreateDirectoryA("DIA4A", NULL);

	std::vector<unsigned char> m_pGlobalMetadata = LoadFileBuffer(R"(RotMG Exalt_Data\il2cpp_data\Metadata\global-metadata.dat)");
	if (m_pGlobalMetadata.empty())
	{
		printf("[-] Failed To Find global-metadata.dat, Make Sure The Tool Is In The Right Folder\n");
		getchar();
		return 1;
	}

	PROCESS_INFORMATION m_pProcessInformation;
	memset(&m_pProcessInformation, 0, sizeof(m_pProcessInformation));

	STARTUPINFOA m_pStartupInfo;
	memset(&m_pStartupInfo, 0, sizeof(m_pStartupInfo));

	bool m_bProcessCreated = CreateProcessA(
		"RotMG Exalt.exe", NULL,
		NULL, NULL, 
		NULL, CREATE_SUSPENDED,
		NULL, NULL, 
		&m_pStartupInfo, &m_pProcessInformation
	);

	if (!m_bProcessCreated)
	{
		printf("[-] Failed To Start Exalt");
		getchar();
		return 1;
	}

	printf("[+] Started Exalt Successfully!\n");

	HANDLE m_pProcessHandle = m_pProcessInformation.hProcess;

	std::string m_strDumperModuleName = "DumperModule.dll";

	void* m_pRemoteDumperModuleName = VirtualAllocEx(m_pProcessHandle, NULL, m_strDumperModuleName.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD m_dwWPMResult = WriteProcessMemory(m_pProcessHandle, m_pRemoteDumperModuleName, m_strDumperModuleName.data(), m_strDumperModuleName.size(), NULL);

	if (m_pRemoteDumperModuleName == nullptr || m_dwWPMResult == 0)
	{
		printf("[-] Failed To Write Module String In Exalt\n");
		getchar();
		return 1;
	}

	printf("[+] Wrote Module String In Exalt Successfully!\n");

	void* m_pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryA");
	if (m_pLoadLibraryA == nullptr)
	{
		printf("[-] Failed To Find LoadLibraryA\n");
		getchar();
		return 1;
	}

	HANDLE m_pRemoteThread = CreateRemoteThread(m_pProcessHandle, (LPSECURITY_ATTRIBUTES)NULL, NULL, (LPTHREAD_START_ROUTINE)m_pLoadLibraryA, m_pRemoteDumperModuleName, NULL, NULL);
	if (m_pRemoteThread == nullptr)
	{
		printf("[-] Failed To Create Module Mapping Thread\n");
		getchar();
		return 1;
	}

	printf("[+] Mapped Dumper Module Into Memory Successfully!\n"); // bs but cba to find a better way to express the above

	if (WaitForSingleObject(m_pRemoteThread, 10000) != WAIT_OBJECT_0)
	{
		printf("[-] Something Failed While Waiting For The Module Dumper\n");
		getchar();
		return 1;
	}

	printf("[+] The Module Dumper Has Been Loaded!\n");
	printf("[+] Waiting For A Maximum Of 30 Seconds For The Metadata Header To Be Dumped\n");

	// delete it incase it already exists so we can check for a new one
	_unlink("DIA4A\\decrypted-metadata-header.dat");

	ResumeThread(m_pProcessInformation.hThread);

	bool m_bDumpFinished = false;
	for (int i = 0; i < 300; i++)
	{
		Sleep(100);

		if (std::ifstream("DIA4A\\decrypted-metadata-header.dat").is_open())
		{
			m_bDumpFinished = true;
			break;
		}
	}

	TerminateProcess(m_pProcessInformation.hProcess, 0);

	if (!m_bDumpFinished)
	{
		printf("[-] Failed To Dump Metadata Header After 30 Seconds Of Waiting\n");
		getchar();
		return 1;
	}

	printf("[+] The Decrypted Metadata Header Should Now Be Dumped In \"DIA4A\\decrypted-metadata-header.dat\"\n");

	printf("[+] Trying To Unshuffle The Header\n");
	{
		std::vector<unsigned char> m_pDecryptedMetadataBuffer = LoadFileBuffer("DIA4A\\decrypted-metadata-header.dat");

		int m_nIntegerCount = m_pDecryptedMetadataBuffer.size() / sizeof(int);
		std::vector<int> m_nDecryptedMetadata(m_nIntegerCount);
		memcpy(m_nDecryptedMetadata.data(), m_pDecryptedMetadataBuffer.data(), m_pDecryptedMetadataBuffer.size());

		int m_nHighestRealOffset = 0;
		std::map<int, int> m_nOffsetInstances;
		for (int i = 0; i < m_nIntegerCount; i++)
		{
			int& m_nCurrentOffsetInstances = m_nOffsetInstances[m_nDecryptedMetadata[i]];
			m_nCurrentOffsetInstances++;

			if (m_nCurrentOffsetInstances == 3 && m_nDecryptedMetadata[i] > 1000000)
			{
				m_nHighestRealOffset = m_nDecryptedMetadata[i];
				break;
			}
		}

		// the size of the last offset should be within 4 bytes of the actual "globla-metadata.dat" file size (ty smol/smolplague)
		int m_nBytesToFileEnd = m_pGlobalMetadata.size() - m_nHighestRealOffset;

		int m_nLastOffsetSize = 0;
		for (int i = 0; i < m_nIntegerCount; i++)
		{
			if (m_nDecryptedMetadata[i] % 4 != 0 || std::abs(m_nBytesToFileEnd - m_nDecryptedMetadata[i]) > 4)
			{
				continue;
			}

			m_nLastOffsetSize = m_nDecryptedMetadata[i];
			break;
		}

		std::vector<std::pair<int, int>> m_nPairs;
		m_nPairs.push_back({ m_nHighestRealOffset, m_nLastOffsetSize });
		m_nPairs.push_back({ m_nHighestRealOffset, 0 });
		m_nPairs.push_back({ m_nHighestRealOffset, 0 });


		int m_nOffsetsLeft = 28;
		int m_nCurrentOffset = m_nHighestRealOffset;

		for (int m_nRunInstance = 0; m_nRunInstance < 28; m_nRunInstance++)
		{
			for (int i = 0; i < m_nIntegerCount; i++)
			{
				if (m_nDecryptedMetadata[i] <= 0 || m_nDecryptedMetadata[i] % 4 != 0)
				{
					continue;
				}

				bool m_bFound = false;
				for (int j = 0; j < m_nIntegerCount; j++)
				{
					if (m_nDecryptedMetadata[j] <= 0)
					{
						continue;
					}

					// m_nCurrentOffset = current offset
					// m_nDecryptedMetadata[i] = size of previous offset
					// m_nDecryptedMetadata[j] = previous offset

					int m_nPreviousOffset = m_nDecryptedMetadata[j];
					int m_nPreviousSize = m_nDecryptedMetadata[i];

					int m_nMax = m_nPreviousOffset > m_nPreviousSize ? m_nPreviousOffset : m_nPreviousSize;
					int m_nMin = m_nPreviousOffset < m_nPreviousSize ? m_nPreviousOffset : m_nPreviousSize;
					if (m_nPairs.size() == 25 || m_nPairs.size() == 28 || m_nPairs.size() == 29 || m_nPairs.size() == 30)
					{
						m_nPreviousOffset = m_nMin;
						m_nPreviousSize = m_nMax;
					}
					else
					{
						m_nPreviousOffset = m_nMax;
						m_nPreviousSize = m_nMin;
					}

					int m_nOffsetDelta = m_nCurrentOffset - m_nPreviousOffset;
					if (std::abs(m_nPreviousSize - m_nOffsetDelta) <= 4)
					{
						m_nPairs.push_back({ m_nPreviousOffset, m_nPreviousSize });
						m_nCurrentOffset = m_nPreviousOffset;
						m_nOffsetsLeft--;

						m_nDecryptedMetadata[i] = 0;
						m_nDecryptedMetadata[j] = 0;

						m_bFound = true;
						break;
					}
				}

				if (m_bFound)
				{
					break;
				}
			}
		}

		m_nPairs.push_back({ 0xFAB11BAF, 29 }); // add the sanity and version
		std::reverse(m_nPairs.begin(), m_nPairs.end());

		if (m_nOffsetsLeft == 0)
		{
			printf("[+] Unshuffled All Offsets Successfully, Saving As \"DIA4A\\unshuffled-metadata-header.dat\"\n");

			int m_nUnshuffledHeader[64];
			for (int i = 0; i < 64; i += 2)
			{
				m_nUnshuffledHeader[i] = m_nPairs[i / 2].first;
				m_nUnshuffledHeader[i + 1] = m_nPairs[i / 2].second;
			}

			FILE* m_pUnshuffledMetadataHeaderFile = nullptr;
			fopen_s(&m_pUnshuffledMetadataHeaderFile, "DIA4A\\unshuffled-metadata-header.dat", "wb");
			fwrite(m_nUnshuffledHeader, 1, sizeof(m_nUnshuffledHeader), m_pUnshuffledMetadataHeaderFile);
			fclose(m_pUnshuffledMetadataHeaderFile);


			printf("[+] Found global-metadata.dat, Creating \"DIA4A\\global-metadata.dat\" With The Unshuffled Header\n");

			memcpy(m_pGlobalMetadata.data(), m_nUnshuffledHeader, sizeof(m_nUnshuffledHeader));

			FILE* m_pUnshuffledGlobalMetadataFile = nullptr;
			fopen_s(&m_pUnshuffledGlobalMetadataFile, "DIA4A\\global-metadata.dat", "wb");
			fwrite(m_pGlobalMetadata.data(), 1, m_pGlobalMetadata.size(), m_pUnshuffledGlobalMetadataFile);
			fclose(m_pUnshuffledGlobalMetadataFile);
		}
		else
		{
			printf("[-] Failed To Unshuffle Offsets In The Header\n");
		}
	}
	printf("[+] Finished Executing\n");
	getchar();

	return 0;
}