#include "security.h"
#include "string_encryption.hpp"
#include <iostream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #include <intrin.h>
#else
    #include <unistd.h>
    #include <sys/ptrace.h>
#endif

// S-box для подстановки (AES-подобный)
const uint8_t Security::SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xd7, 0x4b, 0x55, 0xcf, 0x34, 0xc5, 0x84,
    0xcb, 0xcf, 0x18, 0xcd, 0x6f, 0x53, 0x59, 0x4a, 0x43, 0x6d, 0x08, 0xd0, 0x39, 0x56, 0x27, 0xf3,
    0x10, 0x61, 0x5c, 0x6e, 0xf7, 0x42, 0xec, 0xb3, 0x51, 0xf8, 0x6e, 0x25, 0x8e, 0xde, 0xfc, 0x8d,
    0xfa, 0xd7, 0x6b, 0x76, 0x8c, 0xcc, 0x4d, 0x4e, 0xd9, 0xb1, 0x54, 0x5e, 0xe3, 0x40, 0x45, 0xf1
};

// Анти-отладчик: Проверка присоединён ли отладчик
bool Security::IsDebuggerPresent() {
#ifdef _WIN32
    // Windows: Проверка отладчика
    return ::IsDebuggerPresent() == TRUE;
#else
    // Linux: Проверка ptrace
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return true;
    }
    ptrace(PTRACE_DETACH, 0, 1, 0);
    return false;
#endif
}

// Анти-отладчик: Проверка виртуальной машины
bool Security::IsRunningInVirtualMachine() {
#ifdef _WIN32
    // Проверка типичных индикаторов VM
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\Description\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256] = {0};
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, 
            (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            std::string manufacturer(buffer);
            if (manufacturer.find("VMware") != std::string::npos ||
                manufacturer.find("VirtualBox") != std::string::npos ||
                manufacturer.find("QEMU") != std::string::npos) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    
    return false;
#else
    // Определение VM на Linux
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "hypervisor")) {
                fclose(fp);
                return true;
            }
        }
        fclose(fp);
    }
    return false;
#endif
}

// Анти-отладчик: Обнаружение breakpoints
void Security::DetectBreakpoints() {
#ifdef _WIN32
    // Проверка INT3 breakpoints (0xCC)
    DWORD oldProtect;
    unsigned char* ptr = (unsigned char*)DetectBreakpoints;
    
    VirtualProtect(ptr, 1, PAGE_EXECUTE_READ, &oldProtect);
    if (*ptr == 0xCC) {
        std::cerr << "[SECURITY] Breakpoint detected!" << std::endl;
        exit(-1);
    }
    VirtualProtect(ptr, 1, oldProtect, &oldProtect);
#endif
}

// Calculate CRC32 checksum
uint32_t Security::CalculateChecksum(const std::string& data) {
    uint32_t crc = 0xFFFFFFFF;
    
    for (unsigned char byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(int)(crc & 1));
        }
    }
    
    return crc ^ 0xFFFFFFFF;
}

// Verify checksum
bool Security::VerifyChecksum(const std::string& data, uint32_t expectedChecksum) {
    return CalculateChecksum(data) == expectedChecksum;
}

// Подстановка байта с помощью S-box
uint8_t Security::SubstituteValue(uint8_t val) {
    return SBOX[val];
}

// Шифрование строки с помощью XOR + rotation + S-box подстановка
std::string Security::EncryptString(const std::string& plaintext, const std::string& key) {
    std::string encrypted = plaintext;
    size_t keyLen = key.length();
    
    if (keyLen == 0) return plaintext;
    
    for (size_t i = 0; i < encrypted.length(); i++) {
        uint8_t byte = (uint8_t)encrypted[i];
        
        // S-box подстановка
        byte = SubstituteValue(byte);
        
        // XOR с ключом
        byte ^= (uint8_t)key[i % keyLen];
        
        // Ротация
        int shift = ((i % 8) + 1);
        byte = ((byte << shift) | (byte >> (8 - shift)));
        
        // Дополнительный XOR с позицией
        byte ^= (uint8_t)(i & 0xFF);
        
        encrypted[i] = (char)byte;
    }
    
    return encrypted;
}

// Дешифрование строки
std::string Security::DecryptString(const std::string& ciphertext, const std::string& key) {
    std::string decrypted = ciphertext;
    size_t keyLen = key.length();
    
    if (keyLen == 0) return ciphertext;
    
    for (size_t i = 0; i < decrypted.length(); i++) {
        uint8_t byte = (uint8_t)decrypted[i];
        
        // Обратный XOR с позицией
        byte ^= (uint8_t)(i & 0xFF);
        
        // Обратная ротация
        int shift = ((i % 8) + 1);
        byte = ((byte >> shift) | (byte << (8 - shift)));
        
        // XOR с ключом
        byte ^= (uint8_t)key[i % keyLen];
        
        // Обратная S-box подстановка
        for (int j = 0; j < 256; j++) {
            if (SBOX[j] == byte) {
                byte = (uint8_t)j;
                break;
            }
        }
        
        decrypted[i] = (char)byte;
    }
    
    return decrypted;
}

// Шифрование буфера на месте
void Security::EncryptBuffer(uint8_t* buffer, size_t size, const std::string& key) {
    if (!buffer || size == 0 || key.length() == 0) return;
    
    size_t keyLen = key.length();
    
    for (size_t i = 0; i < size; i++) {
        uint8_t byte = buffer[i];
        
        // S-box подстановка
        byte = SubstituteValue(byte);
        
        // XOR с ключом
        byte ^= (uint8_t)key[i % keyLen];
        
        // Ротация
        int shift = ((i % 8) + 1);
        byte = ((byte << shift) | (byte >> (8 - shift)));
        
        // XOR с позицией
        byte ^= (uint8_t)(i & 0xFF);
        
        buffer[i] = byte;
    }
}

// Дешифрование буфера на месте
void Security::DecryptBuffer(uint8_t* buffer, size_t size, const std::string& key) {
    if (!buffer || size == 0 || key.length() == 0) return;
    
    size_t keyLen = key.length();
    
    for (size_t i = 0; i < size; i++) {
        uint8_t byte = buffer[i];
        
        // Обратный XOR с позицией
        byte ^= (uint8_t)(i & 0xFF);
        
        // Обратная ротация
        int shift = ((i % 8) + 1);
        byte = ((byte >> shift) | (byte << (8 - shift)));
        
        // XOR с ключом
        byte ^= (uint8_t)key[i % keyLen];
        
        // Обратная S-box подстановка
        for (int j = 0; j < 256; j++) {
            if (SBOX[j] == byte) {
                byte = (uint8_t)j;
                break;
            }
        }
        
        buffer[i] = byte;
    }
}

// Помощник для дешифрования путей
std::string Security::DecryptPath(const std::string& encryptedPath) {
    return DecryptString(encryptedPath, "TS_KEY_2024");
}

// Инициализация мастер ключа для StringEncryption
const std::string StringEncryption::MASTER_KEY = "MASTER_ENCRYPTION_KEY_TS";

// Вычисление контрольной суммы исполняемого кода
uint32_t Security::GetCodeChecksum() {
#ifdef _WIN32
    HMODULE hModule = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    
    DWORD codeSize = pNtHeaders->OptionalHeader.SizeOfCode;
    return CalculateChecksum(std::string((char*)hModule, codeSize));
#else
    return 0;
#endif
}

// Проверка целостности кода
bool Security::VerifyCodeIntegrity() {
#ifdef _WIN32
    static uint32_t initialChecksum = GetCodeChecksum();
    return GetCodeChecksum() == initialChecksum;
#else
    return true;
#endif
}
