#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

class Security {
public:
    // Анти-отладчик
    static bool IsDebuggerPresent();
    static bool IsRunningInVirtualMachine();
    static void DetectBreakpoints();
    
    // Контрольная сумма
    static uint32_t CalculateChecksum(const std::string& data);
    static bool VerifyChecksum(const std::string& data, uint32_t expectedChecksum);
    
    // Шифрование (Advanced XOR + rotation + подстановка)
    static std::string EncryptString(const std::string& plaintext, const std::string& key);
    static std::string DecryptString(const std::string& ciphertext, const std::string& key);
    
    // Быстрое шифрование для больших данных
    static void EncryptBuffer(uint8_t* buffer, size_t size, const std::string& key);
    static void DecryptBuffer(uint8_t* buffer, size_t size, const std::string& key);
    
    // Проверка целостности кода
    static uint32_t GetCodeChecksum();
    static bool VerifyCodeIntegrity();
    
    // Помощники для зашифрованных путей
    static std::string DecryptPath(const std::string& encryptedPath);
    
private:
    static const uint32_t MAGIC_KEY = 0xDEADBEEF;
    static const uint8_t SBOX[256];
    static uint8_t SubstituteValue(uint8_t val);
};

// Макросы для шифрования строк во время компиляции
#define ENCRYPT_STR(str) Security::EncryptString(str, "TS_KEY_2024")
#define DECRYPT_STR(str) Security::DecryptString(str, "TS_KEY_2024")
