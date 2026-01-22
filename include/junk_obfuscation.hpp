#pragma once
#include <cstdlib>
#include <cstring>
#include <random>

#ifdef _WIN32
    #include <windows.h>
#endif

// Обфускация через мусорный код и junk файлы
// Делает программу нечитаемой для анализаторов

class JunkObfuscation {
private:
    static constexpr int JUNK_DATA_SIZE = 50 * 1024 * 1024; // 50MB мусора
    static char* junk_buffer;
    
public:
    // Создание громадного статического массива для увеличения размера бинарника
    static void AllocateJunkMemory() {
        junk_buffer = (char*)malloc(JUNK_DATA_SIZE);
        if (junk_buffer) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            
            for (int i = 0; i < JUNK_DATA_SIZE; i++) {
                junk_buffer[i] = (char)dis(gen);
            }
        }
    }
    
    // Создание мусорных файлов для маскировки реальных операций
    static void CreateGarbageFiles() {
#ifdef _WIN32
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        // Создаём сотни файлов с мусором
        for (int i = 0; i < 500; i++) {
            volatile char filename[256];
            sprintf((char*)filename, "temp_%d_%d.tmp", i, rand());
            
            FILE* fp = fopen((const char*)filename, "wb");
            if (fp) {
                // Каждый файл 100KB случайных данных
                for (int j = 0; j < 100000; j++) {
                    unsigned char byte = dis(gen);
                    fwrite(&byte, 1, 1, fp);
                }
                fclose(fp);
                remove((const char*)filename);
            }
        }
#endif
    }
    
    // Модификация собственного кода в памяти
    static void SelfModifyingCode() {
#ifdef _WIN32
        // Выделяем память для выполняемого кода
        unsigned char junk_code[] = {
            0x55, 0x89, 0xE5, 0x83, 0xEC, 0x20,
            0xC7, 0x45, 0xFC, 0x00, 0x00, 0x00, 0x00,
            0x8B, 0x45, 0xFC, 0x83, 0xC0, 0x01,
            0x89, 0x45, 0xFC, 0x8B, 0x45, 0xFC,
            0x83, 0xF8, 0x64, 0x7C, 0xEB,
            0xC9, 0xC3
        };
        
        unsigned char* exec_buffer = (unsigned char*)VirtualAlloc(
            NULL, sizeof(junk_code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        
        if (exec_buffer) {
            memcpy(exec_buffer, junk_code, sizeof(junk_code));
            DWORD old_protect;
            VirtualProtect(exec_buffer, sizeof(junk_code), PAGE_EXECUTE_READ, &old_protect);
            VirtualFree(exec_buffer, 0, MEM_RELEASE);
        }
#endif
    }
    
    // Заполнение памяти случайными данными (anti-debugging)
    static void CorruptMemory() {
        volatile unsigned char* ptr = (volatile unsigned char*)malloc(10 * 1024 * 1024);
        if (ptr) {
            for (int i = 0; i < 10 * 1024 * 1024; i++) {
                ptr[i] = (unsigned char)rand();
                // Периодически обращаемся к памяти
                if (i % 1000000 == 0) {
                    volatile unsigned char dummy = ptr[i];
                    (void)dummy;
                }
            }
            free((void*)ptr);
        }
    }
    
    // Мусорная логика с множеством вычислений
    static void ObfuscatedJunkLogic() {
        volatile int x = 0xDEADBEEF;
        volatile int y = 0xCAFEBABE;
        volatile int z = 0;
        volatile int w = 0;
        
        // Выполняем огромное количество бессмысленных операций
        for (volatile int iteration = 0; iteration < 5000000; iteration++) {
            // XOR и ротации
            x = ((x ^ y) + (x * 31)) ^ 0xAAAA5555;
            y = (y << 13) | (y >> 19);
            z = ((x ^ y ^ z) * 0x27D4EB2D) ^ 0x55555555;
            w = (z << 7) | (z >> 25);
            
            // Дополнительные вычисления
            volatile int temp1 = (x + y) ^ (z - w);
            volatile int temp2 = (temp1 * 7) + (temp1 >> 4);
            volatile int temp3 = (temp2 ^ 0xDEADBEEF) + (x & y);
            
            // Периодические проверки (для запутывания)
            if (iteration % 500000 == 0) {
                volatile int dummy = temp3;
                (void)dummy;
            }
        }
    }
    
    // Dead code - множество невыполняемых путей
    static void DeadCodePaths() {
        volatile int condition = (POLY_VERSION ^ POLY_RANDOM_SEED) & 0xFF;
        
        if (condition == 0xFFFFFFFF) {
            // Невозможный путь 1
            volatile int impossible1 = 0;
            for (int i = 0; i < 1000000; i++) {
                impossible1 += (i * 0xDEADBEEF) ^ (i << 3);
            }
        }
        
        if (condition == 0) {
            // Невозможный путь 2
            volatile int impossible2 = 0;
            for (int i = 0; i < 1000000; i++) {
                impossible2 += (i * 0xCAFEBABE) ^ (i >> 2);
            }
        }
        
        if (condition > 1000) {
            // Невозможный путь 3
            volatile int impossible3 = 0;
            for (int i = 0; i < 1000000; i++) {
                impossible3 += (i * condition) ^ (i + 1);
            }
        }
        
        // Код, который кажется важным, но ничего не делает
        volatile char dummy_string[1000] = "This is a dummy string for obfuscation";
        volatile int dummy_value = strlen((const char*)dummy_string);
        (void)dummy_value;
    }
    
    // Anti-disassembly через встраивание данных в код
    static void AntiDisassembly() {
        // Встраиваем случайные данные, которые выглядят как код
        volatile unsigned char fake_code[] = {
            0x48, 0x8D, 0x15, 0xE0, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xC2, 0x48, 0x8D, 0x0D, 0xD8,
            0x00, 0x00, 0x00, 0xFF, 0x15, 0xD2, 0x00,
            0x00, 0x00, 0xC3, 0x90, 0x90, 0x90, 0x90
        };
        
        // Выполняем с защитой памяти
#ifdef _WIN32
        DWORD old_protect;
        VirtualProtect((void*)fake_code, sizeof(fake_code), PAGE_EXECUTE_READ, &old_protect);
#endif
    }
    
    // Случайные циклы для замедления анализа
    static void RandomizedLoops() {
        std::random_device rd;
        int seed = rd() % 10000 + 1000;
        
        volatile int result = 0;
        for (volatile int i = 0; i < seed * 1000; i++) {
            result ^= (i * 0x7FFFFFFF) + (i >> 3);
        }
    }
    
    // Криптографические операции для имитации реальной работы
    static void FakeCrypto() {
        unsigned char data[256];
        for (int i = 0; i < 256; i++) {
            data[i] = (unsigned char)rand();
        }
        
        // Несколько раундов бессмысленного "шифрования"
        for (int round = 0; round < 10; round++) {
            for (int i = 0; i < 256; i++) {
                data[i] ^= (unsigned char)(i ^ round);
                data[i] = ((data[i] << 3) | (data[i] >> 5));
                data[i] += (unsigned char)rand();
            }
        }
    }
    
    // Главная функция обфускации
    static void ExecuteAllObfuscation() {
        // Выполняем все техники в полиморфном порядке
        volatile int execution_order = POLY_VERSION % 8;
        
        switch(execution_order) {
            case 0:
                AllocateJunkMemory();
                ObfuscatedJunkLogic();
                DeadCodePaths();
                SelfModifyingCode();
                break;
            case 1:
                CreateGarbageFiles();
                FakeCrypto();
                CorruptMemory();
                RandomizedLoops();
                break;
            case 2:
                ObfuscatedJunkLogic();
                AntiDisassembly();
                DeadCodePaths();
                AllocateJunkMemory();
                break;
            case 3:
                CorruptMemory();
                SelfModifyingCode();
                FakeCrypto();
                RandomizedLoops();
                break;
            case 4:
                DeadCodePaths();
                RandomizedLoops();
                CreateGarbageFiles();
                ObfuscatedJunkLogic();
                break;
            case 5:
                AntiDisassembly();
                AllocateJunkMemory();
                FakeCrypto();
                SelfModifyingCode();
                break;
            case 6:
                RandomizedLoops();
                CorruptMemory();
                DeadCodePaths();
                AntiDisassembly();
                break;
            case 7:
                FakeCrypto();
                CreateGarbageFiles();
                ObfuscatedJunkLogic();
                SelfModifyingCode();
                break;
        }
    }
    
    // Очистка
    static void Cleanup() {
        if (junk_buffer) {
            free(junk_buffer);
            junk_buffer = NULL;
        }
    }
};

// Объявление статического буфера (инициализация в .cpp)
// Объявлено как extern в header, определено в security.cpp

// Макрос для быстрого вызова
#define OBFUSCATE_ALL() JunkObfuscation::ExecuteAllObfuscation()
