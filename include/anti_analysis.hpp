#pragma once
#include <string>
#include <cstdint>
#include <vector>
#include <thread>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #include <intrin.h>
    #include <winternl.h>
    #include <ntstatus.h>
#else
    #include <unistd.h>
    #include <cstdio>
#endif

// Обнаружение любых попыток анализа программы
// Уничтожение связи между отладчиком/анализатором и программой

class AntiAnalysis {
public:
    // Обнаружение отладчиков
    
    static bool DetectDebugger() {
#ifdef _WIN32
        return IsDebuggerPresent();
#else
        return DetectPtraceDebugger();
#endif
    }
    
    static bool DetectRemoteDebugger() {
#ifdef _WIN32
        // Проверяем подключен ли remote debugger
        BOOL bDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent);
        return (bDebuggerPresent == TRUE);
#else
        return false;
#endif
    }
    
    // Обнаружение DLL injection для анализа
    
    static bool DetectInjectedDLL() {
        // Ищем подозрительные DLL в памяти процесса
        std::vector<std::string> suspicious_dlls = {
            "frida-agent",      // Frida injection
            "pin",              // PIN instrumentation
            "unicorn",          // Unicorn emulator DLL
            "qemu",             // QEMU DLL
            "dbghelp",          // Debug helper
            "detours"           // Microsoft Detours
        };
        
        // Проверяем loadded modules
#ifdef _WIN32
        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (hModuleSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32 = {0};
            me32.dwSize = sizeof(MODULEENTRY32);
            
            if (Module32First(hModuleSnap, &me32)) {
                do {
                    std::string module_name = me32.szModule;
                    for (auto& suspicious : suspicious_dlls) {
                        if (module_name.find(suspicious) != std::string::npos) {
                            CloseHandle(hModuleSnap);
                            return true;
                        }
                    }
                } while (Module32Next(hModuleSnap, &me32));
            }
            CloseHandle(hModuleSnap);
        }
#endif
        return false;
    }
    
    // Обнаружение инструментов анализа в памяти
    
    static bool DetectAnalysisTools() {
#ifdef _WIN32
        // Проверяем наличие окон известных анализаторов
        std::vector<std::string> analyzer_windows = {
            "IDA",              // IDA Pro
            "Ghidra",           // Ghidra
            "x64dbg",           // x64dbg
            "Immunity",         // Immunity Debugger
            "OllyDbg",          // OllyDbg
            "WinDbg",           // Windows Debugger
            "Process Monitor",  // Process Monitor
            "Wireshark",        // Wireshark
            "Fiddler",          // Fiddler proxy
            "Charles",          // Charles proxy
            "Burp Suite"        // Burp Suite
        };
        
        for (auto& tool : analyzer_windows) {
            HWND hwnd = FindWindowA(NULL, tool.c_str());
            if (hwnd != NULL) {
                return true;
            }
        }
#endif
        return false;
    }
    
    // Обнаружение breakpoints в коде
    
    static bool DetectBreakpoints() {
#ifdef _WIN32
        // Проверяем INT3 breakpoints (0xCC)
        unsigned char* ptr = (unsigned char*)DetectBreakpoints;
        
        // Проверяем первые 100 байт функции
        for (int i = 0; i < 100; i++) {
            if (ptr[i] == 0xCC) {
                return true;
            }
        }
#endif
        return false;
    }
    
    // Обнаружение hooks в системных функциях
    
    static bool DetectHooks() {
#ifdef _WIN32
        // Проверяем первые 5 байт функции на JMP (E9, FF, 48 8B и т.д.)
        // которые указывают на hook
        
        LPVOID critical_functions[] = {
            (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA"),
            (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA"),
            (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile"),
            (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile"),
            (LPVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteFile")
        };
        
        for (auto func : critical_functions) {
            if (!func) continue;
            
            unsigned char* ptr = (unsigned char*)func;
            
            // JMP instruction
            if (ptr[0] == 0xE9) return true;
            
            // MOV r64, imm64; JMP r64
            if (ptr[0] == 0x48 && ptr[1] == 0xB8) return true;
            
            // NOP sled (0x90 0x90 0x90...) часто используется перед hooks
            int nop_count = 0;
            for (int i = 0; i < 10; i++) {
                if (ptr[i] == 0x90) nop_count++;
            }
            if (nop_count > 5) return true;
        }
#endif
        return false;
    }
    
    // Обнаружение трассировки (WinAPI hooks, ETW)
    
    static bool DetectTracing() {
#ifdef _WIN32
        // Проверяем ETW (Event Tracing for Windows)
        HANDLE hEvent = OpenEventA(GENERIC_READ, FALSE, "Global\\NT_TRACING_ENABLED");
        if (hEvent != NULL) {
            CloseHandle(hEvent);
            return true;
        }
        
        // Проверяем WMI Event Subscription
        // (требует проверки реестра)
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Tracing", 
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
#endif
        return false;
    }
    
    // Обнаружение профилирования
    
    static bool DetectProfiling() {
#ifdef _WIN32
        // Проверяем наличие профилировщика
        // Профилировщик устанавливает различные hooks и flags
        
        // Проверяем HEAP_FLAGS для Debug Heap
        HANDLE hHeap = GetProcessHeap();
        HEAP_INFORMATION_CLASS info;
        unsigned long heap_flags = 0;
        
        // Если кучи используют отладочные флаги - есть профилировщик
        // Это зависит от конфигурации системы
#endif
        return false;
    }
    
    // Обнаружение изменений кода в памяти
    
    static bool DetectCodePatching() {
#ifdef _WIN32
        // Вычисляем checksum функции и проверяем его периодически
        // Если checksum меняется - код был пропатчен
        
        static uint32_t initial_checksum = 0;
        
        if (initial_checksum == 0) {
            // Первый запуск - запоминаем checksum
            initial_checksum = ComputeCodeChecksum((unsigned char*)DetectCodePatching, 100);
        } else {
            // Проверяем, не изменился ли код
            uint32_t current_checksum = ComputeCodeChecksum((unsigned char*)DetectCodePatching, 100);
            return (current_checksum != initial_checksum);
        }
#endif
        return false;
    }
    
    // Обнаружение эмуляции
    
    static bool DetectEmulation() {
#ifdef _WIN32
        // Проверяем CPU flags, которые обычно имеют эмуляторы
        
        // CPUID для обнаружения гипервизора
        int cpuinfo[4] = {0, 0, 0, 0};
        
        __cpuid(cpuinfo, 1);
        
        // Флаг гипервизора (бит 31 ECX, который находится в cpuinfo[2])
        if (cpuinfo[2] & (1 << 31)) {
            return true; // Работаем в виртуальной машине/эмуляторе
        }
        
        // Проверяем CPUID для гипервизора
        __cpuid(cpuinfo, 0x40000000);
        
        if (cpuinfo[0] >= 0x40000000) {
            // Если вернулось что-то - есть гипервизор
            return true;
        }
#endif
        return false;
    }
    
    // Обнаружение порты отладки/мониторинга
    
    static bool DetectDebugPort() {
#ifdef _WIN32
        // Проверяем, подключен ли debugger через port
        // Обычно это порт 1024-5000
        
        // Более простой способ - проверить PEB (Process Environment Block)
        // Флаг BeingDebugged обычно игнорируется, но есть другие флаги
        
        // Проверяем NtQueryInformationProcess с ProcessDebugObjectHandle
        typedef NTSTATUS(NTAPI * pNtQueryInformationProcess)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        
        pNtQueryInformationProcess NtQueryInformationProcess =
            (pNtQueryInformationProcess)GetProcAddress(
                GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        
        if (NtQueryInformationProcess) {
            HANDLE hDebugObject = NULL;
            ULONG len = 0;
            
            NTSTATUS status = NtQueryInformationProcess(
                GetCurrentProcess(),
                (PROCESSINFOCLASS)30, // ProcessDebugObjectHandle
                &hDebugObject,
                sizeof(HANDLE),
                &len);
            
            if (NT_SUCCESS(status) && hDebugObject != NULL) {
                return true;
            }
        }
#endif
        return false;
    }
    
    // РЕАКЦИЯ НА ОБНАРУЖЕНИЕ
    
    static void ReactToAnalysis() {
        // Различные способы прервать анализ
        
        // Метод 1: Молчаливый выход
        if (DetectDebugger() || DetectAnalysisTools() || DetectHooks()) {
            exit(-1);
        }
        
        // Метод 2: Генерирование исключения
        if (DetectBreakpoints()) {
            throw std::runtime_error("Analysis detected");
        }
        
        // Метод 3: Бесконечный цикл (зависнуть, чтобы анализатор вышел)
        if (DetectTracing()) {
            volatile int x = 0;
            while (true) x++;
        }
        
        // Метод 4: Повреждение памяти (crash)
        if (DetectEmulation()) {
            int* null_ptr = nullptr;
            *null_ptr = 0xDEADBEEF;
        }
    }
    
    // НЕПРЕРЫВНАЯ ПРОВЕРКА
    
    static void MonitorForAnalysis() {
        // Запускается в фоновом потоке
        // Периодически проверяет признаки анализа
        
        while (true) {
            // Проверяем каждые 100ms
#ifdef _WIN32
            Sleep(100);
#else
            sleep(1);
#endif
            
            // Множественные проверки
            if (DetectInjectedDLL()) {
                ReactToAnalysis();
                break;
            }
            
            if (DetectHooks()) {
                ReactToAnalysis();
                break;
            }
            
            if (DetectCodePatching()) {
                ReactToAnalysis();
                break;
            }
            
            if (DetectDebugPort()) {
                ReactToAnalysis();
                break;
            }
        }
    }
    
private:
    static uint32_t ComputeCodeChecksum(unsigned char* code, size_t size) {
        uint32_t checksum = 0;
        for (size_t i = 0; i < size; i++) {
            checksum = (checksum * 31 + code[i]) ^ 0xDEADBEEF;
        }
        return checksum;
    }
    
    static bool DetectPtraceDebugger() {
#ifdef __linux__
        // Linux: проверяем /proc/self/status для TracerPid
        FILE* fp = fopen("/proc/self/status", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "TracerPid")) {
                    // Получаем PID
                    int tracer_pid = 0;
                    sscanf(line, "TracerPid:\t%d", &tracer_pid);
                    fclose(fp);
                    return (tracer_pid != 0);
                }
            }
            fclose(fp);
        }
#endif
        return false;
    }
};

// Макросы для использования

#define CHECK_ANALYSIS() \
    if (AntiAnalysis::DetectDebugger() || \
        AntiAnalysis::DetectAnalysisTools() || \
        AntiAnalysis::DetectEmulation()) { \
        exit(-1); \
    }

#define MONITOR_ANALYSIS() \
    std::thread analysis_monitor([]() { \
        AntiAnalysis::MonitorForAnalysis(); \
    }); \
    analysis_monitor.detach()

#define REACT_TO_ANALYSIS() \
    AntiAnalysis::ReactToAnalysis()
