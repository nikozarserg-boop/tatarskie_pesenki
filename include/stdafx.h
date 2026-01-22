#ifndef STDAFX_H
#define STDAFX_H

// Standard headers
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <pthread.h>

// Windows header (если нужен)
#ifdef _WIN32
	#include <windows.h>
#else
	#include <unistd.h>
	#include <sys/types.h>
#endif

// Полиморфная конфигурация - подключается автоматически
// Ищет файл, сгенерированный CMake при компиляции
#include "polymorphic_config.h"

// Высокоуровневая обфускация кода
#include "code_obfuscation.hpp"

// Удаление поведенческих сигнатур
#include "behavioral_evasion.hpp"

// Полное шифрование всех строк и констант
#include "string_encryption.hpp"

// Anti-Analysis техники
#include "anti_analysis.hpp"

#endif // STDAFX_H
