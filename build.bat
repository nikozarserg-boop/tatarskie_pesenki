@echo off

setlocal enabledelayedexpansion

where cmake >nul 2>nul
if %errorlevel% neq 0 (
    exit /b 1
)

cd /d "%~dp0"

echo [0/4] Очистка старых файлов...
if exist build (
    rmdir /s /q build >nul 2>&1
)

if exist dist (
    rmdir /s /q dist >nul 2>&1
)

mkdir build >nul 2>&1

mkdir dist >nul 2>&1

cd build

echo.
echo [1/4] Генерация файлов конфигурации...
cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-O3 -fvisibility=hidden" ..
if %errorlevel% neq 0 (
    echo [ОШИБКА] CMake конфигурация не удалась
    exit /b 1
)

echo.
echo [2/4] Компиляция
cmake --build . --config Release
if %errorlevel% neq 0 (
    echo [ОШИБКА] Компиляция не удалась
    exit /b 1
)

echo.
echo [3/4] Проверка файла...
if exist "bin\tatarskie_pesenki.exe" (
    echo [OK] tatarskie_pesenki.exe скомпилирован
) else (
    echo [ОШИБКА] tatarskie_pesenki.exe не найден
    exit /b 1
)

copy "bin\tatarskie_pesenki.exe" "..\dist\tatarskie_pesenki.exe" >nul 2>&1
echo [OK] tatarskie_pesenki.exe скопирован в папку dist

echo.
echo [4/4] Обфускация (удаление символов отладки)...
strip "..\dist\tatarskie_pesenki.exe" >nul 2>&1
echo [OK] Символы отладки удалены

cd ..
