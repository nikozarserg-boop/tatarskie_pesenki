#include "stdafx.h"
#include <Windows.h>
#include <thread>
#include <chrono>

// Функция для отключения монитора
void TurnOffMonitor()
{
	SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)2);
}
