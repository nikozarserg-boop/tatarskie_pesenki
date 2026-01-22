#include "stdafx.h"
#include "ScreenMelting.h"
#include <thread>
#include <chrono>
#include <cstdlib>
#include <ctime>

// Глобальные переменные
int screenWidth = 0;
int screenHeight = 0;
int interval = 100;
bool g_running = true;

#ifdef _WIN32
    #include <windows.h>

    LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        switch (msg)
        {
            case WM_CREATE:
            {
                HDC desktop = GetDC(HWND_DESKTOP);
                HDC window = GetDC(hWnd);
                
                BitBlt(window, 0, 0, screenWidth, screenHeight, desktop, 0, 0, SRCCOPY);
                
                ReleaseDC(hWnd, window);
                ReleaseDC(HWND_DESKTOP, desktop);
                
                SetTimer(hWnd, 0, interval, 0);
                ShowWindow(hWnd, SW_SHOW);
                break;
            }
            case WM_PAINT:
            {
                ValidateRect(hWnd, 0);
                break;
            }
            case WM_TIMER:
            {
                HDC hdc = GetDC(hWnd);
                
                int x = (rand() % screenWidth) - (200 / 2);
                int y = (rand() % 15);
                int width = (rand() % 200);
                
                BitBlt(hdc, x, y, width, screenHeight, hdc, x, 0, SRCCOPY);
                
                ReleaseDC(hWnd, hdc);
                break;
            }
            case WM_DESTROY:
            {
                PostQuitMessage(0);
                break;
            }
        }
        return DefWindowProcA(hWnd, msg, wParam, lParam);
    }

    DWORD WINAPI ScreenMeltingThread(LPVOID lpParam)
    {
        screenWidth = GetSystemMetrics(SM_CXSCREEN);
        screenHeight = GetSystemMetrics(SM_CYSCREEN);
        
        srand((unsigned)GetTickCount());
        
        WNDCLASSA wndClass = {};
        wndClass.lpfnWndProc = MainWndProc;
        wndClass.hCursor = NULL;
        wndClass.lpszClassName = "ScreenMelting";
        
        if (RegisterClassA(&wndClass))
        {
            HWND hWnd = CreateWindowExA(WS_EX_TOPMOST, "ScreenMelting", 0, WS_POPUP, 0, 0, screenWidth, screenHeight,
                HWND_DESKTOP, 0, 0, 0);
            
            if (hWnd)
            {
                MSG msg = { 0 };
                
                while (g_running && msg.message != WM_QUIT)
                {
                    if (PeekMessage(&msg, 0, 0, 0, PM_REMOVE))
                    {
                        TranslateMessage(&msg);
                        DispatchMessage(&msg);
                    }
                    else
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                }
                
                DestroyWindow(hWnd);
            }
        }
        
        return 0;
    }

    void InitializeWindow()
    {
        HANDLE hThread = CreateThread(NULL, 0, ScreenMeltingThread, NULL, 0, NULL);
        if (hThread)
        {
            CloseHandle(hThread);
        }
    }

#elif defined(__APPLE__)
    // macOS реализация через Cocoa
    #include <Cocoa/Cocoa.h>
    #include <CoreGraphics/CoreGraphics.h>

    void ScreenMeltingWorker()
    {
        @autoreleasepool
        {
            NSScreen* mainScreen = [NSScreen mainScreen];
            screenWidth = (int)mainScreen.frame.size.width;
            screenHeight = (int)mainScreen.frame.size.height;

            NSWindow* window = [[NSWindow alloc]
                initWithContentRect:NSMakeRect(0, 0, screenWidth, screenHeight)
                styleMask:NSWindowStyleMaskBorderless
                backing:NSBackingStoreBuffered
                defer:NO];

            [window setOpaque:YES];
            [window setBackgroundColor:[NSColor blackColor]];
            [window setLevel:NSScreenSaverWindowLevel];
            [window makeKeyAndOrderFront:nil];

            srand((unsigned)time(nullptr));

            CGDirectDisplayID mainDisplay = CGMainDisplayID();
            
            while (g_running)
            {
                // Захватываем экран
                CGImageRef screenshot = CGDisplayCreateImage(mainDisplay);
                if (!screenshot)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(interval));
                    continue;
                }

                NSImage* nsImage = [[NSImage alloc] initWithCGImage:screenshot size:NSZeroSize];
                NSImageView* imageView = [[NSImageView alloc] initWithFrame:NSMakeRect(0, 0, screenWidth, screenHeight)];
                [imageView setImage:nsImage];

                // Эффект "плавления"
                for (int i = 0; i < 20; ++i)
                {
                    int x = rand() % screenWidth;
                    int y = rand() % 30;
                    int width = 50 + rand() % 150;

                    if (x + width > screenWidth)
                        width = screenWidth - x;

                    // Копируем полосу вниз
                    CGRect srcRect = CGRectMake(x, y, width, screenHeight - y);
                    CGRect dstRect = CGRectMake(x, y + 5, width, screenHeight - y - 5);
                    CGImageRef croppedImage = CGImageCreateWithImageInRect(screenshot, srcRect);
                    
                    if (croppedImage)
                    {
                        CGContextRef ctx = (CGContextRef)[[NSGraphicsContext currentContext] graphicsPort];
                        CGContextDrawImage(ctx, dstRect, croppedImage);
                        CGImageRelease(croppedImage);
                    }
                }

                CFRelease(screenshot);
                [nsImage release];
                [imageView release];

                std::this_thread::sleep_for(std::chrono::milliseconds(interval));
            }

            [window release];
        }
    }

    void InitializeWindow()
    {
        std::thread melting_thread(ScreenMeltingWorker);
        melting_thread.detach();
    }

#else
    // Linux X11 реализация
    #include <X11/Xlib.h>
    #include <X11/Xutil.h>
    #include <X11/extensions/Xrandr.h>

    void ScreenMeltingWorker()
    {
        Display* display = XOpenDisplay(nullptr);
        if (!display)
            return;

        int screen = DefaultScreen(display);
        Window root = RootWindow(display, screen);
        
        screenWidth = DisplayWidth(display, screen);
        screenHeight = DisplayHeight(display, screen);

        // Создаём окно на весь экран
        XSetWindowAttributes attrs = {};
        attrs.background_pixel = BlackPixel(display, screen);
        attrs.override_redirect = True;

        Window window = XCreateWindow(
            display, root,
            0, 0, screenWidth, screenHeight, 0,
            DefaultDepth(display, screen),
            InputOutput,
            DefaultVisual(display, screen),
            CWBackPixel | CWOverrideRedirect,
            &attrs
        );

        XMapWindow(display, window);
        XRaiseWindow(display, window);

        // Выбираем события
        XSelectInput(display, window, ExposureMask | KeyPressMask);

        GC gc = XCreateGC(display, window, 0, nullptr);
        XSetForeground(display, gc, BlackPixel(display, screen));
        XSetBackground(display, gc, WhitePixel(display, screen));

        srand((unsigned)time(nullptr));

        XEvent event;
        while (g_running)
        {
            // Обработка событий
            while (XPending(display))
            {
                XNextEvent(display, &event);
                if (event.type == KeyPress)
                {
                    g_running = false;
                    break;
                }
            }

            // Рисуем эффект плавления
            for (int i = 0; i < 20; ++i)
            {
                int x = rand() % screenWidth;
                int y = rand() % 30;
                int width = 50 + rand() % 150;

                if (x + width > screenWidth)
                    width = screenWidth - x;

                // Копируем полосу вниз (эффект стекания)
                XCopyArea(display, window, window, gc,
                    x, y, width, screenHeight - y,
                    x, y + 5);

                XFlush(display);
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(interval));
        }

        XFreeGC(display, gc);
        XDestroyWindow(display, window);
        XCloseDisplay(display);
    }

    void InitializeWindow()
    {
        std::thread melting_thread(ScreenMeltingWorker);
        melting_thread.detach();
    }

#endif
