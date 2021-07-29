#include "stdafx.h"

#ifdef _DEBUG
#define _CRT_SECURE_NO_WARNINGS

#include <memory>
#include <iostream>
#include <string>

#include <windows.h>

#include "debugLog.h"

void DebugLog(const wchar_t* fmt, ...)
{
    va_list	va;
    va_start(va, fmt);
    size_t len = static_cast<size_t>(vswprintf(nullptr, 0, fmt, va)) + 2;
    auto str = std::make_unique<wchar_t[]>(len);

    if (str == nullptr)
    {
        va_end(va);
        return;
    }

    wvsprintfW(str.get(), fmt, va);

    va_end(va);

    std::wcout << std::wstring(str.get()) << std::endl;
}
#endif
