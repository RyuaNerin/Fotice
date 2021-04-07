//#define __TEST

#include <windows.h>
#include <TlHelp32.h>

#include <cstdint>
#include <memory>
#include <string>

#include "minhook/include/MinHook.h"

constexpr char* Signature = "4055535641544157488dac24????????4881ec20020000488b05";

#ifdef __TEST

void DebugLog(const wchar_t *fmt, ...)
{
    va_list	va;
    va_start(va, fmt);
    size_t len = std::wcslen(L"Fotice: ") + vswprintf(nullptr, 0, fmt, va) + 2;
    auto str = std::make_unique<wchar_t[]>(len);

    if (str == nullptr)
    {
        va_end(va);
        return;
    }

    len = wsprintfW(str.get(), L"Fotice: ");
    wvsprintfW(str.get() + len, fmt, va);

    va_end(va);

    OutputDebugStringW(str.get());
}
#else
#define DebugLog
#endif


typedef void(*OnMessageDelegate)(void* manager, uint16_t chatType, const void* senderName, const void* message, uint32_t senderId, void* parameter);
OnMessageDelegate OnMessageOriginal;

void Notice(void* manager);
void OnMessage(void* manager, uint16_t chatType, const void* senderName, const void* message, uint32_t senderId, void* parameter)
{
    Notice(manager);

    if (chatType == 3)
    {
        DebugLog(L"Filtered : chatType: %d", chatType);
        return;
    }
    DebugLog(L"New Chat : [%d] %s", chatType, message);

    OnMessageOriginal(manager, chatType, senderName, message, senderId, parameter);
}

bool noticePrinted = false;
void Notice(void* manager)
{
    if (noticePrinted) return;
    noticePrinted = true;

    // 이제부터 Fotice 가 공지사항 출력을 차단합니다.
    // 만든이 : RyuaNerin (admin@ryuar.in)

    std::string sender("");
    std::string text1("  \xec\x9d\xb4\xec\xa0\x9c\xeb\xb6\x80\xed\x84\xb0\x20\x46\x6f\x74\x69\x63\x65\x20\xea\xb0\x80\x20\xea\xb3\xb5\xec\xa7\x80\xec\x82\xac\xed\x95\xad\x20\xec\xb6\x9c\xeb\xa0\xa5\xec\x9d\x84\x20\xec\xb0\xa8\xeb\x8b\xa8\xed\x95\xa9\xeb\x8b\x88\xeb\x8b\xa4\x2e  ");
    std::string text2("  \xeb\xa7\x8c\xeb\x93\xa0\xec\x9d\xb4\x20\x3a\x20\x52\x79\x75\x61\x4e\x65\x72\x69\x6e\x20\x28\x61\x64\x6d\x69\x6e\x40\x72\x79\x75\x61\x72\x2e\x69\x6e\x29  ");

    OnMessageOriginal(manager, 3, &sender, &text1, 0, nullptr);
    OnMessageOriginal(manager, 3, &sender, &text2, 0, nullptr);
}

LPVOID OnMessageAddr = nullptr;
bool sigScan();

BOOL g_hooked = FALSE;
BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    DebugLog(L"DllMain : fdwReason: %d", fdwReason);
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DebugLog(L"DLL_PROCESS_ATTACH");

            if (sigScan() && MH_Initialize() == MH_OK)
            {
                g_hooked = TRUE;

                DebugLog(L"Initialized");
                MH_CreateHook(OnMessageAddr, &OnMessage, (LPVOID*)&OnMessageOriginal);
                MH_EnableHook(OnMessageAddr);
            }
            
            break;

        case DLL_PROCESS_DETACH:
            DebugLog(L"DLL_PROCESS_DETACH");

            if (g_hooked)
            {
                MH_DisableHook(OnMessageAddr);
                MH_RemoveHook(OnMessageAddr);
                MH_Uninitialize();
            }
            break;
    }

    return TRUE;
}

typedef struct
{
    size_t size;
    std::unique_ptr<bool[]> mask;
    std::unique_ptr<byte[]> value;

    std::unique_ptr<size_t[]> bch; // Bad Character Heuristic
} signature;

byte hex2dec(const char* hex);
void genBCH(signature* sig);
bool getFFXIVModule(DWORD pid, uint8_t** modBaseAddr, size_t* modBaseSize);
uint8_t* findSignature(const uint8_t* modBaseAddr, const size_t modBaseSize, const signature *sig);
bool sigScan()
{
    if (OnMessageAddr != nullptr)
        return true;

    // signature 만들기
    signature sig;
    sig.size  = std::strlen(Signature) / 2;
    sig.mask  = std::make_unique<bool[]>(sig.size);
    sig.value = std::make_unique<byte[]>(sig.size);

    for (size_t i = 0; i < sig.size; i++)
    {
        if (Signature[i * 2] == '?')
        {
            sig.mask[i] = true;
        }
        else
        {
            sig.value[i] = hex2dec(Signature + i * 2);
            sig.mask[i] = false;
        }
    }
    genBCH(&sig);

    DebugLog(L"signature : baseSize: %d", sig.size);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    // 파이널 판타지 메인 모듈 주소 얻어오기

    auto pid = GetCurrentProcessId();
    DebugLog(L"pid %d", pid);

    uint8_t* baseAddr = nullptr;
    size_t baseSize = 0;

    if (!getFFXIVModule(pid, &baseAddr, &baseSize))
    {
        DebugLog(L"Module not found");
        return false;
    }
    DebugLog(L"Module found : %p / %p", baseAddr, baseSize);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    // 위치 계산
    auto funcAddr = findSignature(baseAddr, baseSize, &sig);
    if (funcAddr == nullptr)
    {
        DebugLog(L"Signaure not found");
        return false;
    }
    DebugLog(L"Signaure found : %x", funcAddr);

    OnMessageAddr = funcAddr;

    return true;
}

byte hex2dec(const char* hex)
{
    byte val = 0;

    if      (hex[0] >= '0' && hex[0] <= '9') val  = (hex[0] - '0'     ) << 4;
    else if (hex[0] >= 'a' && hex[0] <= 'f') val  = (hex[0] - 'a' + 10) << 4;
    else if (hex[0] >= 'A' && hex[0] <= 'F') val  = (hex[0] - 'A' + 10) << 4;

    if      (hex[1] >= '0' && hex[1] <= '9') val |= (hex[1] - '0'     );
    else if (hex[1] >= 'a' && hex[1] <= 'f') val |= (hex[1] - 'a' + 10);
    else if (hex[1] >= 'A' && hex[1] <= 'F') val |= (hex[1] - 'A' + 10);

    return val;
}

void genBCH(signature *sig)
{
    sig->bch = std::make_unique<size_t[]>(256);

    size_t last = sig->size - 1;
    size_t idx;
    for (idx = last; idx > 0 && !sig->mask[idx]; --idx)
    {
    }

    auto diff = last - idx;
    if (diff == 0) diff = 1;

    for (idx = 0; idx <= 255; ++idx)
        sig->bch[idx] = diff;
    for (idx = last - diff; idx < last; ++idx)
        sig->bch[sig->value[idx]] = last - idx;
}

bool getFFXIVModule(DWORD pid, uint8_t** modBaseAddr, size_t* modBaseSize)
{
    bool res = false;

    MODULEENTRY32W snapEntry = { 0, };
    snapEntry.dwSize = sizeof(MODULEENTRY32W);

    const auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot)
    {
        if (Module32FirstW(hSnapshot, &snapEntry))
        {
            do
            {
                if (lstrcmpiW(snapEntry.szModule, L"ffxiv_dx11.exe") == 0)
                {
                    *modBaseAddr = reinterpret_cast<uint8_t*>(snapEntry.modBaseAddr);
                    *modBaseSize = static_cast<size_t>(snapEntry.modBaseSize);
                    res = true;
                    break;
                }
            } while (Module32Next(hSnapshot, &snapEntry));
        }
        CloseHandle(hSnapshot);
    }
    return res;
}

size_t findArray(const uint8_t* source, const size_t sourceSize, const signature *sig);
uint8_t* findSignature(const uint8_t* baseAddr, const size_t baseSize, const signature *sig)
{
    const auto offset = findArray(baseAddr, baseSize, sig);
    if (offset != -1)
    {
        return const_cast<uint8_t*>(baseAddr + offset);
    }

    return nullptr;
}

size_t findArray(const uint8_t* baseAddr, const size_t baseSize, const signature* sig)
{
    if (sig->size > baseSize)
    {
        return -1;
    }

    const size_t sigLast = sig->size - 1;

    size_t offset = 0;
    const size_t offsetMax = baseSize - sig->size;
    while (offset <= offsetMax)
    {
        size_t position;
        for (position = sigLast; sig->mask[position] || sig->value[position] == baseAddr[offset + position]; position--)
        {
            if (position == 0)
                return offset;
        }
        offset += sig->bch[baseAddr[offset + sigLast]];
    }

    return -1;
}
