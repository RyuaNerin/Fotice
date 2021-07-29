#pragma once

#include <string>

#include <Windows.h>
#include <tlhelp32.h>

#include <json/json.h>

typedef struct _FOTICE_PATCH
{
    std::shared_ptr<int16_t[]> aft;
    size_t                     aft_size = 0;

    std::shared_ptr<int16_t[]> bef;
    size_t                     bef_size = 0;

    std::shared_ptr<size_t[]> prefix_table;
} FOTICE_PATCH;

typedef struct _FOTICE_PATCH_INFO
{
    std::wstring version;

    std::vector<FOTICE_PATCH> patch;
} FOTICE_PATCH_INFO;

enum class PATCH_RESULT : DWORD
{
    SUCCESS,
    NOT_SUPPORTED,
    REQUIRE_ADMIN
};

bool getMemoryPatches(FOTICE_PATCH_INFO*);
PATCH_RESULT ffxivPatch(PROCESSENTRY32 pEntry, std::vector<FOTICE_PATCH> patch);
