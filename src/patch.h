#pragma once

#include <string>
#include <vector>

typedef struct _FOTICE_PATCH
{
    std::vector<int16_t> aft;
    std::vector<int16_t> bef;
    bool req;
} FOTICE_PATCH;

typedef struct _FOTICE_PATCH_INFO
{
    std::wstring version;

    std::vector<FOTICE_PATCH> patch;
} FOTICE_PATCH_INFO;

enum class PATCH_RESULT : int
{
    SUCCESS,
    NOT_SUPPORTED,
    REQUIRE_ADMIN
};

bool getMemoryPatches(FOTICE_PATCH_INFO*);
PATCH_RESULT ffxivPatch(PROCESSENTRY32 pEntry, std::vector<FOTICE_PATCH> patch);
