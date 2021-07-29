#include "stdafx.h"

#include "patch.h"

#include <algorithm>
#include <fstream>

#include "common.h"
#include "http.h"

std::shared_ptr<int16_t[]> hexToString(Json::Value value, size_t* length);
BYTE hex2dec(const char *hex);

PATCH_RESULT ffxivPatch(HANDLE hProcess, PBYTE modBaseAddr, DWORD modBaseSize, FOTICE_PATCH patch);

bool getMemoryPatches(FOTICE_PATCH_INFO* patch_info)
{
    std::string body;
    try
    {
        std::ifstream fs("patch.json");
        fs.seekg(0, std::ios::end);
        body.reserve(fs.tellg());
        fs.seekg(0, std::ios::beg);

        body.assign((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    }
    catch (const std::exception&)
    {
    }

#ifndef _DEBUG
    if (body.size() == 0 && !getHttp(L"raw.githubusercontent.com", L"/RyuaNerin/Fotice/master/json_patch_element.json", body))
    {
        return false;
    }
#endif

    Json::Reader jsonReader;
    Json::Value json;
    if (!jsonReader.parse(body, json))
    {
        return false;
    }

    std::string json_version = json["json_version"].asString();

    std::wstring json_version_w;
    json_version_w.assign(json_version.begin(), json_version.end());
    patch_info->version = json_version_w;

    Json::Value json_patch = json["patch"];

    for (int index = 0; index < (int)json_patch.size(); ++index)
    {
        Json::Value json_patch_element = json_patch[index];

        FOTICE_PATCH m;
        m.bef = hexToString(json_patch_element["bef"], &m.bef_size);
        m.aft = hexToString(json_patch_element["aft"], &m.aft_size);

        patch_info->patch.push_back(m);
    }

    return true;
}

bool getFFXIVModule(DWORD pid, LPCWSTR lpModuleName, PBYTE* modBaseAddr, DWORD* modBaseSize)
{
    bool res = false;

    MODULEENTRY32 snapEntry = { 0 };
    snapEntry.dwSize = sizeof(MODULEENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot)
    {
        if (Module32First(hSnapshot, &snapEntry))
        {
            do
            {
                if (lstrcmpi(snapEntry.szModule, lpModuleName) == 0)
                {
                    *modBaseAddr = snapEntry.modBaseAddr;
                    *modBaseSize = snapEntry.modBaseSize;
                    res = true;
                    break;
                }
            } while (Module32Next(hSnapshot, &snapEntry));
        }
        CloseHandle(hSnapshot);
    }

    return res;
}

PATCH_RESULT ffxivPatch(PROCESSENTRY32 pEntry, std::vector<FOTICE_PATCH> patch)
{
    PBYTE modBaseAddr;
    DWORD modBaseSize;

    if (!getFFXIVModule(pEntry.th32ProcessID, pEntry.szExeFile, &modBaseAddr, &modBaseSize))
        return PATCH_RESULT::REQUIRE_ADMIN;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pEntry.th32ProcessID);
    if (hProcess == NULL)
        return PATCH_RESULT::REQUIRE_ADMIN;

    PATCH_RESULT result;
    for (int8_t i = 0; i < patch.size(); ++i)
    {
        result = ffxivPatch(hProcess, modBaseAddr, modBaseSize, patch[i]);
        if (result != PATCH_RESULT::SUCCESS)
            return result;
    }

    return PATCH_RESULT::SUCCESS;
}

PATCH_RESULT ffxivPatch(HANDLE hProcess, PBYTE modBaseAddr, DWORD modBaseSize, FOTICE_PATCH patch)
{
    bool res = false;

    PBYTE modBaseLimit = modBaseAddr + modBaseSize - patch.bef_size;

    auto buff_ptr = std::unique_ptr<BYTE[]>(new BYTE[FOTICE_BUFFERSIZE]);
    BYTE* buff_start = buff_ptr.get();
    BYTE* buff_end;

    SIZE_T read;

    SIZE_T toRead;

    auto pat_start = patch.bef.get();
    auto pat_end = patch.bef.get() + patch.bef_size;

    while (modBaseAddr < modBaseLimit)
    {
        toRead = (SIZE_T)(modBaseLimit - modBaseAddr);
        if (toRead > FOTICE_BUFFERSIZE)
            toRead = FOTICE_BUFFERSIZE;

        if (toRead < patch.bef_size)
            break;

        if (!ReadProcessMemory(hProcess, modBaseAddr, buff_start, toRead, &read))
            return PATCH_RESULT::REQUIRE_ADMIN;

        buff_end = buff_start + read;

        auto ret = std::search(buff_start, buff_end, pat_start, pat_end, [](BYTE fr_buff, int16_t fr_pattern){ return fr_pattern == -1 || fr_pattern == fr_buff; });
        if (ret != buff_end)
        {
            size_t pos = (size_t)(ret - buff_start);

            // 쓰기...
            for (size_t i = 0; i < patch.aft_size; i++)
            {
                if (patch.aft.get()[i] != -1)
                    buff_start[i] = (BYTE)patch.aft.get()[i];
                else
                    buff_start[i] = buff_start[pos + i];
            }

            PBYTE addr = modBaseAddr + pos;
            SIZE_T written;

            if (WriteProcessMemory(hProcess, addr, buff_start, patch.aft_size, &written) && written == patch.aft_size)
                res = true;

            modBaseAddr += pos + patch.aft_size;
        }
        else
        {
            modBaseAddr += read - patch.aft_size + 1;
        }
    }

    if (res)
        return PATCH_RESULT::SUCCESS;
    else
        return PATCH_RESULT::NOT_SUPPORTED;
}

std::shared_ptr<int16_t[]> hexToString(Json::Value value, size_t* length)
{
    std::string str = value.asCString();
    const char* cstr = str.c_str();
    const size_t str_len = str.size();

    std::vector<int16_t> v;

    size_t i = 0;
    while (i < str_len)
    {
        if (str[i] == ' ')
        {
            i++;
            continue;
        }

        v.push_back((str[i] == '?') ? -1 : hex2dec(cstr + i));

        i += 2;
    }

    *length = v.size();

    auto buf = std::shared_ptr<int16_t[]>(new int16_t[v.size()]);
    std::copy(v.begin(), v.end(), buf.get());

    return buf;
}

BYTE hex2dec(const char *hex)
{
    BYTE val = 0;

    if (hex[0] >= '0' && hex[0] <= '9') val = (hex[0] - '0') << 4;
    else if (hex[0] >= 'a' && hex[0] <= 'f') val = (hex[0] - 'a' + 10) << 4;
    else if (hex[0] >= 'A' && hex[0] <= 'F') val = (hex[0] - 'A' + 10) << 4;

    if (hex[1] >= '0' && hex[1] <= '9') val |= hex[1] - '0';
    else if (hex[1] >= 'a' && hex[1] <= 'f') val |= hex[1] - 'a' + 10;
    else if (hex[1] >= 'A' && hex[1] <= 'F') val |= hex[1] - 'A' + 10;

    return val;
}
