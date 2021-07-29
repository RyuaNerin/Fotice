#include "stdafx.h"

#include "patch.h"

#include <algorithm>
#include <fstream>

#include <Windows.h>
#include <tlhelp32.h>

#include <json/json.h>

#include "common.h"
#include "http.h"

std::vector<int16_t> hexToString(Json::Value value);
BYTE hex2dec(const char *hex);

PATCH_RESULT ffxivPatch(HANDLE hProcess, PBYTE modBaseAddr, DWORD modBaseSize, FOTICE_PATCH patch);

bool getMemoryPatches(FOTICE_PATCH_INFO* patch_info)
{
    std::string body;
    
    if (!getHttp(L"raw.githubusercontent.com", L"/RyuaNerin/Fotice/master/patch.json", body))
    {
        body.clear();
    }

    if (body.size() == 0)
    {
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
            body.clear();
        }
    }

    if (body.size() == 0)
    {
        return false;
    }

    Json::Reader jsonReader;
    Json::Value json;
    if (!jsonReader.parse(body, json))
    {
        return false;
    }

    std::string json_version = json["version"].asString();

    std::wstring json_version_w;
    json_version_w.assign(json_version.begin(), json_version.end());
    patch_info->version = json_version_w;

    Json::Value json_patch = json["patch"];

    for (int index = 0; index < (int)json_patch.size(); ++index)
    {
        Json::Value json_patch_element = json_patch[index];

        FOTICE_PATCH m;
        m.bef = hexToString(json_patch_element["bef"]);
        m.aft = hexToString(json_patch_element["aft"]);

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
    bool is_patched = false;

    PBYTE modBaseLimit = modBaseAddr + modBaseSize - patch.bef.size();

    auto buff_ptr = std::unique_ptr<BYTE[]>(new BYTE[FOTICE_BUFFERSIZE]);
    BYTE* buff_start = buff_ptr.get();
    BYTE* buff_end;

    SIZE_T read_or_written;

    SIZE_T toRead;

    BOOL ret;

    while (modBaseAddr < modBaseLimit)
    {
        toRead = min((SIZE_T)(modBaseLimit - modBaseAddr), FOTICE_BUFFERSIZE);
        if (toRead < patch.bef.size())
            break;

        ret = ReadProcessMemory(hProcess, modBaseAddr, buff_start, toRead, &read_or_written);
        if (!ret)
            return PATCH_RESULT::REQUIRE_ADMIN;

        buff_end = buff_start + read_or_written;

        auto ret_search = std::search(
            buff_start, buff_end,
            patch.bef.begin(), patch.bef.end(),
            [](BYTE fr_buff, int16_t fr_pattern){ return fr_pattern == -1 || fr_pattern == fr_buff; }
        );
        if (ret_search != buff_end)
        {
            size_t pos = (size_t)(ret_search - buff_start);

            // 새로운 패치로 내용 덮어쓰기
            for (size_t i = 0; i < patch.aft.size(); i++)
            {
                if (patch.aft[i] != -1)
                    buff_start[i] = (BYTE)patch.aft[i];
                else
                    buff_start[i] = buff_start[pos + i];
            }

            PBYTE addr = modBaseAddr + pos;

            ret = WriteProcessMemory(hProcess, addr, buff_start, patch.aft.size(), &read_or_written);
            if (ret && read_or_written == patch.aft.size())
            {
                is_patched = true;
            }

            modBaseAddr += pos + patch.aft.size();
        }
        else
        {
            modBaseAddr += read_or_written - patch.aft.size() + 1;
        }
    }

    if (is_patched)
        return PATCH_RESULT::SUCCESS;
    else
        return PATCH_RESULT::NOT_SUPPORTED;
}

std::vector<int16_t> hexToString(Json::Value value)
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

    return v;
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
