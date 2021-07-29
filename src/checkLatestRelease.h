#pragma once

#include <Windows.h>

enum class RELEASE_RESULT : DWORD
{
    LATEST,
    NEW_RELEASE,
    NETWORK_ERROR,
    PARSING_ERROR
};

RELEASE_RESULT checkLatestRelease();
