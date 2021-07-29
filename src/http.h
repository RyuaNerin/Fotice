#pragma once

#include <string>

#include <Windows.h>

bool getHttp(LPCWSTR host, LPCWSTR path, std::string &body);
