#pragma once

#include <string>
#include <base64.h>

// file taken from course site.

class Base64Wrapper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};
