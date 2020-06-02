#pragma once
#include "includes.hpp"

namespace utils {
    inline std::string time_to_str(std::time_t time) {
        char buff[15];
        struct tm timeinfo;

        localtime_s(&timeinfo, &time);

        strftime(buff, sizeof(buff), "%Y-%m-%d", &timeinfo);

        return std::string(buff);
    }
}