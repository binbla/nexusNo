#include <cstdarg>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "../include/utils.hpp"
template <size_t N>
std::string array_to_hex(const std::array<uint8_t, N>& data) {
    std::string result;
    result.reserve(N * 2);
    for (uint8_t byte : data) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        result += buf;
    }
    return result;
}
std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    // 补实现
}
