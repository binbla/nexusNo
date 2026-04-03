#include <cstdarg>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

#include "../include/crypto_provider.hpp"
#include "../include/utils.hpp"

namespace wg {

// ============================================================================
// Logger Implementation
// ============================================================================

LogLevel Logger::current_level_ = LogLevel::INFO;

void Logger::set_level(LogLevel level) { current_level_ = level; }

LogLevel Logger::get_level() { return current_level_; }

std::string Logger::timestamp_string() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string Logger::level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO";
        case LogLevel::WARN:
            return "WARN";
        case LogLevel::ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

void Logger::debug(const std::string& message) {
    if (current_level_ <= LogLevel::DEBUG) {
        std::cerr << "[" << timestamp_string() << "] [DEBUG] " << message
                  << std::endl;
    }
}

void Logger::info(const std::string& message) {
    if (current_level_ <= LogLevel::INFO) {
        std::cerr << "[" << timestamp_string() << "] [INFO] " << message
                  << std::endl;
    }
}

void Logger::warn(const std::string& message) {
    if (current_level_ <= LogLevel::WARN) {
        std::cerr << "[" << timestamp_string() << "] [WARN] " << message
                  << std::endl;
    }
}

void Logger::error(const std::string& message) {
    if (current_level_ <= LogLevel::ERROR) {
        std::cerr << "[" << timestamp_string() << "] [ERROR] " << message
                  << std::endl;
    }
}

void Logger::log(LogLevel level, const char* fmt, ...) {
    if (current_level_ > level) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    // Allocate buffer for formatted string
    va_list args_copy;
    va_copy(args_copy, args);
    int size = vsnprintf(nullptr, 0, fmt, args_copy);
    va_end(args_copy);

    if (size > 0) {
        std::vector<char> buffer(size + 1);
        vsnprintf(buffer.data(), buffer.size(), fmt, args);

        std::string message(buffer.data());
        switch (level) {
            case LogLevel::DEBUG:
                debug(message);
                break;
            case LogLevel::INFO:
                info(message);
                break;
            case LogLevel::WARN:
                warn(message);
                break;
            case LogLevel::ERROR:
                error(message);
                break;
        }
    }

    va_end(args);
}

// ============================================================================
// Random Implementation
// ============================================================================

std::vector<uint8_t> Random::bytes(size_t size) {
    // Note: This would need access to crypto provider
    // For now, return empty - will be implemented when crypto integration is
    // complete
    return std::vector<uint8_t>(size, 0);
}

uint32_t Random::uint32() {
    auto bytes = Random::bytes(4);
    uint32_t result = 0;
    result |= (uint32_t)bytes[0] << 24;
    result |= (uint32_t)bytes[1] << 16;
    result |= (uint32_t)bytes[2] << 8;
    result |= (uint32_t)bytes[3];
    return result;
}

uint64_t Random::uint64() {
    auto bytes = Random::bytes(8);
    uint64_t result = 0;
    result |= (uint64_t)bytes[0] << 56;
    result |= (uint64_t)bytes[1] << 48;
    result |= (uint64_t)bytes[2] << 40;
    result |= (uint64_t)bytes[3] << 32;
    result |= (uint64_t)bytes[4] << 24;
    result |= (uint64_t)bytes[5] << 16;
    result |= (uint64_t)bytes[6] << 8;
    result |= (uint64_t)bytes[7];
    return result;
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        result += buf;
    }
    return result;
}

}  // namespace wg
