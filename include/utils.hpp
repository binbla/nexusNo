#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "crypto.hpp"

namespace wg {

// ============================================================================
// Logger - Simple Logging Utility
// ============================================================================

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
};

class Logger {
   public:
    /// Set global log level
    static void set_level(LogLevel level);

    /// Get current log level
    static LogLevel get_level();

    /// Log a debug message
    static void debug(const std::string& message);

    /// Log an info message
    static void info(const std::string& message);

    /// Log a warning message
    static void warn(const std::string& message);

    /// Log an error message
    static void error(const std::string& message);

    /// Log with format string
    static void log(LogLevel level, const char* fmt, ...);

   private:
    static LogLevel current_level_;
    static std::string timestamp_string();
    static std::string level_to_string(LogLevel level);
};

// ============================================================================
// Random - Secure Random Generation (Wrapper around Crypto)
// ============================================================================

class Random {
   public:
    /// Generate random bytes using secure random source
    /// @param size Number of bytes to generate
    /// @return Random bytes
    static std::vector<uint8_t> bytes(size_t size);

    /// Generate random uint32
    static uint32_t uint32();

    /// Generate random uint64
    static uint64_t uint64();

   private:
    Random() = delete;
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert bytes to hex string
std::string bytes_to_hex(const std::vector<uint8_t>& data);

/// Convert bytes array to hex string
template <size_t N>
std::string array_to_hex(const std::array<uint8_t, N>& data);

/// Returns theTAI64N timestamp for the current time. Out 12 bytes, the first 8
/// bytes being a big-endian integer of the number of seconds since 1970 TAI and
/// the last 4 bytes being a big-endian integer of the number of nanoseconds
/// from the beginning of that second.
inline Timestamp tai64n_timestamp() {
    std::array<uint8_t, 12> timestamp{};
    auto now = std::chrono::system_clock::now();
    auto epoch_seconds =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch())
            .count() +
        37;  // Add 37 seconds to convert from Unix time (UTC) to TAI
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           now.time_since_epoch())
                           .count() %
                       1000000000;

    // Write big-endian seconds
    for (int i = 0; i < 8; ++i) {
        timestamp[7 - i] = static_cast<uint8_t>(epoch_seconds & 0xFF);
        epoch_seconds >>= 8;
    }

    // Write big-endian nanoseconds
    for (int i = 0; i < 4; ++i) {
        timestamp[11 - i] = static_cast<uint8_t>(nanoseconds & 0xFF);
        nanoseconds >>= 8;
    }

    return timestamp;
};

// 字节序处理
inline void write_u32_le(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
}

inline void write_u64_le(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xff));
    }
}
inline uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= (static_cast<uint64_t>(p[i]) << (8 * i));
    }
    return v;
}
template <size_t N>
inline void write_bytes(std::vector<uint8_t>& out,
                        const std::array<uint8_t, N>& arr) {
    out.insert(out.end(), arr.begin(), arr.end());
}
template <size_t N>
inline std::array<uint8_t, N> read_array(const uint8_t* p) {
    std::array<uint8_t, N> out{};
    std::memcpy(out.data(), p, N);
    return out;
}
}  // namespace wg
