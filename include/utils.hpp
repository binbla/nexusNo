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
inline Timestamp tai64n_now() {
    Timestamp out{};

    auto now = std::chrono::system_clock::now();
    auto since_epoch = now.time_since_epoch();

    uint64_t sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count());

    uint32_t nsec = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch)
            .count() %
        1'000'000'000ULL);

    // 如果你有自己的 INITIATIONS_PER_SECOND，这里按 WG 一样降精度
    constexpr uint32_t INITIATIONS_PER_SECOND = 50;  // 示例
    constexpr uint32_t NSEC_PER_SEC = 1'000'000'000U;

    uint32_t quantum = 1;
    uint32_t target = NSEC_PER_SEC / INITIATIONS_PER_SECOND;
    while ((quantum << 1) <= target) {
        quantum <<= 1;
    }
    nsec = (nsec / quantum) * quantum;

    uint64_t tai64_sec = 0x400000000000000aULL + sec;

    for (int i = 0; i < 8; ++i) {
        out[7 - i] = static_cast<uint8_t>(tai64_sec & 0xff);
        tai64_sec >>= 8;
    }
    for (int i = 0; i < 4; ++i) {
        out[11 - i] = static_cast<uint8_t>(nsec & 0xff);
        nsec >>= 8;
    }

    return out;
}
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
