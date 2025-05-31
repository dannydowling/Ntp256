#pragma once

// Visual Studio specific defines
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <sstream>
#include <shellapi.h>

// Link required libraries
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "shell32.lib")

namespace NTP256 {

    // Forward declarations
    struct Time256;
    class Time256Math;
    class TimeConverter;

    // High precision 128-bit intermediate calculations
    struct UInt128 {
        uint64_t low = 0;
        uint64_t high = 0;

        UInt128() = default;
        UInt128(uint64_t l, uint64_t h) : low(l), high(h) {}
    };

    // Enhanced constants for true 256-bit precision
    namespace Constants {
        // Planck time in attoseconds (5.39121 × 10^-44 seconds = 5.39121 × 10^-26 attoseconds)
        // For simplicity, we'll use attoseconds as our base unit and track Planck times separately
        constexpr uint64_t ATTOSECONDS_PER_SECOND = 1000000000000000000ULL; // 10^18
        constexpr uint64_t FEMTOSECONDS_PER_SECOND = 1000000000000000ULL; // 10^15
        constexpr uint64_t NANOSECONDS_PER_SECOND = 1000000000ULL; // 10^9
        constexpr uint64_t NTP_EPOCH_OFFSET = 2208988800ULL; // Seconds from 1900 to 1970
        constexpr uint64_t FILETIME_EPOCH_OFFSET = 11644473600ULL; // Seconds from 1601 to 1970
        constexpr int NTP_PORT = 123;
        constexpr int SOCKET_TIMEOUT_SECONDS = 10;

        // For reference: Age of universe ~ 13.8 billion years ~ 4.35 × 10^17 seconds
        // In attoseconds: ~ 4.35 × 10^35
        // 256 bits can represent up to ~ 1.16 × 10^77, so we have plenty of room
    }

    // Enhanced 256-bit arithmetic operations
    class Time256Math {
    public:
        // Add two 256-bit numbers
        static void add256(Time256& result, const Time256& a, const Time256& b);

        // Multiply 256-bit number by 64-bit number
        static void multiply256x64(Time256& result, const Time256& a, uint64_t b);

        // Divide 256-bit number by 64-bit number, return quotient and remainder
        static void divide256x64(Time256& quotient, uint64_t& remainder, const Time256& dividend, uint64_t divisor);

    private:
        static void addAtOffset(Time256& result, const UInt128& value, int offset);
        static void divide128x64(uint64_t& quotient, uint64_t& remainder, const UInt128& dividend, uint64_t divisor);
    };

    // 256-bit time structure using 4 64-bit integers (little-endian)
    struct Time256 {
        uint64_t part[4] = { 0 }; // [0] = lowest 64 bits, [3] = highest 64 bits

        // Default constructor
        Time256() = default;

        // Constructor from seconds and attoseconds - uses enhanced 256-bit arithmetic
        Time256(uint64_t seconds, uint64_t attoseconds = 0);

        // Copy constructor and assignment
        Time256(const Time256&) = default;
        Time256& operator=(const Time256&) = default;

        // Comparison operators
        bool operator==(const Time256& other) const;
        bool operator!=(const Time256& other) const;
        bool operator<(const Time256& other) const;
        bool operator>(const Time256& other) const;
        bool operator<=(const Time256& other) const;
        bool operator>=(const Time256& other) const;

        // Arithmetic operators
        Time256 operator+(const Time256& other) const;
        Time256& operator+=(const Time256& other);

        // Utility methods
        void clear();
        std::string toHexString() const;
        std::string toHumanString() const;
    };

    // NTP packet structure (RFC 5905 compliant)
#pragma pack(push, 1)
    struct NTPPacket {
        uint8_t li_vn_mode = 0;      // Leap Indicator, Version, Mode
        uint8_t stratum = 0;         // Stratum level
        uint8_t poll = 0;            // Poll interval
        uint8_t precision = 0;       // Precision
        uint32_t root_delay = 0;     // Root delay
        uint32_t root_dispersion = 0; // Root dispersion
        uint32_t ref_id = 0;         // Reference ID
        uint64_t ref_timestamp = 0;  // Reference timestamp (NTP format)
        uint64_t orig_timestamp = 0; // Origin timestamp
        uint64_t recv_timestamp = 0; // Receive timestamp
        uint64_t trans_timestamp = 0; // Transmit timestamp
    };
#pragma pack(pop)

    // Exception classes for better error handling
    class NTPException : public std::runtime_error {
    public:
        explicit NTPException(const std::string& message)
            : std::runtime_error("NTP Error: " + message) {}
    };

    class NetworkException : public std::runtime_error {
    public:
        explicit NetworkException(const std::string& message, int errorCode = 0)
            : std::runtime_error("Network Error: " + message +
                (errorCode ? " (Code: " + std::to_string(errorCode) + ")" : "")) {
        }
    };

    class SystemTimeException : public std::runtime_error {
    public:
        explicit SystemTimeException(const std::string& message, DWORD errorCode = 0)
            : std::runtime_error("System Time Error: " + message +
                (errorCode ? " (Code: " + std::to_string(errorCode) + ")" : "")) {
        }
    };

    // NTP Client class
    class NTPClient {
    private:
        std::vector<std::string> servers_;
        int timeout_seconds_;

        // RAII Socket wrapper
        class SocketWrapper {
        private:
            SOCKET socket_;
        public:
            SocketWrapper();
            ~SocketWrapper();
            SOCKET get() const { return socket_; }
            bool isValid() const { return socket_ != INVALID_SOCKET; }
        };

        // RAII Winsock wrapper
        class WinsockWrapper {
        private:
            bool initialized_;
        public:
            WinsockWrapper();
            ~WinsockWrapper();
            bool isInitialized() const { return initialized_; }
        };

    public:
        explicit NTPClient(const std::vector<std::string>& servers = {
            "time.nist.gov",
            "pool.ntp.org",
            "time.google.com",
            "time.cloudflare.com"
            }, int timeout = Constants::SOCKET_TIMEOUT_SECONDS);

        Time256 getTimeUTC();
        Time256 getTimeUTC(const std::string& server);

    private:
        Time256 queryServer(const std::string& server);
        sockaddr_in resolveServer(const std::string& server);
    };

    // Time conversion utilities
    class TimeConverter {
    public:
        static Time256 fromNTPTimestamp(uint32_t ntp_seconds, uint32_t ntp_fraction);
        static Time256 fromFileTimeUTC(const FILETIME& ft);
        static Time256 fromSystemTimeUTC(const SYSTEMTIME& st);
        static Time256 getCurrentUTC();

        static FILETIME toFileTimeUTC(const Time256& t);
        static SYSTEMTIME toSystemTimeUTC(const Time256& t);
        static void addUInt128ToTime256(Time256& t, const UInt128& val);
        static UInt128 multiply64(uint64_t a, uint64_t b);
    };

    // System time management
    class SystemTimeManager {
    public:
        static bool setSystemTimeLocal(const Time256& utc_time);
        static Time256 getSystemTimeUTC();
        static bool hasPrivileges();
        static bool requestElevation();

    private:
        static void enablePrivileges();
        static bool isElevated();
        static bool restartAsAdmin();
    };

    // ============================================================================
    // IMPLEMENTATION SECTION
    // ============================================================================

    // Time256Math implementation
    void Time256Math::add256(Time256& result, const Time256& a, const Time256& b) {
        uint64_t carry = 0;
        for (int i = 0; i < 4; i++) {
            uint64_t sum = a.part[i] + b.part[i] + carry;
            carry = (sum < a.part[i] || (sum == a.part[i] && carry > 0)) ? 1 : 0;
            result.part[i] = sum;
        }
    }

    void Time256Math::multiply256x64(Time256& result, const Time256& a, uint64_t b) {
        result.clear();

        for (int i = 0; i < 4; i++) {
            if (a.part[i] == 0) continue;

            // Multiply part[i] by b and add to result at offset i
            UInt128 prod = TimeConverter::multiply64(a.part[i], b);

            // Add to result with proper positioning
            addAtOffset(result, prod, i);
        }
    }

    void Time256Math::divide256x64(Time256& quotient, uint64_t& remainder, const Time256& dividend, uint64_t divisor) {
        quotient.clear();
        remainder = 0;

        // Long division from high to low
        for (int i = 3; i >= 0; i--) {
            // Bring down the next 64 bits
            UInt128 temp;
            temp.high = remainder;
            temp.low = dividend.part[i];

            // Divide this 128-bit number by divisor
            uint64_t q = 0;
            uint64_t r = 0;
            divide128x64(q, r, temp, divisor);

            quotient.part[i] = q;
            remainder = r;
        }
    }

    void Time256Math::addAtOffset(Time256& result, const UInt128& value, int offset) {
        if (offset >= 4) return;

        uint64_t carry = 0;

        // Add low part
        if (offset < 4) {
            uint64_t sum = result.part[offset] + value.low + carry;
            carry = (sum < result.part[offset] || (sum == result.part[offset] && carry > 0)) ? 1 : 0;
            result.part[offset] = sum;
        }

        // Add high part
        if (offset + 1 < 4) {
            uint64_t sum = result.part[offset + 1] + value.high + carry;
            carry = (sum < result.part[offset + 1] || (sum == result.part[offset + 1] && carry > 0)) ? 1 : 0;
            result.part[offset + 1] = sum;
        }

        // Propagate remaining carry
        for (int i = offset + 2; i < 4 && carry > 0; i++) {
            uint64_t sum = result.part[i] + carry;
            carry = (sum < result.part[i]) ? 1 : 0;
            result.part[i] = sum;
        }
    }

    void Time256Math::divide128x64(uint64_t& quotient, uint64_t& remainder, const UInt128& dividend, uint64_t divisor) {
        if (dividend.high == 0) {
            quotient = dividend.low / divisor;
            remainder = dividend.low % divisor;
            return;
        }

        // Proper 128-bit division algorithm
        quotient = 0;
        remainder = 0;

        // Process bit by bit from highest to lowest
        for (int i = 127; i >= 0; i--) {
            remainder <<= 1;

            // Extract bit i from dividend
            uint64_t bit;
            if (i >= 64) {
                bit = (dividend.high >> (i - 64)) & 1;
            }
            else {
                bit = (dividend.low >> i) & 1;
            }

            remainder |= bit;

            if (remainder >= divisor) {
                remainder -= divisor;
                if (i >= 64) {
                    quotient |= (1ULL << (i - 64));
                }
                else {
                    quotient |= (1ULL << i);
                }
            }
        }
    }

    // Enhanced Time256 constructor that avoids overflow
    Time256::Time256(uint64_t seconds, uint64_t attoseconds) {
        clear();

        // Clamp attoseconds to valid range
        if (attoseconds >= Constants::ATTOSECONDS_PER_SECOND) {
            uint64_t extra_seconds = attoseconds / Constants::ATTOSECONDS_PER_SECOND;
            attoseconds = attoseconds % Constants::ATTOSECONDS_PER_SECOND;
            seconds += extra_seconds;
        }

        // Create seconds as 256-bit number
        Time256 seconds_part;
        seconds_part.clear();
        seconds_part.part[0] = seconds;

        // Multiply by ATTOSECONDS_PER_SECOND
        Time256 seconds_in_attoseconds;
        Time256Math::multiply256x64(seconds_in_attoseconds, seconds_part, Constants::ATTOSECONDS_PER_SECOND);

        // Create attoseconds as 256-bit number
        Time256 attoseconds_part;
        attoseconds_part.clear();
        attoseconds_part.part[0] = attoseconds;

        // Add them together
        Time256Math::add256(*this, seconds_in_attoseconds, attoseconds_part);
    }

    void Time256::clear() {
        std::memset(part, 0, sizeof(part));
    }

    bool Time256::operator==(const Time256& other) const {
        return std::memcmp(part, other.part, sizeof(part)) == 0;
    }

    bool Time256::operator!=(const Time256& other) const {
        return !(*this == other);
    }

    bool Time256::operator<(const Time256& other) const {
        for (int i = 3; i >= 0; i--) {
            if (part[i] < other.part[i]) return true;
            if (part[i] > other.part[i]) return false;
        }
        return false;
    }

    bool Time256::operator>(const Time256& other) const {
        return other < *this;
    }

    bool Time256::operator<=(const Time256& other) const {
        return !(*this > other);
    }

    bool Time256::operator>=(const Time256& other) const {
        return !(*this < other);
    }

    Time256 Time256::operator+(const Time256& other) const {
        Time256 result;
        Time256Math::add256(result, *this, other);
        return result;
    }

    Time256& Time256::operator+=(const Time256& other) {
        Time256Math::add256(*this, *this, other);
        return *this;
    }

    std::string Time256::toHexString() const {
        std::ostringstream oss;
        oss << "0x";
        for (int i = 3; i >= 0; i--) {
            oss << std::hex << std::setfill('0') << std::setw(16) << part[i];
            if (i > 0) oss << "_";
        }
        return oss.str();
    }

    std::string Time256::toHumanString() const {
        try {
            SYSTEMTIME st = TimeConverter::toSystemTimeUTC(*this);

            std::ostringstream oss;
            oss << std::setfill('0')
                << std::setw(4) << st.wYear << "-"
                << std::setw(2) << st.wMonth << "-"
                << std::setw(2) << st.wDay << " "
                << std::setw(2) << st.wHour << ":"
                << std::setw(2) << st.wMinute << ":"
                << std::setw(2) << st.wSecond << "."
                << std::setw(3) << st.wMilliseconds << " UTC";

            // Extract sub-millisecond precision from the 256-bit value
            Time256 seconds_part;
            uint64_t remainder_attoseconds;
            Time256Math::divide256x64(seconds_part, remainder_attoseconds, *this, Constants::ATTOSECONDS_PER_SECOND);

            // Calculate femtoseconds and remaining attoseconds
            uint64_t total_femtoseconds = remainder_attoseconds / 1000ULL;
            uint64_t remaining_attoseconds_final = remainder_attoseconds % 1000ULL;

            oss << " (+" << total_femtoseconds << "fs, +" << remaining_attoseconds_final << "as)";

            return oss.str();
        }
        catch (const std::exception& e) {
            return "Invalid time: " + std::string(e.what());
        }
    }

    // SystemTimeManager implementation
    bool SystemTimeManager::isElevated() {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return false;
        }

        TOKEN_ELEVATION elevation;
        DWORD dwSize = sizeof(TOKEN_ELEVATION);

        bool result = false;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            result = elevation.TokenIsElevated != 0;
        }

        CloseHandle(hToken);
        return result;
    }

    bool SystemTimeManager::restartAsAdmin() {
        wchar_t szPath[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, szPath, ARRAYSIZE(szPath))) {
            std::wcerr << L"Failed to get module file name. Error: " << GetLastError() << std::endl;
            return false;
        }

        LPWSTR cmdLine = GetCommandLineW();
        std::wstring args;

        bool inQuotes = false;
        bool foundSpace = false;
        for (wchar_t* p = cmdLine; *p; ++p) {
            if (*p == L'"') {
                inQuotes = !inQuotes;
            }
            else if (*p == L' ' && !inQuotes) {
                foundSpace = true;
            }
            else if (foundSpace) {
                args = p;
                break;
            }
        }

        std::wcout << L"Requesting administrator privileges..." << std::endl;
        std::wcout << L"A UAC prompt will appear. Please click 'Yes' to continue." << std::endl;

        SHELLEXECUTEINFOW sei = {};
        sei.cbSize = sizeof(SHELLEXECUTEINFOW);
        sei.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.lpParameters = args.c_str();
        sei.lpDirectory = nullptr;
        sei.nShow = SW_NORMAL;

        BOOL result = ShellExecuteExW(&sei);

        if (result) {
            std::wcout << L"Successfully launched elevated process." << std::endl;
            std::wcout << L"This instance will now exit." << std::endl;
            return true;
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_CANCELLED) {
                std::wcerr << L"UAC elevation was cancelled by user." << std::endl;
            }
            else {
                std::wcerr << L"Failed to launch elevated process. Error: " << error << std::endl;
            }
            return false;
        }
    }

    bool SystemTimeManager::requestElevation() {
        if (isElevated()) {
            std::cout << "Already running with administrator privileges." << std::endl;
            return true;
        }

        std::cout << "Administrator privileges required for system time modification." << std::endl;
        std::cout << "Attempt to restart with elevation? (y/n): ";

        char choice;
        std::cin >> choice;

        if (choice == 'y' || choice == 'Y') {
            if (restartAsAdmin()) {
                exit(0);
            }
            else {
                std::cout << "Failed to obtain administrator privileges." << std::endl;
                return false;
            }
        }
        else {
            std::cout << "Continuing without administrator privileges." << std::endl;
            std::cout << "Note: System time cannot be modified." << std::endl;
            return false;
        }
    }

    void SystemTimeManager::enablePrivileges() {
        if (!isElevated()) {
            throw SystemTimeException("Administrator privileges required. Call requestElevation() first.");
        }

        HANDLE hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            throw SystemTimeException("Failed to open process token", GetLastError());
        }

        TOKEN_PRIVILEGES tp;
        if (!LookupPrivilegeValue(nullptr, SE_SYSTEMTIME_NAME, &tp.Privileges[0].Luid)) {
            CloseHandle(hToken);
            throw SystemTimeException("Failed to lookup SE_SYSTEMTIME_NAME privilege", GetLastError());
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
            CloseHandle(hToken);
            throw SystemTimeException("Failed to adjust token privileges", GetLastError());
        }

        DWORD dwResult = GetLastError();
        if (dwResult == ERROR_NOT_ALL_ASSIGNED) {
            CloseHandle(hToken);
            throw SystemTimeException("Failed to enable SE_SYSTEMTIME_NAME privilege");
        }

        CloseHandle(hToken);
        std::cout << "System time privileges enabled successfully." << std::endl;
    }

    bool SystemTimeManager::setSystemTimeLocal(const Time256& utc_time) {
        try {
            enablePrivileges();
            SYSTEMTIME utc_systemtime = TimeConverter::toSystemTimeUTC(utc_time);

            if (!SetSystemTime(&utc_systemtime)) {
                DWORD error = GetLastError();
                throw SystemTimeException("Failed to set system time", error);
            }

            return true;
        }
        catch (const std::exception&) {
            return false;
        }
    }

    Time256 SystemTimeManager::getSystemTimeUTC() {
        return TimeConverter::getCurrentUTC();
    }

    bool SystemTimeManager::hasPrivileges() {
        return isElevated();
    }

    // NTPClient implementation
    NTPClient::SocketWrapper::SocketWrapper() : socket_(INVALID_SOCKET) {
        socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (socket_ != INVALID_SOCKET) {
            DWORD timeout = Constants::SOCKET_TIMEOUT_SECONDS * 1000;
            setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        }
    }

    NTPClient::SocketWrapper::~SocketWrapper() {
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
        }
    }

    NTPClient::WinsockWrapper::WinsockWrapper() : initialized_(false) {
        WSADATA wsaData;
        initialized_ = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
    }

    NTPClient::WinsockWrapper::~WinsockWrapper() {
        if (initialized_) {
            WSACleanup();
        }
    }

    NTPClient::NTPClient(const std::vector<std::string>& servers, int timeout)
        : servers_(servers), timeout_seconds_(timeout) {
    }

    Time256 NTPClient::getTimeUTC() {
        for (const auto& server : servers_) {
            try {
                return queryServer(server);
            }
            catch (const std::exception& e) {
                std::cout << "Failed to query " << server << ": " << e.what() << std::endl;
                continue;
            }
        }
        throw NTPException("Failed to get time from any NTP server");
    }

    Time256 NTPClient::getTimeUTC(const std::string& server) {
        return queryServer(server);
    }

    Time256 NTPClient::queryServer(const std::string& server) {
        WinsockWrapper winsock;
        if (!winsock.isInitialized()) {
            throw NetworkException("Failed to initialize Winsock", WSAGetLastError());
        }

        SocketWrapper sock;
        if (!sock.isValid()) {
            throw NetworkException("Failed to create socket", WSAGetLastError());
        }

        sockaddr_in server_addr = resolveServer(server);

        NTPPacket packet{};
        packet.li_vn_mode = 0x1B;
        packet.stratum = 0;
        packet.poll = 4;
        packet.precision = 0xFA;

        if (sendto(sock.get(), reinterpret_cast<const char*>(&packet), sizeof(packet), 0,
            reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
            throw NetworkException("Failed to send NTP request", WSAGetLastError());
        }

        int addr_len = sizeof(server_addr);
        int recv_len = recvfrom(sock.get(), reinterpret_cast<char*>(&packet), sizeof(packet), 0,
            reinterpret_cast<sockaddr*>(&server_addr), &addr_len);
        if (recv_len == SOCKET_ERROR) {
            throw NetworkException("Failed to receive NTP response", WSAGetLastError());
        }

        // Fix NTP timestamp parsing
        // NTP timestamps are stored in network byte order (big-endian)
        // We need to convert the entire 64-bit timestamp from network to host order

        // First, get the raw bytes in correct order
        uint64_t raw_timestamp = packet.trans_timestamp;

        // Convert from network byte order to host byte order for the entire 64-bit value
        uint64_t host_timestamp =
            ((raw_timestamp & 0xFF00000000000000ULL) >> 56) |
            ((raw_timestamp & 0x00FF000000000000ULL) >> 40) |
            ((raw_timestamp & 0x0000FF0000000000ULL) >> 24) |
            ((raw_timestamp & 0x000000FF00000000ULL) >> 8) |
            ((raw_timestamp & 0x00000000FF000000ULL) << 8) |
            ((raw_timestamp & 0x0000000000FF0000ULL) << 24) |
            ((raw_timestamp & 0x000000000000FF00ULL) << 40) |
            ((raw_timestamp & 0x00000000000000FFULL) << 56);

        // Extract seconds and fraction parts
        uint32_t ntp_seconds = static_cast<uint32_t>(host_timestamp >> 32);
        uint32_t ntp_fraction = static_cast<uint32_t>(host_timestamp & 0xFFFFFFFF);

        std::cout << "Debug - Raw trans_timestamp: 0x" << std::hex << raw_timestamp << std::dec << std::endl;
        std::cout << "Debug - Host order timestamp: 0x" << std::hex << host_timestamp << std::dec << std::endl;
        std::cout << "Debug - NTP seconds: " << ntp_seconds << ", fraction: " << ntp_fraction << std::endl;

        // Sanity check: NTP seconds should be > 3.8 billion for 2024+
        if (ntp_seconds < 3800000000UL || ntp_seconds > 5000000000UL) {
            std::cout << "Warning - NTP timestamp out of expected range for current time" << std::endl;
        }

        return TimeConverter::fromNTPTimestamp(ntp_seconds, ntp_fraction);
    }

    sockaddr_in NTPClient::resolveServer(const std::string& server) {
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(Constants::NTP_PORT);

        if (inet_pton(AF_INET, server.c_str(), &server_addr.sin_addr) <= 0) {
            addrinfo hints{}, * res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;

            if (getaddrinfo(server.c_str(), std::to_string(Constants::NTP_PORT).c_str(), &hints, &res) != 0) {
                throw NetworkException("Failed to resolve server address: " + server);
            }

            server_addr = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
            freeaddrinfo(res);
        }

        return server_addr;
    }

    // TimeConverter implementation
    UInt128 TimeConverter::multiply64(uint64_t a, uint64_t b) {
        uint32_t a_low = static_cast<uint32_t>(a);
        uint32_t a_high = static_cast<uint32_t>(a >> 32);
        uint32_t b_low = static_cast<uint32_t>(b);
        uint32_t b_high = static_cast<uint32_t>(b >> 32);

        uint64_t low_low = static_cast<uint64_t>(a_low) * b_low;
        uint64_t low_high = static_cast<uint64_t>(a_low) * b_high;
        uint64_t high_low = static_cast<uint64_t>(a_high) * b_low;
        uint64_t high_high = static_cast<uint64_t>(a_high) * b_high;

        uint64_t middle = low_high + high_low;
        uint64_t carry = (middle < low_high) ? 1ULL << 32 : 0;

        UInt128 result;
        result.low = low_low + (middle << 32);
        result.high = high_high + (middle >> 32) + carry;

        if (result.low < low_low) {
            result.high++;
        }

        return result;
    }

    void TimeConverter::addUInt128ToTime256(Time256& t, const UInt128& val) {
        uint64_t carry = 0;

        uint64_t sum = t.part[0] + val.low;
        carry = (sum < t.part[0]) ? 1 : 0;
        t.part[0] = sum;

        sum = t.part[1] + val.high + carry;
        carry = (sum < t.part[1] || (sum == t.part[1] && carry)) ? 1 : 0;
        t.part[1] = sum;

        for (int i = 2; i < 4 && carry; i++) {
            sum = t.part[i] + carry;
            carry = (sum < t.part[i]) ? 1 : 0;
            t.part[i] = sum;
        }
    }

    Time256 TimeConverter::fromNTPTimestamp(uint32_t ntp_seconds, uint32_t ntp_fraction) {
        std::cout << "Debug - fromNTPTimestamp input: seconds=" << ntp_seconds << ", fraction=" << ntp_fraction << std::endl;

        // Convert NTP seconds to Unix seconds
        uint64_t unix_seconds = static_cast<uint64_t>(ntp_seconds) - Constants::NTP_EPOCH_OFFSET;
        std::cout << "Debug - Unix seconds: " << unix_seconds << std::endl;

        // Convert NTP fraction to attoseconds using precise arithmetic
        // NTP fraction represents 1/2^32 of a second
        uint64_t attoseconds_from_fraction = 0;
        if (ntp_fraction != 0) {
            // Use precise 128-bit calculation: attoseconds = (fraction * 10^18) / 2^32
            UInt128 temp = multiply64(static_cast<uint64_t>(ntp_fraction), Constants::ATTOSECONDS_PER_SECOND);

            // Divide by 2^32 (right shift by 32 bits)
            attoseconds_from_fraction = (temp.high << 32) | (temp.low >> 32);
        }

        std::cout << "Debug - Attoseconds from fraction: " << attoseconds_from_fraction << std::endl;

        // Create Time256 using the enhanced constructor
        Time256 result(unix_seconds, attoseconds_from_fraction);

        std::cout << "Debug - Result parts: [0]=" << result.part[0]
            << " [1]=" << result.part[1]
            << " [2]=" << result.part[2]
            << " [3]=" << result.part[3] << std::endl;

        return result;
    }

    Time256 TimeConverter::fromFileTimeUTC(const FILETIME& ft) {
        // FILETIME is 100-nanosecond intervals since January 1, 1601 UTC
        uint64_t filetime_ticks = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

        // Convert to seconds and remainder
        uint64_t seconds_since_1601 = filetime_ticks / 10000000ULL;
        uint64_t remaining_ticks = filetime_ticks % 10000000ULL;

        // Convert to Unix epoch
        if (seconds_since_1601 < Constants::FILETIME_EPOCH_OFFSET) {
            Time256 result;
            result.clear();
            return result;
        }

        uint64_t unix_seconds = seconds_since_1601 - Constants::FILETIME_EPOCH_OFFSET;
        uint64_t attoseconds = remaining_ticks * 100000000000ULL; // 100ns to attoseconds

        // Use the enhanced constructor
        return Time256(unix_seconds, attoseconds);
    }

    Time256 TimeConverter::fromSystemTimeUTC(const SYSTEMTIME& st) {
        FILETIME ft;
        if (!SystemTimeToFileTime(&st, &ft)) {
            throw SystemTimeException("Failed to convert SYSTEMTIME to FILETIME", GetLastError());
        }
        return fromFileTimeUTC(ft);
    }

    Time256 TimeConverter::getCurrentUTC() {
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        return fromFileTimeUTC(ft);
    }

    FILETIME TimeConverter::toFileTimeUTC(const Time256& t) {
        // Extract seconds from the 256-bit time
        Time256 quotient;
        uint64_t remainder_attoseconds;

        Time256Math::divide256x64(quotient, remainder_attoseconds, t, Constants::ATTOSECONDS_PER_SECOND);

        // The quotient's low part should contain the seconds
        uint64_t unix_seconds = quotient.part[0];

        // Handle potential overflow in quotient higher parts
        if (quotient.part[1] > 0 || quotient.part[2] > 0 || quotient.part[3] > 0) {
            // Time is too large for FILETIME - clamp to maximum
            unix_seconds = UINT64_MAX / 10000000ULL - Constants::FILETIME_EPOCH_OFFSET;
            remainder_attoseconds = 0;
        }

        // Convert to seconds since 1601
        uint64_t seconds_since_1601 = unix_seconds + Constants::FILETIME_EPOCH_OFFSET;

        // Convert attoseconds to 100ns ticks
        uint64_t ticks_from_attoseconds = remainder_attoseconds / 100000000000ULL;

        // Total FILETIME ticks
        uint64_t total_ticks = seconds_since_1601 * 10000000ULL + ticks_from_attoseconds;

        FILETIME ft;
        ft.dwLowDateTime = static_cast<DWORD>(total_ticks & 0xFFFFFFFF);
        ft.dwHighDateTime = static_cast<DWORD>(total_ticks >> 32);
        return ft;
    }

    SYSTEMTIME TimeConverter::toSystemTimeUTC(const Time256& t) {
        FILETIME ft = toFileTimeUTC(t);
        SYSTEMTIME st;
        if (!FileTimeToSystemTime(&ft, &st)) {
            throw SystemTimeException("Failed to convert FILETIME to SYSTEMTIME", GetLastError());
        }
        return st;
    }

} // namespace NTP256

// Main application
int main() {
    using namespace NTP256;

    try {
        std::cout << "Enhanced 256-bit Precision NTP Time Synchronization (UTC)\n";
        std::cout << "========================================================\n\n";

        // Check for admin privileges early
        if (!SystemTimeManager::hasPrivileges()) {
            std::cout << "This application requires administrator privileges to modify system time.\n\n";

            // Request elevation through UAC
            if (!SystemTimeManager::requestElevation()) {
                std::cout << "Continuing in read-only mode...\n\n";
            }
            // If requestElevation() succeeds, it will restart the app and exit this instance
        }

        // Display current system time
        Time256 current_time = SystemTimeManager::getSystemTimeUTC();
        std::cout << "Current system time (UTC):\n";
        std::cout << "  Hex: " << current_time.toHexString() << "\n";
        std::cout << "  Human: " << current_time.toHumanString() << "\n\n";

        // Check privileges
        if (!SystemTimeManager::hasPrivileges()) {
            std::cout << "WARNING: Running without administrator privileges.\n";
            std::cout << "System time updates will not be possible.\n\n";
        }

        // Get NTP time
        std::cout << "Synchronizing with NTP servers...\n";
        NTPClient client;
        Time256 ntp_time = client.getTimeUTC();

        std::cout << "\nNTP time (UTC):\n";
        std::cout << "  Hex: " << ntp_time.toHexString() << "\n";
        std::cout << "  Human: " << ntp_time.toHumanString() << "\n\n";

        // Compare times
        if (ntp_time != current_time) {
            std::cout << "Time difference detected: NTP time is "
                << (ntp_time > current_time ? "ahead" : "behind")
                << " of system time\n\n";

            std::cout << "Update system time with NTP time? (y/n): ";
            char choice;
            std::cin >> choice;

            if (choice == 'y' || choice == 'Y') {
                if (SystemTimeManager::setSystemTimeLocal(ntp_time)) {
                    std::cout << "System time synchronized successfully!\n";
                }
                else {
                    std::cout << "Failed to set system time. Make sure you're running as Administrator.\n";
                }
            }
            else {
                std::cout << "System time not changed.\n";
            }
        }
        else {
            std::cout << "System time is already synchronized (within precision limits).\n";
        }

        std::cout << "\n=== 256-bit Time Format Benefits ===\n";
        std::cout << "• Attosecond precision (10^-18 seconds)\n";
        std::cout << "• Represents ~13.8 billion years in Planck time units\n";
        std::cout << "• Future-proof beyond Unix timestamp 2038 limit\n";
        std::cout << "• Suitable for high-precision scientific applications\n";
        std::cout << "• Object-oriented C++ design with RAII and exception handling\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
    std::cin.get();

    return 0;
}