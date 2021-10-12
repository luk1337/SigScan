#include "SigScan.h"
#include <cctype>
#include <cstring>
#include <fstream>

#pragma push_macro("NDEBUG")
#undef NDEBUG
#include <cassert>
#pragma pop_macro("NDEBUG")

std::vector<uintptr_t> SigScan::find(const std::string_view& pattern, uintptr_t start_address, uintptr_t end_address,
    std::optional<size_t> max, const std::function<void(uintptr_t)>& callback)
{
    assert(start_address < end_address);
    assert(!max.has_value() || *max > 0);

    auto sig = parse_pattern(pattern);
    assert(end_address - start_address >= sig.size());

    std::vector<uintptr_t> addresses;

    for (auto address = start_address; address <= end_address - sig.size(); ++address) {
        if (sig_match(sig, address)) {
            addresses.emplace_back(address);

            if (callback != nullptr) {
                callback(address);
            }

            if (max.has_value() && addresses.size() == max.value()) {
                break;
            }
        }
    }

    return addresses;
}

void SigScan::patch(const std::string& file, const std::vector<uintptr_t>& addresses, const std::string& bytes)
{
    auto data = parse_bytes(bytes);

    for (const auto& address : addresses) {
        memcpy(reinterpret_cast<void*>(address), data.data(), data.size());
    }
}

bool SigScan::sig_match(const Signature& signature, uintptr_t address)
{
    for (const auto& byte : signature) {
        if (byte.has_value() && *byte != *reinterpret_cast<uint8_t*>(address)) {
            return false;
        }
        ++address;
    }
    return true;
}

std::vector<char> SigScan::parse_bytes(const std::string_view& bytes)
{
    assert(!bytes.empty());

    std::vector<char> ret;

    size_t pos = 0;
    size_t found;

    do {
        found = bytes.find_first_of(' ', pos);
        auto byte = get_byte(bytes.substr(pos, found - pos));
        assert(byte.has_value());
        ret.emplace_back(*byte);
        pos = found + 1;
    } while (found != std::string_view::npos);

    return ret;
}

SigScan::Signature SigScan::parse_pattern(const std::string_view& pattern)
{
    assert(!pattern.empty());

    Signature ret;

    size_t pos = 0;
    size_t found;

    do {
        found = pattern.find_first_of(' ', pos);
        ret.emplace_back(get_byte(pattern.substr(pos, found - pos)));
        pos = found + 1;
    } while (found != std::string_view::npos);

    return ret;
}

std::optional<uint8_t> SigScan::get_byte(const std::string_view& str)
{
    assert(str.length() == 1 || str.length() == 2);

    auto first = str[0];
    assert(first == '?' || isxdigit(first));

    auto second = str.length() == 2 ? str[1] : '?';
    assert(second == '?' || isxdigit(second));

    assert(!(first == '?' && second != '?') && !(second == '?' && first != '?'));

    constexpr auto get_bits = [](char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        return (c & (~0x20)) - 'A' + 0xA;
    };

    return first == '?' ? std::nullopt : std::make_optional(get_bits(first) << 4 | get_bits(second));
}