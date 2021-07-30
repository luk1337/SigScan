#include "SigScan.h"
#include <cctype>

#pragma push_macro("NDEBUG")
#undef NDEBUG
#include <cassert>
#pragma pop_macro("NDEBUG")

std::vector<uintptr_t> SigScan::find(
    const std::string_view& pattern, uintptr_t start_address, uintptr_t end_address, std::optional<size_t> max)
{
    assert(start_address < end_address);

    auto sig = parse_pattern(pattern);
    std::vector<uintptr_t> addresses;

    for (auto address = start_address; address <= end_address - sig.size(); ++address) {
        if (sig_match(sig, address)) {
            addresses.emplace_back(address);

            if (max.has_value() && addresses.size() == max.value()) {
                break;
            }
        }
    }

    return addresses;
}

bool SigScan::sig_match(const Signature& signature, uintptr_t address)
{
    for (auto& byte : signature) {
        if (byte.has_value() && *byte != *reinterpret_cast<uint8_t*>(address)) {
            return false;
        }
        ++address;
    }
    return true;
}

SigScan::Signature SigScan::parse_pattern(const std::string_view& pattern)
{
    assert(!pattern.empty());

    Signature ret;

    for (size_t i = 0; i < pattern.size(); i += 3) {
        ret.emplace_back(get_byte(pattern.substr(i, 2)));
    }

    return ret;
}

std::optional<uint8_t> SigScan::get_byte(const std::string_view& str)
{
    assert(str.length() == 2);

    constexpr auto is_hex_or_any = [](char c) { return c == '?' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); };

    auto first = static_cast<char>(std::tolower(str[0]));
    assert(is_hex_or_any(first));

    auto second = static_cast<char>(std::tolower(str[1]));
    assert(is_hex_or_any(second));

    if (first == '?') {
        assert(second == '?');
        return {};
    }

    if (second == '?') {
        assert(first == '?');
        return {};
    }

    constexpr auto get_bits = [](char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        return (c & (~0x20)) - 'A' + 0xA;
    };

    return get_bits(first) << 4 | get_bits(second);
}