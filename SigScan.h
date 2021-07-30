#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

class SigScan {
public:
    static std::vector<uintptr_t> find(const std::string_view& pattern, uintptr_t start_address, uintptr_t end_address,
        std::optional<size_t> max = {});

private:
    using Signature = std::vector<std::optional<uint8_t>>;

    static bool sig_match(const Signature& signature, uintptr_t address);
    static Signature parse_pattern(const std::string_view& pattern);
    static std::optional<uint8_t> get_byte(const std::string_view& str);
};
