#include "SigScan.h"
#include <boost/program_options.hpp>
#include <iostream>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#elif (defined _WIN32 || defined _WIN64)
#include <windows.h>
#endif

std::pair<uintptr_t, uintptr_t> map_file(const char* path)
{
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
    auto fd = open(path, O_RDONLY);

    if (fd == -1) {
        perror("failed to open file");
        return {};
    }

    struct stat st = {};
    fstat(fd, &st);

    auto mem = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if (mem == MAP_FAILED) {
        perror("failed to map file");
        return {};
    }

    return { reinterpret_cast<uintptr_t>(mem), reinterpret_cast<uintptr_t>(mem) + st.st_size };
#elif (defined _WIN32 || defined _WIN64)
    auto handle = CreateFile(path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (handle == INVALID_HANDLE_VALUE) {
        std::cout << "failed to open file, error=" << GetLastError() << std::endl;
        return {};
    }

    LARGE_INTEGER file_size = {};

    if (!GetFileSizeEx(handle, &file_size)) {
        std::cout << "failed to get file size, error=" << GetLastError() << std::endl;
        return {};
    }

    auto file_mapping = CreateFileMapping(handle, nullptr, PAGE_READONLY, 0, file_size.QuadPart, nullptr);

    if (file_mapping == INVALID_HANDLE_VALUE) {
        std::cout << "failed to create file mapping, error=" << GetLastError() << std::endl;
        return {};
    }

    auto mem = MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, file_size.QuadPart);

    if (mem == nullptr) {
        std::cout << "failed to map view of file, error=" << GetLastError() << std::endl;
        return {};
    }

    return { reinterpret_cast<uintptr_t>(mem),
        reinterpret_cast<uintptr_t>(mem) + static_cast<ptrdiff_t>(file_size.QuadPart) };
#endif
}

int main(int argc, char** argv)
{
    namespace po = boost::program_options;

    po::options_description desc;
    desc.add_options()("help,h", "print usage message");
    desc.add_options()("file,f", po::value<std::string>()->required(), "path to file");
    desc.add_options()("pattern,p", po::value<std::string>()->required(), "IDA style code pattern");
    desc.add_options()("max,m", po::value<size_t>(), "maximum number of matches");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);

    if (argc <= 1 || vm.count("help")) {
        std::cout << desc;
        return 0;
    }

    po::notify(vm);

    auto [start_address, end_address] = map_file(vm["file"].as<std::string>().c_str());

    if (start_address == 0) {
        return 0;
    }

    auto max = vm.count("max") ? std::make_optional(vm["max"].as<size_t>()) : std::nullopt;
    auto matches = SigScan::find(vm["pattern"].as<std::string>(), start_address, end_address, max);

    for (const auto& match : matches) {
        std::cout << "0x" << std::uppercase << std::hex << (match - start_address) << std::endl;
    }

    return 0;
}
