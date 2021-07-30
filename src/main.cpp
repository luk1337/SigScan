#include "SigScan.h"
#include <boost/program_options.hpp>
#include <fcntl.h>
#include <iostream>
#include <sys/mman.h>
#include <sys/stat.h>

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

    auto fd = open(vm["file"].as<std::string>().c_str(), O_RDONLY);

    if (fd == -1) {
        perror("failed to open file");
        return -1;
    }

    struct stat st = {};
    fstat(fd, &st);

    auto mem = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if (mem == MAP_FAILED) {
        perror("failed to map file");
        return -1;
    }

    auto start_address = reinterpret_cast<uintptr_t>(mem);
    auto end_address = start_address + st.st_size;
    auto max = vm.count("max") ? std::make_optional(vm["max"].as<size_t>()) : std::nullopt;
    auto matches = SigScan::find(vm["pattern"].as<std::string>(), start_address, end_address, max);

    for (const auto& match : matches) {
        std::cout << "0x" << std::uppercase << std::hex << (match - start_address) << std::endl;
    }

    return 0;
}
