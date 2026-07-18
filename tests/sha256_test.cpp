#include "sha256.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <unistd.h>

int main() {
    char path[] = "/tmp/nightwatch-sha256-test-XXXXXX";
    const int descriptor = mkstemp(path);
    if (descriptor < 0) {
        std::cerr << "mkstemp failed\n";
        return 1;
    }
    unlink(path);
    const std::string input = "abc";
    if (write(descriptor, input.data(), input.size()) !=
        static_cast<ssize_t>(input.size())) {
        close(descriptor);
        std::cerr << "test write failed\n";
        return 1;
    }
    const std::string expected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const std::string actual = sha256_fd(descriptor);
    close(descriptor);
    if (actual != expected) {
        std::cerr << "SHA-256 mismatch: " << actual << '\n';
        return 1;
    }
    std::cout << "SHA-256 test passed\n";
    return 0;
}
