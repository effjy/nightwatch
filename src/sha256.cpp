#include "sha256.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace {
constexpr std::array<std::uint32_t, 64> constants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
    0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
    0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
    0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

std::uint32_t rotate_right(std::uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32U - count));
}

class Sha256 {
public:
    void update(const unsigned char* data, std::size_t length) {
        total_bytes_ += length;
        while (length > 0) {
            const std::size_t available = block_.size() - block_size_;
            const std::size_t amount = length < available ? length : available;
            std::memcpy(block_.data() + block_size_, data, amount);
            block_size_ += amount;
            data += amount;
            length -= amount;
            if (block_size_ == block_.size()) {
                transform(block_.data());
                block_size_ = 0;
            }
        }
    }

    std::array<unsigned char, 32> finish() {
        const std::uint64_t total_bits = total_bytes_ * 8U;
        block_[block_size_++] = 0x80U;
        if (block_size_ > 56) {
            while (block_size_ < 64) {
                block_[block_size_++] = 0;
            }
            transform(block_.data());
            block_size_ = 0;
        }
        while (block_size_ < 56) {
            block_[block_size_++] = 0;
        }
        for (unsigned int index = 0; index < 8; ++index) {
            block_[63U - index] = static_cast<unsigned char>(total_bits >> (index * 8U));
        }
        transform(block_.data());

        std::array<unsigned char, 32> digest{};
        for (std::size_t index = 0; index < state_.size(); ++index) {
            digest[index * 4] = static_cast<unsigned char>(state_[index] >> 24U);
            digest[index * 4 + 1] = static_cast<unsigned char>(state_[index] >> 16U);
            digest[index * 4 + 2] = static_cast<unsigned char>(state_[index] >> 8U);
            digest[index * 4 + 3] = static_cast<unsigned char>(state_[index]);
        }
        return digest;
    }

private:
    void transform(const unsigned char* data) {
        std::array<std::uint32_t, 64> words{};
        for (std::size_t index = 0; index < 16; ++index) {
            const std::size_t offset = index * 4;
            words[index] = (static_cast<std::uint32_t>(data[offset]) << 24U) |
                           (static_cast<std::uint32_t>(data[offset + 1]) << 16U) |
                           (static_cast<std::uint32_t>(data[offset + 2]) << 8U) |
                           static_cast<std::uint32_t>(data[offset + 3]);
        }
        for (std::size_t index = 16; index < words.size(); ++index) {
            const std::uint32_t s0 = rotate_right(words[index - 15], 7) ^
                                     rotate_right(words[index - 15], 18) ^
                                     (words[index - 15] >> 3U);
            const std::uint32_t s1 = rotate_right(words[index - 2], 17) ^
                                     rotate_right(words[index - 2], 19) ^
                                     (words[index - 2] >> 10U);
            words[index] = words[index - 16] + s0 + words[index - 7] + s1;
        }

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];

        for (std::size_t index = 0; index < words.size(); ++index) {
            const std::uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                                       rotate_right(e, 25);
            const std::uint32_t choice = (e & f) ^ ((~e) & g);
            const std::uint32_t temporary1 = h + sum1 + choice + constants[index] + words[index];
            const std::uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                                       rotate_right(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temporary2 = sum0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + temporary1;
            d = c;
            c = b;
            b = a;
            a = temporary1 + temporary2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<std::uint32_t, 8> state_ = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    std::array<unsigned char, 64> block_{};
    std::size_t block_size_{0};
    std::uint64_t total_bytes_{0};
};
}  // namespace

std::string sha256_fd(int descriptor) {
    Sha256 hash;
    std::array<unsigned char, 65536> buffer{};
    off_t offset = 0;
    while (true) {
        const ssize_t count = pread(descriptor, buffer.data(), buffer.size(), offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            throw std::runtime_error("cannot hash executable: " +
                                     std::string(std::strerror(errno)));
        }
        if (count == 0) {
            break;
        }
        hash.update(buffer.data(), static_cast<std::size_t>(count));
        offset += count;
    }
    const auto digest = hash.finish();
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const unsigned char byte : digest) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}
