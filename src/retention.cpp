#include "retention.hpp"

#include <limits>

namespace {
void saturating_increment(std::uint64_t& value) noexcept {
    if (value != std::numeric_limits<std::uint64_t>::max()) {
        ++value;
    }
}

std::uint64_t saturating_add(std::uint64_t left, std::size_t right) noexcept {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    if (right > maximum || left > maximum - static_cast<std::uint64_t>(right)) {
        return maximum;
    }
    return left + static_cast<std::uint64_t>(right);
}
}

RecordBudget::RecordBudget(std::size_t limit) noexcept : limit_(limit) {}

bool RecordBudget::allow_new(std::size_t retained) noexcept {
    if (retained < limit_) {
        return true;
    }
    saturating_increment(dropped_);
    return false;
}

std::size_t RecordBudget::limit() const noexcept { return limit_; }
std::uint64_t RecordBudget::dropped() const noexcept { return dropped_; }

JournalBudget::JournalBudget(std::uint64_t maximum_bytes,
                             std::uint64_t marker_reserve_bytes) noexcept
    : maximum_bytes_(maximum_bytes),
      normal_bytes_(marker_reserve_bytes > maximum_bytes
                        ? 0U : maximum_bytes - marker_reserve_bytes) {}

bool JournalBudget::allow_entry(std::size_t bytes) noexcept {
    if (exhausted_ || saturating_add(written_bytes_, bytes) > normal_bytes_) {
        exhausted_ = true;
        saturating_increment(dropped_entries_);
        return false;
    }
    return true;
}

void JournalBudget::account_written(std::size_t bytes) noexcept {
    written_bytes_ = saturating_add(written_bytes_, bytes);
}

bool JournalBudget::marker_fits(std::size_t bytes) const noexcept {
    return saturating_add(written_bytes_, bytes) <= maximum_bytes_;
}

std::uint64_t JournalBudget::maximum_bytes() const noexcept {
    return maximum_bytes_;
}

std::uint64_t JournalBudget::written_bytes() const noexcept {
    return written_bytes_;
}

std::uint64_t JournalBudget::dropped_entries() const noexcept {
    return dropped_entries_;
}

bool JournalBudget::exhausted() const noexcept { return exhausted_; }

