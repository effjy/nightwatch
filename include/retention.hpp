#pragma once

#include <cstddef>
#include <cstdint>

class RecordBudget {
public:
    explicit RecordBudget(std::size_t limit) noexcept;

    bool allow_new(std::size_t retained) noexcept;
    std::size_t limit() const noexcept;
    std::uint64_t dropped() const noexcept;

private:
    std::size_t limit_;
    std::uint64_t dropped_{0};
};

class JournalBudget {
public:
    JournalBudget(std::uint64_t maximum_bytes,
                  std::uint64_t marker_reserve_bytes) noexcept;

    bool allow_entry(std::size_t bytes) noexcept;
    void account_written(std::size_t bytes) noexcept;
    bool marker_fits(std::size_t bytes) const noexcept;

    std::uint64_t maximum_bytes() const noexcept;
    std::uint64_t written_bytes() const noexcept;
    std::uint64_t dropped_entries() const noexcept;
    bool exhausted() const noexcept;

private:
    std::uint64_t maximum_bytes_;
    std::uint64_t normal_bytes_;
    std::uint64_t written_bytes_{0};
    std::uint64_t dropped_entries_{0};
    bool exhausted_{false};
};

