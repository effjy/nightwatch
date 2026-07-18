#include "retention.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>

int main() {
    RecordBudget records(2);
    assert(records.allow_new(0));
    assert(records.allow_new(1));
    assert(!records.allow_new(2));
    assert(!records.allow_new(3));
    assert(records.limit() == 2);
    assert(records.dropped() == 2);

    RecordBudget none(0);
    assert(!none.allow_new(0));
    assert(none.dropped() == 1);

    JournalBudget journal(100, 20);
    assert(journal.allow_entry(60));
    journal.account_written(60);
    assert(journal.written_bytes() == 60);
    assert(journal.allow_entry(20));
    journal.account_written(20);
    assert(!journal.allow_entry(1));
    assert(journal.exhausted());
    assert(journal.dropped_entries() == 1);
    assert(journal.marker_fits(20));
    journal.account_written(20);
    assert(!journal.marker_fits(1));
    assert(!journal.allow_entry(0));
    assert(journal.dropped_entries() == 2);

    JournalBudget invalid_reserve(10, 20);
    assert(!invalid_reserve.allow_entry(1));
    assert(invalid_reserve.marker_fits(10));

    JournalBudget saturation(std::numeric_limits<std::uint64_t>::max(), 0);
    saturation.account_written(std::numeric_limits<std::size_t>::max());
    assert(saturation.written_bytes() ==
           static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()));

    std::cout << "Retention budget tests passed\n";
    return 0;
}
