#include "preflight.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {
bool expect(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
    }
    return condition;
}
}  // namespace

int main() {
    bool passed = true;
    passed &= expect(preflight_exit_code({}) == 0,
                     "no findings should be ready");
    passed &= expect(preflight_exit_code({
                         {PreflightStatus::pass, "one", "ok"},
                         {PreflightStatus::warning, "two", "degraded"}}) == 3,
                     "a warning should produce the degraded exit status");
    passed &= expect(preflight_exit_code({
                         {PreflightStatus::warning, "one", "degraded"},
                         {PreflightStatus::failure, "two", "bad"}}) == 1,
                     "a failure should dominate warnings");
    if (!passed) {
        return 1;
    }
    std::cout << "Preflight status tests passed\n";
    return 0;
}
