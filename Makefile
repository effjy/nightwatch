CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Wconversion -pthread
CPPFLAGS ?= -Iinclude
LDFLAGS ?=
LDLIBS ?= -pthread

TARGET := nightwatch
TEST_TARGETS := tests/sha256_test tests/reviewed_test tests/network_test \
	 tests/script_test tests/kernel_test tests/preflight_test tests/assurance_test \
	 tests/golden_report_test tests/json_report_test tests/helper_runner_test \
	 tests/retention_test tests/paths_test tests/persistence_test \
	 tests/authentication_test
SANITIZE_DIR := build/sanitize
SANITIZE_CXXFLAGS := -std=c++17 -O1 -g3 -Wall -Wextra -Wpedantic \
	-Wconversion -pthread -fsanitize=address,undefined -fno-omit-frame-pointer
SANITIZE_LDFLAGS := -fsanitize=address,undefined
SANITIZE_ASAN_OPTIONS ?= detect_leaks=0:strict_string_checks=1
SANITIZE_TEST_TARGETS := $(addprefix $(SANITIZE_DIR)/,sha256_test \
	reviewed_test network_test script_test kernel_test preflight_test \
	assurance_test golden_report_test json_report_test helper_runner_test \
	retention_test paths_test persistence_test authentication_test)
FUZZ_DIR := build/fuzz
FUZZ_ITERATIONS ?= 50000
FUZZ_SEED ?= 0x4e49474854574154
PREFIX ?= /usr/local
SYSTEM_CONFIG_DIR ?= /etc/nightwatch
STATE_DIR ?= /var/lib/nightwatch
REPORT_DIR ?= /var/log/nightwatch
REVIEWED_SOURCE ?= packaging/reviewed-executables.db
VERSION ?= 0.1.0
SOURCES := $(wildcard src/*.cpp)
OBJECTS := $(SOURCES:.cpp=.o)

.PHONY: all debug test sanitize fuzz fuzz-build install install-reviewed dist clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

src/%.o: src/%.cpp include/monitor.hpp include/fingerprint.hpp include/network.hpp \
		include/reviewed.hpp include/script.hpp include/kernel.hpp include/preflight.hpp \
		include/assurance.hpp include/assurance_json.hpp include/helper_runner.hpp \
		include/retention.hpp include/paths.hpp include/persistence.hpp \
		include/authentication.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

src/sha256.o: include/sha256.hpp

tests/sha256_test: tests/sha256_test.cpp src/sha256.cpp include/sha256.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/sha256_test.cpp src/sha256.cpp -o $@

tests/reviewed_test: tests/reviewed_test.cpp src/reviewed.cpp \
		include/reviewed.hpp include/fingerprint.hpp \
		packaging/reviewed-executables.db
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/reviewed_test.cpp src/reviewed.cpp -o $@

tests/network_test: tests/network_test.cpp src/network.cpp include/network.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/network_test.cpp src/network.cpp -o $@

tests/script_test: tests/script_test.cpp src/script.cpp src/fingerprint.cpp \
		src/sha256.cpp include/script.hpp include/fingerprint.hpp include/sha256.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/script_test.cpp src/script.cpp \
		src/fingerprint.cpp src/sha256.cpp -o $@

tests/kernel_test: tests/kernel_test.cpp src/kernel.cpp include/kernel.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/kernel_test.cpp src/kernel.cpp -o $@

tests/preflight_test: tests/preflight_test.cpp src/preflight.cpp src/fingerprint.cpp \
		src/reviewed.cpp src/sha256.cpp src/helper_runner.cpp include/preflight.hpp \
		include/fingerprint.hpp include/reviewed.hpp include/sha256.hpp \
		include/helper_runner.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/preflight_test.cpp src/preflight.cpp \
		src/fingerprint.cpp src/reviewed.cpp src/sha256.cpp src/helper_runner.cpp -o $@

tests/assurance_test: tests/assurance_test.cpp src/assurance.cpp include/assurance.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/assurance_test.cpp src/assurance.cpp -o $@

tests/golden_report_test: tests/golden_report_test.cpp src/assurance.cpp \
		src/sha256.cpp include/assurance.hpp include/sha256.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/golden_report_test.cpp \
	src/assurance.cpp src/sha256.cpp -o $@

tests/json_report_test: tests/json_report_test.cpp src/assurance_json.cpp \
		src/assurance.cpp src/authentication.cpp include/assurance_json.hpp \
		include/assurance.hpp include/authentication.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/json_report_test.cpp \
		src/assurance_json.cpp src/assurance.cpp src/authentication.cpp -o $@

tests/helper_runner_test: tests/helper_runner_test.cpp src/helper_runner.cpp \
		include/helper_runner.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/helper_runner_test.cpp \
		src/helper_runner.cpp -o $@

tests/retention_test: tests/retention_test.cpp src/retention.cpp \
		include/retention.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/retention_test.cpp \
		src/retention.cpp -o $@

tests/paths_test: tests/paths_test.cpp include/paths.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/paths_test.cpp -o $@

tests/persistence_test: tests/persistence_test.cpp src/persistence.cpp \
		src/fingerprint.cpp src/reviewed.cpp src/sha256.cpp include/persistence.hpp \
		include/fingerprint.hpp include/sha256.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/persistence_test.cpp \
		src/persistence.cpp src/fingerprint.cpp src/reviewed.cpp src/sha256.cpp -o $@

tests/authentication_test: tests/authentication_test.cpp src/authentication.cpp \
		include/authentication.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/authentication_test.cpp \
		src/authentication.cpp -o $@

test: all $(TEST_TARGETS)
	./tests/sha256_test
	./tests/reviewed_test
	./tests/network_test
	./tests/script_test
	./tests/kernel_test
	./tests/preflight_test
	./tests/assurance_test
	./tests/golden_report_test
	./tests/json_report_test
	./tests/helper_runner_test
	./tests/retention_test
	./tests/paths_test
	./tests/persistence_test
	./tests/authentication_test

$(SANITIZE_DIR):
	mkdir -p $@

$(SANITIZE_DIR)/sha256_test: tests/sha256_test.cpp src/sha256.cpp \
		include/sha256.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/sha256_test.cpp \
		src/sha256.cpp $(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/reviewed_test: tests/reviewed_test.cpp src/reviewed.cpp \
		include/reviewed.hpp include/fingerprint.hpp \
		packaging/reviewed-executables.db | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/reviewed_test.cpp \
		src/reviewed.cpp $(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/network_test: tests/network_test.cpp src/network.cpp \
		include/network.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/network_test.cpp \
		src/network.cpp $(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/script_test: tests/script_test.cpp src/script.cpp \
		src/fingerprint.cpp src/sha256.cpp include/script.hpp \
		include/fingerprint.hpp include/sha256.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/script_test.cpp \
		src/script.cpp src/fingerprint.cpp src/sha256.cpp \
		$(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/kernel_test: tests/kernel_test.cpp src/kernel.cpp \
		include/kernel.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/kernel_test.cpp \
		src/kernel.cpp $(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/preflight_test: tests/preflight_test.cpp src/preflight.cpp \
		src/fingerprint.cpp src/reviewed.cpp src/sha256.cpp src/helper_runner.cpp \
		include/preflight.hpp include/fingerprint.hpp include/reviewed.hpp \
		include/sha256.hpp include/helper_runner.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/preflight_test.cpp \
		src/preflight.cpp src/fingerprint.cpp src/reviewed.cpp src/sha256.cpp \
		src/helper_runner.cpp \
		$(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/assurance_test: tests/assurance_test.cpp src/assurance.cpp \
		include/assurance.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/assurance_test.cpp \
		src/assurance.cpp $(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/golden_report_test: tests/golden_report_test.cpp \
		src/assurance.cpp src/sha256.cpp include/assurance.hpp \
		include/sha256.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/golden_report_test.cpp \
		src/assurance.cpp src/sha256.cpp $(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/json_report_test: tests/json_report_test.cpp \
		src/assurance_json.cpp src/assurance.cpp src/authentication.cpp \
		include/assurance_json.hpp include/assurance.hpp \
		include/authentication.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/json_report_test.cpp \
		src/assurance_json.cpp src/assurance.cpp src/authentication.cpp \
		$(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/helper_runner_test: tests/helper_runner_test.cpp \
		src/helper_runner.cpp include/helper_runner.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/helper_runner_test.cpp \
		src/helper_runner.cpp $(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/retention_test: tests/retention_test.cpp src/retention.cpp \
		include/retention.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/retention_test.cpp \
		src/retention.cpp $(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/paths_test: tests/paths_test.cpp include/paths.hpp \
		| $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/paths_test.cpp \
		$(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/persistence_test: tests/persistence_test.cpp \
		src/persistence.cpp src/fingerprint.cpp src/sha256.cpp \
		src/reviewed.cpp include/persistence.hpp include/fingerprint.hpp \
		include/sha256.hpp \
		| $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/persistence_test.cpp \
		src/persistence.cpp src/fingerprint.cpp src/reviewed.cpp src/sha256.cpp \
		$(SANITIZE_LDFLAGS) -o $@

$(SANITIZE_DIR)/authentication_test: tests/authentication_test.cpp \
		src/authentication.cpp include/authentication.hpp | $(SANITIZE_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/authentication_test.cpp \
		src/authentication.cpp $(SANITIZE_LDFLAGS) -o $@

sanitize: $(SANITIZE_TEST_TARGETS)
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/sha256_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/reviewed_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/network_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/script_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/kernel_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/preflight_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/assurance_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/golden_report_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/json_report_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/helper_runner_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/retention_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/paths_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/persistence_test
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(SANITIZE_DIR)/authentication_test

$(FUZZ_DIR):
	mkdir -p $@

$(FUZZ_DIR)/parser_fuzz: tests/parser_fuzz.cpp src/network.cpp src/kernel.cpp \
		src/script.cpp src/authentication.cpp include/network.hpp include/kernel.hpp \
		include/script.hpp include/authentication.hpp \
		| $(FUZZ_DIR)
	$(CXX) $(CPPFLAGS) $(SANITIZE_CXXFLAGS) tests/parser_fuzz.cpp \
		src/network.cpp src/kernel.cpp src/script.cpp src/authentication.cpp \
		$(SANITIZE_LDFLAGS) -o $@

fuzz-build: $(FUZZ_DIR)/parser_fuzz

fuzz: $(FUZZ_DIR)/parser_fuzz
	ASAN_OPTIONS=$(SANITIZE_ASAN_OPTIONS) \
		UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
		$(FUZZ_DIR)/parser_fuzz --seed $(FUZZ_SEED) \
		--iterations $(FUZZ_ITERATIONS)

debug: CXXFLAGS := -std=c++17 -O0 -g3 -Wall -Wextra -Wpedantic -Wconversion -pthread
debug: clean all

install: all
	install -d -o root -g root -m 0755 $(DESTDIR)$(PREFIX)/sbin
	install -o root -g root -m 0755 $(TARGET) \
		$(DESTDIR)$(PREFIX)/sbin/$(TARGET)
	install -d -o root -g root -m 0700 $(DESTDIR)$(SYSTEM_CONFIG_DIR)
	install -d -o root -g root -m 0700 $(DESTDIR)$(STATE_DIR)
	install -d -o root -g root -m 0700 $(DESTDIR)$(REPORT_DIR)

install-reviewed: $(REVIEWED_SOURCE)
	install -d -o root -g root -m 0700 $(DESTDIR)$(SYSTEM_CONFIG_DIR)
	install -o root -g root -m 0600 $(REVIEWED_SOURCE) \
		$(DESTDIR)$(SYSTEM_CONFIG_DIR)/reviewed-executables.db

dist:
	./scripts/package-release.sh $(VERSION)

clean:
	$(RM) $(OBJECTS) $(TARGET) $(TEST_TARGETS)
	$(RM) -r $(SANITIZE_DIR)
	$(RM) -r $(FUZZ_DIR)
