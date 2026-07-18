#include "script.hpp"

#include <algorithm>
#include <cstddef>
#include <cctype>
#include <filesystem>

namespace fs = std::filesystem;

namespace {
enum class Interpreter {
    none,
    python,
    shell,
    perl,
    ruby,
    node,
    php,
    lua,
};

bool versioned_name(const std::string& name, const std::string& base) {
    if (name == base) {
        return true;
    }
    if (name.rfind(base, 0) != 0 || name.size() == base.size()) {
        return false;
    }
    return std::all_of(name.begin() + static_cast<std::ptrdiff_t>(base.size()),
                       name.end(), [](unsigned char character) {
        return std::isdigit(character) != 0 || character == '.';
    });
}

Interpreter interpreter_type(const std::string& executable) {
    const std::string name = fs::path(executable).filename().string();
    if (versioned_name(name, "python")) {
        return Interpreter::python;
    }
    if (name == "sh" || name == "bash" || name == "dash" || name == "zsh" ||
        name == "ksh") {
        return Interpreter::shell;
    }
    if (versioned_name(name, "perl")) {
        return Interpreter::perl;
    }
    if (versioned_name(name, "ruby")) {
        return Interpreter::ruby;
    }
    if (versioned_name(name, "node") || versioned_name(name, "nodejs")) {
        return Interpreter::node;
    }
    if (versioned_name(name, "php")) {
        return Interpreter::php;
    }
    if (versioned_name(name, "lua")) {
        return Interpreter::lua;
    }
    return Interpreter::none;
}

bool inline_code_option(Interpreter type, const std::string& option) {
    switch (type) {
    case Interpreter::python:
        return option == "-c" || option == "-m";
    case Interpreter::shell:
        return option == "-c";
    case Interpreter::perl:
    case Interpreter::ruby:
    case Interpreter::lua:
        return option == "-e" || option == "-E";
    case Interpreter::node:
        return option == "-e" || option == "--eval" || option == "-p" ||
               option == "--print";
    case Interpreter::php:
        return option == "-r";
    case Interpreter::none:
        return false;
    }
    return false;
}

bool option_takes_value(Interpreter type, const std::string& option) {
    switch (type) {
    case Interpreter::python:
        return option == "-W" || option == "-X";
    case Interpreter::shell:
        return option == "-o" || option == "-O";
    case Interpreter::perl:
        return option == "-I" || option == "-M" || option == "-m";
    case Interpreter::ruby:
        return option == "-I" || option == "-r" || option == "-E" ||
               option == "--encoding";
    case Interpreter::node:
        return option == "-r" || option == "--require" ||
               option == "--loader" || option == "--import";
    case Interpreter::php:
        return option == "-d" || option == "-c";
    case Interpreter::lua:
        return option == "-l";
    case Interpreter::none:
        return false;
    }
    return false;
}
}  // namespace

std::vector<std::string> split_process_arguments(const std::string& contents) {
    std::vector<std::string> result;
    std::size_t start = 0;
    while (start < contents.size()) {
        const std::size_t end = contents.find('\0', start);
        result.push_back(contents.substr(
            start, end == std::string::npos ? std::string::npos : end - start));
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    while (!result.empty() && result.back().empty()) {
        result.pop_back();
    }
    return result;
}

std::optional<std::string> find_script_entrypoint(
    const std::string& executable,
    const std::vector<std::string>& arguments,
    const std::string& working_directory) {
    const Interpreter type = interpreter_type(executable);
    if (type == Interpreter::none || arguments.size() < 2) {
        return std::nullopt;
    }

    bool options_finished = false;
    bool skip_value = false;
    for (std::size_t index = 1; index < arguments.size(); ++index) {
        const std::string& argument = arguments[index];
        if (skip_value) {
            skip_value = false;
            continue;
        }
        if (!options_finished && argument == "--") {
            options_finished = true;
            continue;
        }
        if (!options_finished && inline_code_option(type, argument)) {
            return std::nullopt;
        }
        if (!options_finished && !argument.empty() && argument[0] == '-') {
            skip_value = option_takes_value(type, argument);
            continue;
        }

        fs::path path(argument);
        if (!path.is_absolute()) {
            const fs::path directory(working_directory);
            if (!directory.is_absolute()) {
                return std::nullopt;
            }
            path = directory / path;
        }
        path = path.lexically_normal();
        const std::string normalized = path.string();
        if (normalized.empty() || normalized.size() > 4096) {
            return std::nullopt;
        }
        return normalized;
    }
    return std::nullopt;
}
