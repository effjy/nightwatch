#include "authentication.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <map>
#include <sstream>

namespace {
bool starts_with(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) {
                       return static_cast<char>(std::tolower(character));
                   });
    return value;
}

std::string normalize_dash(const std::string& value) {
    return value == "-" ? std::string{} : value;
}

bool parse_hex4(const std::string& input, std::size_t& offset,
                unsigned int& value) {
    if (offset + 4 > input.size()) return false;
    value = 0;
    for (unsigned int index = 0; index < 4; ++index) {
        const unsigned char character =
            static_cast<unsigned char>(input[offset++]);
        value <<= 4U;
        if (character >= '0' && character <= '9') {
            value += character - '0';
        } else if (character >= 'a' && character <= 'f') {
            value += 10U + character - 'a';
        } else if (character >= 'A' && character <= 'F') {
            value += 10U + character - 'A';
        } else {
            return false;
        }
    }
    return true;
}

void append_utf8(std::string& output, unsigned int value) {
    if (value <= 0x7fU) {
        output.push_back(static_cast<char>(value));
    } else if (value <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (value >> 6U)));
        output.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xe0U | (value >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((value >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
    }
}

void skip_space(const std::string& input, std::size_t& offset) {
    while (offset < input.size() &&
           std::isspace(static_cast<unsigned char>(input[offset]))) {
        ++offset;
    }
}

bool parse_json_string(const std::string& input, std::size_t& offset,
                       std::string& output) {
    skip_space(input, offset);
    if (offset >= input.size() || input[offset++] != '"') return false;
    output.clear();
    while (offset < input.size()) {
        const unsigned char character =
            static_cast<unsigned char>(input[offset++]);
        if (character == '"') return true;
        if (character < 0x20U) return false;
        if (character != '\\') {
            output.push_back(static_cast<char>(character));
            continue;
        }
        if (offset >= input.size()) return false;
        const char escaped = input[offset++];
        switch (escaped) {
        case '"': output.push_back('"'); break;
        case '\\': output.push_back('\\'); break;
        case '/': output.push_back('/'); break;
        case 'b': output.push_back('\b'); break;
        case 'f': output.push_back('\f'); break;
        case 'n': output.push_back('\n'); break;
        case 'r': output.push_back('\r'); break;
        case 't': output.push_back('\t'); break;
        case 'u': {
            unsigned int value = 0;
            if (!parse_hex4(input, offset, value)) return false;
            append_utf8(output, value);
            break;
        }
        default: return false;
        }
    }
    return false;
}

bool skip_json_value(const std::string& input, std::size_t& offset) {
    skip_space(input, offset);
    if (offset >= input.size()) return false;
    if (input[offset] == '"') {
        std::string ignored;
        return parse_json_string(input, offset, ignored);
    }
    if (input[offset] == '[' || input[offset] == '{') {
        const char opening = input[offset++];
        const char closing = opening == '[' ? ']' : '}';
        unsigned int depth = 1;
        bool quoted = false;
        bool escaped = false;
        while (offset < input.size()) {
            const char character = input[offset++];
            if (quoted) {
                if (escaped) escaped = false;
                else if (character == '\\') escaped = true;
                else if (character == '"') quoted = false;
            } else if (character == '"') {
                quoted = true;
            } else if (character == opening) {
                ++depth;
            } else if (character == closing && --depth == 0) {
                return true;
            }
        }
        return false;
    }
    const std::size_t beginning = offset;
    while (offset < input.size() && input[offset] != ',' &&
           input[offset] != '}') {
        ++offset;
    }
    return offset > beginning;
}

bool parse_json_object(const std::string& input,
                       std::map<std::string, std::string>& fields) {
    std::size_t offset = 0;
    skip_space(input, offset);
    if (offset >= input.size() || input[offset++] != '{') return false;
    fields.clear();
    while (true) {
        skip_space(input, offset);
        if (offset >= input.size()) return false;
        if (input[offset] == '}') {
            ++offset;
            skip_space(input, offset);
            return offset == input.size();
        }
        std::string name;
        if (!parse_json_string(input, offset, name)) return false;
        skip_space(input, offset);
        if (offset >= input.size() || input[offset++] != ':') return false;
        skip_space(input, offset);
        if (offset < input.size() && input[offset] == '"') {
            std::string value;
            if (!parse_json_string(input, offset, value)) return false;
            fields[name] = std::move(value);
        } else {
            const std::size_t value_start = offset;
            if (!skip_json_value(input, offset)) return false;
            std::size_t value_end = offset;
            while (value_end > value_start &&
                   std::isspace(static_cast<unsigned char>(input[value_end - 1]))) {
                --value_end;
            }
            fields[name] = input.substr(value_start, value_end - value_start);
        }
        skip_space(input, offset);
        if (offset >= input.size()) return false;
        if (input[offset] == ',') {
            ++offset;
            continue;
        }
        if (input[offset] != '}') return false;
    }
}

std::string field(const std::map<std::string, std::string>& fields,
                  const std::string& name) {
    const auto found = fields.find(name);
    return found == fields.end() ? std::string{} : found->second;
}

std::string event_timestamp(const std::string& microseconds) {
    try {
        std::size_t consumed = 0;
        const unsigned long long parsed = std::stoull(microseconds, &consumed);
        if (consumed != microseconds.size()) return microseconds;
        const auto point = std::chrono::system_clock::time_point(
            std::chrono::microseconds(parsed));
        const std::time_t raw = std::chrono::system_clock::to_time_t(point);
        std::tm local{};
        localtime_r(&raw, &local);
        std::ostringstream output;
        output << std::put_time(&local, "%Y-%m-%d %H:%M:%S %Z");
        return output.str();
    } catch (const std::exception&) {
        return microseconds;
    }
}

std::string token_value(const std::string& message, const std::string& name) {
    const std::string marker = name + '=';
    std::size_t position = 0;
    while ((position = message.find(marker, position)) != std::string::npos) {
        if (position == 0 || message[position - 1] == ' ' ||
            message[position - 1] == ';') {
            const std::size_t beginning = position + marker.size();
            const std::size_t end = message.find_first_of(" ;", beginning);
            return message.substr(beginning, end - beginning);
        }
        position += marker.size();
    }
    return {};
}

bool parse_ssh_message(const std::string& message, const std::string& prefix,
                       std::string& user, std::string& source) {
    if (!starts_with(message, prefix)) return false;
    const std::size_t for_position = message.find(" for ", prefix.size());
    if (for_position == std::string::npos) return false;
    std::size_t user_start = for_position + 5;
    static const std::string invalid = "invalid user ";
    if (message.compare(user_start, invalid.size(), invalid) == 0) {
        user_start += invalid.size();
    }
    const std::size_t from_position = message.find(" from ", user_start);
    if (from_position == std::string::npos || from_position == user_start) {
        return false;
    }
    const std::size_t source_start = from_position + 6;
    const std::size_t port_position = message.find(" port ", source_start);
    if (port_position == std::string::npos || port_position == source_start) {
        return false;
    }
    user = message.substr(user_start, from_position - user_start);
    source = message.substr(source_start, port_position - source_start);
    return !user.empty() && !source.empty();
}

std::string provider_name(const std::map<std::string, std::string>& fields) {
    std::string provider = field(fields, "SYSLOG_IDENTIFIER");
    if (provider.empty()) provider = field(fields, "_COMM");
    if (provider.empty()) provider = field(fields, "_SYSTEMD_UNIT");
    return provider;
}

bool add_event(AuthenticationJournalParse& result, AuthenticationEvent event,
               std::size_t maximum_events) {
    if (result.events.size() >= maximum_events) {
        result.truncated = true;
        return false;
    }
    result.events.push_back(std::move(event));
    return true;
}

void classify_record(const std::map<std::string, std::string>& fields,
                     AuthenticationJournalParse& result,
                     std::size_t maximum_events) {
    const std::string message = field(fields, "MESSAGE");
    if (message.empty()) return;
    AuthenticationEvent event;
    event.cursor = field(fields, "__CURSOR");
    event.timestamp = event_timestamp(field(fields, "__REALTIME_TIMESTAMP"));
    event.uid = field(fields, "_UID");
    event.provider = provider_name(fields);
    event.detail = message;

    std::string parsed_user;
    std::string parsed_source;
    if (parse_ssh_message(message, "Accepted ", parsed_user, parsed_source)) {
        event.type = AuthenticationEventType::session_started;
        event.user = parsed_user;
        event.source = parsed_source;
        add_event(result, std::move(event), maximum_events);
        return;
    }
    static const std::string new_prefix = "New session ";
    static const std::string user_separator = " of user ";
    if (starts_with(message, new_prefix) && message.back() == '.') {
        const std::size_t separator = message.find(
            user_separator, new_prefix.size());
        if (separator != std::string::npos && separator > new_prefix.size() &&
            separator + user_separator.size() < message.size() - 1) {
            const std::string session = message.substr(
                new_prefix.size(), separator - new_prefix.size());
            const std::string user = message.substr(
                separator + user_separator.size(),
                message.size() - 1 - separator - user_separator.size());
        for (auto existing = result.events.rbegin();
             existing != result.events.rend(); ++existing) {
            if (existing->type == AuthenticationEventType::session_started &&
                existing->session_id.empty() && existing->user == user) {
                existing->session_id = session;
                if (existing->provider.find("systemd-logind") == std::string::npos) {
                    existing->provider += "+systemd-logind";
                }
                return;
            }
        }
        event.type = AuthenticationEventType::session_started;
        event.session_id = session;
        event.user = user;
        add_event(result, std::move(event), maximum_events);
        return;
        }
    }
    static const std::string removed_prefix = "Removed session ";
    static const std::string session_prefix = "Session ";
    static const std::string logged_suffix = " logged out.";
    if (starts_with(message, removed_prefix) && message.back() == '.' &&
        message.size() > removed_prefix.size() + 1) {
        event.type = AuthenticationEventType::session_ended;
        event.session_id = message.substr(
            removed_prefix.size(), message.size() - removed_prefix.size() - 1);
        add_event(result, std::move(event), maximum_events);
        return;
    }
    if (starts_with(message, session_prefix) &&
        message.size() > session_prefix.size() + logged_suffix.size() &&
        message.compare(message.size() - logged_suffix.size(),
                        logged_suffix.size(), logged_suffix) == 0) {
        event.type = AuthenticationEventType::session_ended;
        event.session_id = message.substr(
            session_prefix.size(), message.size() - session_prefix.size() -
                                       logged_suffix.size());
        add_event(result, std::move(event), maximum_events);
        return;
    }
    if (parse_ssh_message(message, "Failed ", parsed_user, parsed_source)) {
        event.type = AuthenticationEventType::authentication_failed;
        event.user = parsed_user;
        event.source = parsed_source;
        add_event(result, std::move(event), maximum_events);
        return;
    }
    if (starts_with(message, "pam_") &&
        lower(message).find("authentication failure") != std::string::npos) {
        event.type = AuthenticationEventType::authentication_failed;
        event.user = token_value(message, "user");
        event.tty = token_value(message, "tty");
        event.source = token_value(message, "rhost");
        add_event(result, std::move(event), maximum_events);
        return;
    }
    const std::string provider = lower(event.provider);
    const std::string normalized = lower(message);
    const bool lock_provider =
        provider.find("screensaver") != std::string::npos ||
        provider.find("gnome-shell") != std::string::npos ||
        provider.find("systemd-logind") != std::string::npos;
    if (lock_provider &&
        (normalized == "screen locked" ||
         normalized.find("session locked") != std::string::npos)) {
        event.type = AuthenticationEventType::session_locked;
        add_event(result, std::move(event), maximum_events);
    } else if (lock_provider &&
               (normalized == "screen unlocked" ||
                normalized.find("session unlocked") != std::string::npos)) {
        event.type = AuthenticationEventType::session_unlocked;
        add_event(result, std::move(event), maximum_events);
    }
}
}  // namespace

std::string authentication_event_type_name(AuthenticationEventType type) {
    switch (type) {
    case AuthenticationEventType::session_started: return "session started";
    case AuthenticationEventType::session_ended: return "session ended";
    case AuthenticationEventType::authentication_failed:
        return "authentication failed";
    case AuthenticationEventType::session_locked: return "session locked";
    case AuthenticationEventType::session_unlocked: return "session unlocked";
    }
    return "authentication event";
}

std::string authentication_event_summary(const AuthenticationEvent& event) {
    std::ostringstream output;
    output << authentication_event_type_name(event.type);
    if (!event.user.empty()) output << " for user " << event.user;
    if (!event.session_id.empty()) output << " (session " << event.session_id << ')';
    if (!event.seat.empty()) output << " on seat " << event.seat;
    if (!event.tty.empty()) output << " via TTY " << event.tty;
    if (!event.source.empty()) output << " from " << event.source;
    if (!event.provider.empty()) output << " [source " << event.provider << ']';
    return output.str();
}

std::string parse_journal_cursor(const std::string& output) {
    std::istringstream input(output);
    std::string line;
    std::string cursor;
    while (std::getline(input, line)) {
        static const std::string prefix = "-- cursor: ";
        if (starts_with(line, prefix) && line.size() > prefix.size()) {
            cursor = line.substr(prefix.size());
        }
    }
    return cursor;
}

AuthenticationJournalParse parse_authentication_journal(
    const std::string& output, std::size_t maximum_events) {
    AuthenticationJournalParse result;
    std::istringstream input(output);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || starts_with(line, "-- No entries --")) continue;
        if (starts_with(line, "-- cursor: ")) {
            result.cursor = line.substr(std::string("-- cursor: ").size());
            continue;
        }
        std::map<std::string, std::string> fields;
        if (!parse_json_object(line, fields)) {
            ++result.malformed_lines;
            continue;
        }
        const std::string cursor = field(fields, "__CURSOR");
        if (!cursor.empty()) result.cursor = cursor;
        classify_record(fields, result, maximum_events);
    }
    return result;
}

LoginSessionListParse parse_login_session_list(const std::string& output,
                                               std::size_t maximum_sessions) {
    LoginSessionListParse result;
    std::istringstream input(output);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) continue;
        std::istringstream fields(line);
        std::string id;
        std::string uid;
        std::string user;
        std::string seat;
        std::string tty;
        if (!(fields >> id >> uid >> user >> seat >> tty) || id.empty()) {
            ++result.malformed_lines;
            continue;
        }
        if (result.session_ids.size() >= maximum_sessions) {
            result.truncated = true;
            continue;
        }
        result.session_ids.push_back(id);
    }
    return result;
}

bool parse_login_session_properties(const std::string& output,
                                    LoginSession& session,
                                    std::string& error) {
    std::map<std::string, std::string> properties;
    std::istringstream input(output);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) continue;
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos || separator == 0) {
            error = "malformed loginctl property line";
            return false;
        }
        properties[line.substr(0, separator)] = line.substr(separator + 1);
    }
    session.id = properties["Id"];
    session.uid = properties["User"];
    session.user = properties["Name"];
    session.seat = normalize_dash(properties["Seat"]);
    session.tty = normalize_dash(properties["TTY"]);
    session.source = normalize_dash(properties["RemoteHost"]);
    session.state = properties["State"];
    session.remote = lower(properties["Remote"]) == "yes";
    const auto locked = properties.find("LockedHint");
    session.locked_known = locked != properties.end() &&
        (lower(locked->second) == "yes" || lower(locked->second) == "no");
    session.locked = session.locked_known && lower(locked->second) == "yes";
    if (session.id.empty() || session.uid.empty() || session.user.empty()) {
        error = "loginctl record lacks Id, User, or Name";
        return false;
    }
    error.clear();
    return true;
}
