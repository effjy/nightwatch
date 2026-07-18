#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

enum class AuthenticationEventType {
    session_started,
    session_ended,
    authentication_failed,
    session_locked,
    session_unlocked
};

struct AuthenticationEvent {
    std::string timestamp;
    std::string cursor;
    AuthenticationEventType type{AuthenticationEventType::authentication_failed};
    std::string session_id;
    std::string user;
    std::string uid;
    std::string seat;
    std::string tty;
    std::string source;
    std::string provider;
    std::string detail;
};

struct LoginSession {
    std::string id;
    std::string uid;
    std::string user;
    std::string seat;
    std::string tty;
    std::string source;
    std::string state;
    bool remote{false};
    bool locked_known{false};
    bool locked{false};
};

struct AuthenticationJournalParse {
    std::vector<AuthenticationEvent> events;
    std::string cursor;
    std::size_t malformed_lines{0};
    bool truncated{false};
};

struct LoginSessionListParse {
    std::vector<std::string> session_ids;
    std::size_t malformed_lines{0};
    bool truncated{false};
};

struct AuthenticationStatus {
    bool journal_available{false};
    bool session_state_available{false};
    std::size_t malformed_journal_records{0};
    bool journal_truncated{false};
};

std::string authentication_event_type_name(AuthenticationEventType type);
std::string authentication_event_summary(const AuthenticationEvent& event);
std::string parse_journal_cursor(const std::string& output);
AuthenticationJournalParse parse_authentication_journal(
    const std::string& output, std::size_t maximum_events = 4096);
LoginSessionListParse parse_login_session_list(
    const std::string& output, std::size_t maximum_sessions = 1024);
bool parse_login_session_properties(const std::string& output,
                                    LoginSession& session,
                                    std::string& error);

