#include "authentication.hpp"

#include <cassert>
#include <iostream>
#include <string>

namespace {
std::string journal(const std::string& cursor, const std::string& timestamp,
                    const std::string& provider, const std::string& message,
                    const std::string& uid = "0") {
    return "{\"__CURSOR\":\"" + cursor +
           "\",\"__REALTIME_TIMESTAMP\":\"" + timestamp +
           "\",\"SYSLOG_IDENTIFIER\":\"" + provider +
           "\",\"_UID\":\"" + uid + "\",\"MESSAGE\":\"" +
           message + "\"}\n";
}
}

int main() {
    const std::string normal =
        journal("ssh-ok", "1784343625000000", "sshd",
                "Accepted publickey for alice from 203.0.113.7 port 4422 ssh2") +
        journal("login", "1784343625001000", "systemd-logind",
                "New session 42 of user alice.", "1001") +
        journal("failed", "1784343625002000", "sshd",
                "Failed password for invalid user mallory from 198.51.100.8 port 22 ssh2") +
        journal("pam", "1784343625003000", "mate-screensaver-dialog",
                "pam_unix(mate-screensaver:auth): authentication failure; "
                "logname= uid=1000 euid=1000 tty=:0 ruser= rhost= user=user",
                "1000") +
        journal("end", "1784343625004000", "systemd-logind",
                "Removed session 42.") +
        "-- cursor: final-cursor\n";
    const AuthenticationJournalParse parsed =
        parse_authentication_journal(normal);
    assert(parsed.malformed_lines == 0);
    assert(!parsed.truncated);
    assert(parsed.cursor == "final-cursor");
    assert(parsed.events.size() == 4);
    assert(parsed.events[0].type == AuthenticationEventType::session_started);
    assert(parsed.events[0].user == "alice");
    assert(parsed.events[0].source == "203.0.113.7");
    assert(parsed.events[0].session_id == "42");
    assert(parsed.events[1].type ==
           AuthenticationEventType::authentication_failed);
    assert(parsed.events[1].user == "mallory");
    assert(parsed.events[1].source == "198.51.100.8");
    assert(parsed.events[2].type ==
           AuthenticationEventType::authentication_failed);
    assert(parsed.events[2].user == "user");
    assert(parsed.events[2].tty == ":0");
    assert(parsed.events[3].type == AuthenticationEventType::session_ended);
    assert(parsed.events[3].session_id == "42");

    const std::string harmless = journal(
        "sudo-command", "1784343625005000", "sudo",
        "user : COMMAND=/usr/bin/grep authentication failure journal");
    assert(parse_authentication_journal(harmless).events.empty());

    const AuthenticationJournalParse malformed =
        parse_authentication_journal("{not-json}\n" +
                                     journal("ok", "1", "other", "hello"));
    assert(malformed.malformed_lines == 1);
    assert(malformed.cursor == "ok");

    const AuthenticationJournalParse limited =
        parse_authentication_journal(
            journal("one", "1", "sshd",
                    "Failed password for root from 192.0.2.1 port 22 ssh2") +
            journal("two", "2", "sshd",
                    "Failed password for root from 192.0.2.2 port 22 ssh2"), 1);
    assert(limited.events.size() == 1);
    assert(limited.truncated);
    assert(limited.cursor == "two");

    assert(parse_journal_cursor(
               "-- No entries --\n-- cursor: cursor-value\n") ==
           "cursor-value");

    const LoginSessionListParse sessions = parse_login_session_list(
        "c2 1000 user seat0 - active no -\n"
        "7 1001 alice - pts/2 active no -\n");
    assert(sessions.malformed_lines == 0);
    assert(sessions.session_ids.size() == 2);
    assert(sessions.session_ids[0] == "c2");
    assert(parse_login_session_list("broken\n").malformed_lines == 1);
    assert(parse_login_session_list(
               "c2 1000 user seat0 -\n7 1001 alice - pts/2\n", 1)
               .truncated);

    LoginSession session;
    std::string error;
    assert(parse_login_session_properties(
        "Id=c2\nUser=1000\nName=user\nSeat=seat0\nTTY=\nRemote=no\n"
        "RemoteHost=\nState=active\nLockedHint=no\n",
        session, error));
    assert(session.id == "c2");
    assert(session.user == "user");
    assert(session.seat == "seat0");
    assert(session.locked_known && !session.locked);
    assert(!session.remote);

    LoginSession remote;
    assert(parse_login_session_properties(
        "Id=9\nUser=1001\nName=alice\nSeat=\nTTY=pts/2\nRemote=yes\n"
        "RemoteHost=203.0.113.7\nState=active\nLockedHint=yes\n",
        remote, error));
    assert(remote.remote && remote.locked);
    assert(remote.source == "203.0.113.7");
    assert(!parse_login_session_properties("Id=broken\n", remote, error));
    assert(!error.empty());

    AuthenticationEvent summary_event;
    summary_event.type = AuthenticationEventType::session_unlocked;
    summary_event.user = "user";
    summary_event.session_id = "c2";
    summary_event.seat = "seat0";
    summary_event.provider = "systemd-logind LockedHint";
    const std::string summary = authentication_event_summary(summary_event);
    assert(summary.find("session unlocked") != std::string::npos);
    assert(summary.find("user user") != std::string::npos);
    assert(summary.find("seat0") != std::string::npos);

    std::cout << "Authentication journal and session parser tests passed\n";
    return 0;
}
