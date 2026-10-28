from shadowtrace_agent.collectors.windows.eventlog import parse_security_event
from shadowtrace_agent.schema import Category

# StringInserts as Windows writes them, trimmed to the indices the parser reads.


def inserts(positions: dict[int, str]) -> list:
    size = max(positions) + 1
    row = ["-"] * size
    for index, value in positions.items():
        row[index] = value
    return row


def test_failed_logon_is_parsed_with_reason():
    row = inserts(
        {5: "student", 6: "LAB-PC", 10: "2", 13: "LAB-PC", 19: "10.0.0.9", 9: "0xC000006A"}
    )

    category, action, data = parse_security_event(4625, row)

    assert category == Category.AUTH and action == "logon_failed"
    assert data["target_user"] == "LAB-PC\\student"
    assert data["logon_type"] == "interactive"
    assert data["source_ip"] == "10.0.0.9"
    assert data["reason"] == "wrong_password"


def test_successful_logon():
    row = inserts({5: "admin", 6: "LAB-PC", 8: "10", 11: "LAB-PC", 18: "10.0.0.5"})

    _, action, data = parse_security_event(4624, row)

    assert action == "logon_success"
    assert data["logon_type"] == "remote_interactive"
    assert data["target_user"] == "LAB-PC\\admin"


def test_account_lockout():
    _, action, data = parse_security_event(4740, inserts({0: "student", 1: "DC01"}))
    assert action == "account_locked" and data["target_user"] == "student"


def test_new_account_created():
    row = inserts({0: "backdoor", 1: "LAB-PC", 4: "attacker", 5: "LAB-PC"})
    _, action, data = parse_security_event(4720, row)
    assert action == "account_created"
    assert data["new_account"] == "LAB-PC\\backdoor"
    assert data["created_by"] == "LAB-PC\\attacker"


def test_added_to_administrators_is_flagged():
    row = inserts({0: "LAB-PC\\backdoor", 2: "Administrators", 6: "attacker", 7: "LAB-PC"})
    _, action, data = parse_security_event(4732, row)
    assert action == "member_added_to_group"
    assert data["is_admin_group"] is True


def test_non_admin_group_is_not_flagged():
    row = inserts({0: "user", 2: "Remote Desktop Users", 6: "admin", 7: "LAB-PC"})
    _, _, data = parse_security_event(4732, row)
    assert data["is_admin_group"] is False


def test_audit_log_cleared():
    category, action, data = parse_security_event(1102, inserts({1: "attacker", 2: "LAB-PC"}))
    assert category == Category.SYSTEM and action == "audit_log_cleared"
    assert data["cleared_by"] == "LAB-PC\\attacker"


def test_uninteresting_event_is_ignored():
    assert parse_security_event(4799, inserts({0: "x"})) is None


def test_missing_fields_do_not_crash():
    _, action, data = parse_security_event(4625, [])
    assert action == "logon_failed" and data["target_user"] is None
