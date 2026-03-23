"""End-to-end tests for identity anonymization."""

import re

from netconan.netconan import main

# Identity anonymization test data (Cisco/Arista, SNMP, Juniper set-style)
IDENTITY_INPUT = (
    "username jsmith password 7 122A00190102180D3C2E\n"
    "username jsmith view MonitorView secret 5 $1$salt$ABCDEFGHIJKLMNOPQRS\n"
    "username nocteam secret sha512 $6$rounds=100000$hash\n"
    "snmp-server user jsmith Operators v3 auth sha Secret123 priv aes 128 PrivSecret\n"
    "snmp-server user jsmith Operators remote RemHost01 v3 auth md5 Secret123 priv des56 PrivSecret\n"
    'set system login user netadmin authentication encrypted-password "$6$hash"\n'
    # Juniper set-style patterns
    "set groups EDGE system login user svcacct uid 164\n"
    'set system login user svcacct full-name "Service Account"\n'
    "ip address 10.0.0.1 255.255.255.0\n"
    "hostname router1\n"
)


def test_end_to_end_identity_anonymization(tmpdir):
    """Test identity anonymization with mixed Cisco/SNMP/Juniper input."""
    filename = "identities.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(IDENTITY_INPUT)

    output_dir = tmpdir.mkdir("output")
    args = [
        "-i",
        str(input_dir),
        "-o",
        str(output_dir),
        "-s",
        "TESTSALT",
        "--anonymize-identities",
    ]
    main(args)

    with open(str(output_dir.join(filename))) as f:
        output = f.read()

    output_lines = output.strip().split("\n")

    # Original identity names should not appear in output
    assert "jsmith" not in output
    assert "MonitorView" not in output
    assert "nocteam" not in output
    assert "RemHost01" not in output
    assert "netadmin" not in output
    # Set-style pattern names should be anonymized
    assert "svcacct" not in output
    assert "Service Account" not in output

    # SNMP group names should NOT be anonymized (no --anonymize-groups)
    assert "Operators" in output

    # Replacement formats should be present
    assert "user_" in output
    assert "view_" in output
    assert "rhost_" in output
    assert "fullname_" in output

    # Command keywords should be preserved (flat-style lines 0-5)
    assert output_lines[0].startswith("username ")
    assert " password 7 " in output_lines[0]
    assert " view " in output_lines[1]
    assert " secret 5 " in output_lines[1]
    assert output_lines[3].startswith("snmp-server user ")
    assert " v3 auth sha " in output_lines[3]
    assert " remote " in output_lines[4]
    assert output_lines[5].startswith("set system login user ")
    assert " authentication encrypted-password " in output_lines[5]

    # Set-style lines (6-7)
    assert "user_" in output_lines[6]  # set groups ... user svcacct uid 164
    assert " uid 164" in output_lines[6]
    assert "user_" in output_lines[7]  # set system login user svcacct full-name ...
    assert "fullname_" in output_lines[7]

    # Non-identity lines should pass through unchanged
    assert output_lines[8] == "ip address 10.0.0.1 255.255.255.0"
    assert output_lines[9] == "hostname router1"

    # Same username across lines should produce same replacement (determinism)
    user_replacements = set()
    for i in [0, 1, 3, 4]:
        match = re.search(r"user_[a-z2-7]{8}", output_lines[i])
        assert match is not None, f"No user_ replacement in line {i}: {output_lines[i]}"
        user_replacements.add(match.group())
    assert len(user_replacements) == 1, "Same username should produce same replacement"

    # svcacct appears in lines 6 and 7 — should produce same replacement
    svcacct_replacements = set()
    for i in [6, 7]:
        match = re.search(r"user_[a-z2-7]{8}", output_lines[i])
        assert match is not None, f"No user_ replacement in line {i}: {output_lines[i]}"
        svcacct_replacements.add(match.group())
    assert (
        len(svcacct_replacements) == 1
    ), "Same username should produce same replacement"

    # Passwords should NOT be anonymized (only --anonymize-identities, not -p)
    assert "122A00190102180D3C2E" in output
    assert "Secret123" in output


def test_end_to_end_identity_anonymization_deterministic(tmpdir):
    """Test that identity anonymization is deterministic with same salt."""
    filename = "identities.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(IDENTITY_INPUT)

    output_dir1 = tmpdir.mkdir("output1")
    output_dir2 = tmpdir.mkdir("output2")

    args_base = ["-s", "TESTSALT", "--anonymize-identities"]

    main(args_base + ["-i", str(input_dir), "-o", str(output_dir1)])
    main(args_base + ["-i", str(input_dir), "-o", str(output_dir2)])

    with open(str(output_dir1.join(filename))) as f1, open(
        str(output_dir2.join(filename))
    ) as f2:
        assert f1.read() == f2.read()
