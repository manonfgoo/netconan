"""Test identity anonymization through the FileAnonymizer pipeline."""

import io

from netconan.anonymize_files import FileAnonymizer

_SALT = "TESTSALT"


def test_anonymize_identities_and_passwords():
    """Test that both identities and passwords are anonymized when both flags are on."""
    input_line = "username jsmith password 7 122A00190102180D3C2E\n"
    file_anonymizer = FileAnonymizer(
        anon_pwd=True, anon_ip=False, salt=_SALT, anon_identities=True
    )
    input_io = io.StringIO(input_line)
    output_io = io.StringIO()
    file_anonymizer.anonymize_io(input_io, output_io)
    result = output_io.getvalue()

    # Username should be anonymized
    assert "jsmith" not in result
    assert "user_" in result
    # Password should also be anonymized
    assert "122A00190102180D3C2E" not in result


def test_anonymize_identities_only():
    """Test that identities are anonymized but passwords preserved when only identities flag is on."""
    input_line = "username jsmith password 7 122A00190102180D3C2E\n"
    file_anonymizer = FileAnonymizer(
        anon_pwd=False, anon_ip=False, salt=_SALT, anon_identities=True
    )
    input_io = io.StringIO(input_line)
    output_io = io.StringIO()
    file_anonymizer.anonymize_io(input_io, output_io)
    result = output_io.getvalue()

    # Username should be anonymized
    assert "jsmith" not in result
    assert "user_" in result
    # Password should be preserved (password anonymization is off)
    assert "122A00190102180D3C2E" in result


def test_anonymize_identities_snmp():
    """Test SNMP user identity anonymization (without group) through the pipeline."""
    input_line = "snmp-server user Someone Somegroup v3 auth sha Secret123 priv aes 128 PrivSecret\n"
    file_anonymizer = FileAnonymizer(
        anon_pwd=False, anon_ip=False, salt=_SALT, anon_identities=True
    )
    input_io = io.StringIO(input_line)
    output_io = io.StringIO()
    file_anonymizer.anonymize_io(input_io, output_io)
    result = output_io.getvalue()

    assert "Someone" not in result
    assert "user_" in result
    # Group is NOT replaced without --anonymize-groups
    assert "Somegroup" in result
    assert "group_" not in result
    # Command structure preserved
    assert result.startswith("snmp-server user ")
