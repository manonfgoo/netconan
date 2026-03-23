"""Test identity anonymization."""

#   Copyright 2018 Intentionet
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import re

import pytest

from netconan.identity_anonymization import (
    anonymize_identity,
    generate_group_regexes,
    generate_identity_regexes,
    replace_identities,
)

SALT = "testSalt"

# Reserved words that should not be anonymized (subset for testing)
RESERVED_WORDS = {
    "password",
    "secret",
    "auth",
    "authentication",
    "view",
    "v3",
    "monitoring",
    "all",
}


class TestAnonymizeIdentity:
    """Tests for anonymize_identity()."""

    def test_determinism(self):
        """Same name + salt always produces same output."""
        lookup = {}
        result1 = anonymize_identity("admin", "user", lookup, SALT)
        lookup2 = {}
        result2 = anonymize_identity("admin", "user", lookup2, SALT)
        assert result1 == result2

    def test_format(self):
        """Output matches {prefix}_{8-char-base32} pattern."""
        lookup = {}
        result = anonymize_identity("admin", "user", lookup, SALT)
        assert re.match(r"^user_[a-z2-7]{8}$", result)

    def test_different_names(self):
        """Different names produce different hashes."""
        lookup = {}
        result1 = anonymize_identity("admin", "user", lookup, SALT)
        result2 = anonymize_identity("operator", "user", lookup, SALT)
        assert result1 != result2

    def test_different_salts(self):
        """Different salts produce different hashes."""
        lookup1 = {}
        result1 = anonymize_identity("admin", "user", lookup1, "salt1")
        lookup2 = {}
        result2 = anonymize_identity("admin", "user", lookup2, "salt2")
        assert result1 != result2

    def test_same_name_different_prefix(self):
        """Same name with different prefixes produces different output."""
        lookup = {}
        result_user = anonymize_identity("admin", "user", lookup, SALT)
        result_group = anonymize_identity("admin", "group", lookup, SALT)
        assert result_user != result_group

    def test_lookup_caching(self):
        """Cached value is returned on subsequent calls."""
        lookup = {}
        result1 = anonymize_identity("admin", "user", lookup, SALT)
        result2 = anonymize_identity("admin", "user", lookup, SALT)
        assert result1 == result2
        assert ("user", "admin") in lookup


# Test data: (line, expected_user, expected_view)
cisco_user_view_lines = [
    (
        "username Someone view Someview password 7 122A00190102180D3C2E",
        "Someone",
        "Someview",
    ),
    ("username Someone view Someview secret 5 $1$salt$hash", "Someone", "Someview"),
]

# Test data: (line, expected_user)
cisco_user_lines = [
    ("username Someone password 0 Pwd", "Someone"),
    ("username Someone password 7 122A00190102180D3C2E", "Someone"),
    ("username Someone secret 5 $1$salt$ABCDEFGHIJKLMNOPQRS", "Someone"),
    ("username Someone secret sha512 $6$salt$hash", "Someone"),
    ("username noc secret sha512 $6$rounds=100000$hash", "noc"),
    ("username Someone privilege 15 password 7 122A001901", "Someone"),
    ("username Someone role network-admin password 5 $1$salt$hash", "Someone"),
    (
        "username maxmusertmann sha256-password 8 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 privilege 15 role sysadmin",
        "maxmusertmann",
    ),
]

# Test data: (line, expected_user) — Cisco bsd-username (TACACS+)
bsd_username_lines = [
    (
        "bsd-username maxmustermann secret $1$sqLg/clL$0000000000000000000000000$",
        "maxmustermann",
    ),
    ("bsd-username netops secret 5 $1$salt$hash", "netops"),
]

# Test data: (line, expected_user, expected_group, expected_rhost)
snmp_user_lines = [
    (
        "snmp-server user Someone Somegroup v3 auth sha Secret123 priv aes 128 PrivSecret",
        "Someone",
        "Somegroup",
        None,
    ),
    (
        "snmp-server user Someone Somegroup v3 auth md5 Secret123",
        "Someone",
        "Somegroup",
        None,
    ),
    (
        "snmp-server user Someone Somegroup v3 encrypted auth sha Secret123 priv aes 128 PrivSecret",
        "Someone",
        "Somegroup",
        None,
    ),
    (
        "snmp-server user Someone Somegroup auth sha Secret123 priv aes 128 PrivSecret",
        "Someone",
        "Somegroup",
        None,
    ),
    (
        "snmp-server user Someone Somegroup remote Crap v3 auth md5 Secret123 priv des56 PrivSecret",
        "Someone",
        "Somegroup",
        "Crap",
    ),
    (
        "snmp-server user Someone Somegroup remote Crap auth md5 Secret123",
        "Someone",
        "Somegroup",
        "Crap",
    ),
]

# Test data: (line, expected_user, expected_fullname) — Juniper set-style user+fullname
juniper_set_user_fullname_lines = [
    (
        'set system login user rancid full-name "RANCID User"',
        "rancid",
        "RANCID User",
    ),
    (
        'set groups MyGroup system login user netadmin full-name "Net Admin"',
        "netadmin",
        "Net Admin",
    ),
    (
        "set system login user admin full-name Admin",
        "admin",
        "Admin",
    ),
]

# Test data: (line, expected_user) — Juniper set-style user (broadened)
juniper_set_user_lines = [
    (
        'set system login user admin authentication encrypted-password "$6$hash"',
        "admin",
    ),
    (
        'set system login user operator authentication plain-text-password "pwd123"',
        "operator",
    ),
    (
        'set system login user admin authentication ssh-rsa "AAAA..."',
        "admin",
    ),
    (
        "set groups MyGroup system login user rancid uid 164",
        "rancid",
    ),
    (
        "set groups MyGroup system login user rancid class super-user",
        "rancid",
    ),
]

# Test data: (line, expected_fullname) — Juniper hierarchical full-name
fullname_lines = [
    ("    full-name RANCID;", "RANCID"),
    ('    full-name "Network Operations Center";', "Network Operations Center"),
]

# Test data: (line, expected_user) — SNMP v3 security-name
security_name_lines = [
    ("                security-name observium {", "observium"),
    ("    security-name snmpuser;", "snmpuser"),
    (
        "set snmp v3 usm local-engine user myuser01 security-name observium",
        "observium",
    ),
]

# Test data: (line, expected_user) — Juniper hierarchical user block
hier_user_lines = [
    ("    user rancid {", "rancid"),
    ("        user operator {", "operator"),
]

# Test data: (line, expected_group) — hierarchical group
hier_group_lines = [
    ("            group netops {", "netops"),
    ("                group netops;", "netops"),
]

# Test data: (line, expected_view) — hierarchical view
hier_view_lines = [
    ("        view myview {", "myview"),
]

# Lines that should NOT match hierarchical group (reserved words)
hier_group_reserved_lines = [
    ("            group monitoring {", "monitoring"),
    ("                group monitoring;", "monitoring"),
]

# Lines that should NOT match hierarchical view (reserved words)
hier_view_reserved_lines = [
    ("        view all {", "all"),
]

# Test data: (line, expected_group) — set groups
set_groups_lines = [
    ("set groups MyGroup system login user rancid uid 164", "MyGroup"),
    ("set groups EDGE protocols bgp group IBGP", "EDGE"),
]

# Test data: (line, expected_group) — BGP peer group
bgp_group_lines = [
    ("set protocols bgp group IBGP type internal", "IBGP"),
    ("set groups EDGE protocols bgp group EBGP type external", "EBGP"),
]

# Test data: (line, expected_group) — apply-groups
apply_groups_lines = [
    ("set interfaces ge-0/0/0 apply-groups EDGE", "EDGE"),
    ("    apply-groups SOMETHING;", "SOMETHING"),
]

# Test data: (line, expected_group) — VACM security-to-group
vacm_set_group_lines = [
    (
        "set snmp v3 vacm security-to-group security-model usm security-name observium group netops",
        "netops",
    ),
]

# Test data: (line, expected_group, expected_view) — VACM access
vacm_access_set_lines = [
    (
        "set snmp v3 vacm access group netops default-context-prefix security-model any security-level none read-view myview",
        "netops",
        "myview",
    ),
    (
        "set snmp v3 vacm access group observers default-context-prefix security-model any security-level none notify-view alertview",
        "observers",
        "alertview",
    ),
]

# Lines that should NOT match any identity regex (false positives)
false_positive_lines = [
    "    read-view all;",
    "    class RANCID {",
]


class TestRegexMatching:
    """Tests for identity regex matching."""

    @pytest.mark.parametrize("line,expected_user,expected_view", cisco_user_view_lines)
    def test_cisco_user_view_regex(self, line, expected_user, expected_view):
        """Cisco username+view regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[0][0]  # First regex is user+view
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("user") == expected_user
        assert match.group("view") == expected_view

    @pytest.mark.parametrize("line,expected_user", cisco_user_lines)
    def test_cisco_user_regex(self, line, expected_user):
        """Cisco username regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[1][0]  # Second regex is plain username
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("user") == expected_user

    @pytest.mark.parametrize("line,expected_user", bsd_username_lines)
    def test_bsd_username_regex(self, line, expected_user):
        """Cisco bsd-username regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[2][0]  # Third regex is bsd-username
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("user") == expected_user

    @pytest.mark.parametrize(
        "line,expected_user,expected_group,expected_rhost", snmp_user_lines
    )
    def test_snmp_user_regex(self, line, expected_user, expected_group, expected_rhost):
        """SNMP user regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[3][0]  # Fourth regex is SNMP
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("user") == expected_user
        assert match.group("group") == expected_group
        if expected_rhost is not None:
            assert match.group("rhost") == expected_rhost
        else:
            assert match.group("rhost") is None

    @pytest.mark.parametrize(
        "line,expected_user,expected_fullname", juniper_set_user_fullname_lines
    )
    def test_juniper_set_user_fullname_regex(
        self, line, expected_user, expected_fullname
    ):
        """Juniper set-style user+fullname regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[4][0]  # Fifth regex is set-style user+fullname
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("user") == expected_user
        assert match.group("fullname") == expected_fullname

    @pytest.mark.parametrize("line,expected_user", juniper_set_user_lines)
    def test_juniper_set_user_regex(self, line, expected_user):
        """Juniper set-style login user regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[5][0]  # Sixth regex is set-style user
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("user") == expected_user

    @pytest.mark.parametrize("line,expected_fullname", fullname_lines)
    def test_fullname_regex(self, line, expected_fullname):
        """Juniper hierarchical full-name regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[6][0]  # Seventh regex is full-name
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("fullname") == expected_fullname

    @pytest.mark.parametrize("line,expected_user", security_name_lines)
    def test_security_name_regex(self, line, expected_user):
        """SNMP v3 security-name regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[7][0]  # Eighth regex is security-name
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("user") == expected_user

    @pytest.mark.parametrize("line,expected_user", hier_user_lines)
    def test_juniper_hier_user_regex(self, line, expected_user):
        """Juniper hierarchical user block regex matches correctly."""
        regexes = generate_identity_regexes()
        regex = regexes[8][0]  # Ninth regex is hierarchical user
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("user") == expected_user

    @pytest.mark.parametrize("line,expected_group", set_groups_lines)
    def test_set_groups_regex(self, line, expected_group):
        """Set groups regex matches correctly."""
        regexes = generate_group_regexes()
        regex = regexes[1][0]  # Second group regex is set groups
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("group") == expected_group

    @pytest.mark.parametrize("line,expected_group", bgp_group_lines)
    def test_bgp_group_regex(self, line, expected_group):
        """BGP peer group regex matches correctly."""
        regexes = generate_group_regexes()
        regex = regexes[2][0]  # Third group regex is BGP group
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("group") == expected_group

    @pytest.mark.parametrize("line,expected_group", apply_groups_lines)
    def test_apply_groups_regex(self, line, expected_group):
        """Apply-groups regex matches correctly."""
        regexes = generate_group_regexes()
        regex = regexes[3][0]  # Fourth group regex is apply-groups
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("group") == expected_group

    @pytest.mark.parametrize("line,expected_group", vacm_set_group_lines)
    def test_vacm_set_group_regex(self, line, expected_group):
        """VACM security-to-group regex matches correctly."""
        regexes = generate_group_regexes()
        regex = regexes[4][0]  # Fifth group regex is VACM set group
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("group") == expected_group

    @pytest.mark.parametrize("line,expected_group,expected_view", vacm_access_set_lines)
    def test_vacm_access_set_regex(self, line, expected_group, expected_view):
        """VACM access group+view regex matches correctly."""
        regexes = generate_group_regexes()
        regex = regexes[5][0]  # Sixth group regex is VACM access
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("group") == expected_group
        assert match.group("view") == expected_view

    @pytest.mark.parametrize("line,expected_group", hier_group_lines)
    def test_hier_group_regex(self, line, expected_group):
        """Hierarchical group regex matches correctly."""
        regexes = generate_group_regexes()
        regex = regexes[6][0]  # Seventh group regex is hierarchical group
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("group") == expected_group

    @pytest.mark.parametrize("line,expected_view", hier_view_lines)
    def test_hier_view_regex(self, line, expected_view):
        """Hierarchical view regex matches correctly."""
        regexes = generate_group_regexes()
        regex = regexes[7][0]  # Eighth group regex is hierarchical view
        match = regex.search(line)
        assert match is not None, f"Should match: {line}"
        assert match.group("view") == expected_view

    @pytest.mark.parametrize("line", false_positive_lines)
    def test_false_positive_lines_no_identity_match(self, line):
        """Lines that look similar but should NOT match any identity regex."""
        for regex, _ in generate_identity_regexes():
            match = regex.search(line)
            assert (
                match is None
            ), f"Should NOT match: {line} (matched by {regex.pattern})"


# Identity-only lines (replaced by --anonymize-identities)
all_identity_lines = (
    [(line, user) for line, user, _ in cisco_user_view_lines]
    + [(line, user) for line, user in cisco_user_lines]
    + [(line, user) for line, user in bsd_username_lines]
    + [(line, user) for line, user, _, _ in snmp_user_lines]
    + [(line, user) for line, user, _ in juniper_set_user_fullname_lines]
    + [(line, user) for line, user in juniper_set_user_lines]
    + [(line, name) for line, name in fullname_lines]
    + [(line, user) for line, user in security_name_lines]
    + [(line, user) for line, user in hier_user_lines]
)

# Group/view-only lines (replaced by --anonymize-groups)
all_group_lines = (
    [(line, group) for line, group in set_groups_lines]
    + [(line, group) for line, group in bgp_group_lines]
    + [(line, group) for line, group in apply_groups_lines]
    + [(line, group) for line, group in vacm_set_group_lines]
    + [(line, group) for line, group in hier_group_lines]
    + [(line, view) for line, view in hier_view_lines]
)


class TestReplaceIdentities:
    """Tests for replace_identities() with identity regexes."""

    @pytest.mark.parametrize("line,original_user", all_identity_lines)
    def test_identity_replaced(self, line, original_user):
        """Original identity name does not appear in output."""
        regexes = generate_identity_regexes()
        lookup = {}
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert original_user not in result

    @pytest.mark.parametrize("line,original_name", all_identity_lines)
    def test_replacement_format(self, line, original_name):
        """Output contains a properly formatted replacement prefix."""
        regexes = generate_identity_regexes()
        lookup = {}
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        # At least one anonymized identity prefix should appear
        assert any(
            prefix + "_" in result for prefix in ("user", "view", "fullname", "rhost")
        )

    def test_context_preserved_cisco(self):
        """Command keywords and trailing content are preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = "username Someone password 7 122A00190102180D3C2E"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result.startswith("username ")
        assert " password 7 122A00190102180D3C2E" in result

    def test_context_preserved_bsd_username(self):
        """bsd-username keyword and trailing secret are preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = (
            "bsd-username maxmustermann secret $1$sqLg/clL$0000000000000000000000000$"
        )
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result.startswith("bsd-username ")
        assert " secret $1$sqLg/clL$0000000000000000000000000$" in result
        assert "maxmustermann" not in result

    def test_context_preserved_snmp(self):
        """SNMP command structure is preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = "snmp-server user Someone Somegroup v3 auth sha Secret123 priv aes 128 PrivSecret"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result.startswith("snmp-server user ")
        assert " v3 auth sha Secret123 priv aes 128 PrivSecret" in result

    def test_context_preserved_snmp_remote(self):
        """SNMP remote host structure is preserved (identity pass replaces user+rhost)."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = "snmp-server user Someone Somegroup remote Crap v3 auth md5 Secret123 priv des56 PrivSecret"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result.startswith("snmp-server user ")
        assert " remote " in result
        assert " v3 auth md5 Secret123 priv des56 PrivSecret" in result
        # User and rhost replaced by identity pass
        assert "Someone" not in result
        assert "Crap" not in result
        # Group is NOT replaced by identity pass (needs --anonymize-groups)
        assert "Somegroup" in result

    def test_context_preserved_snmp_remote_both_passes(self):
        """SNMP remote host: both identity and group passes replace all names."""
        identity_regexes = generate_identity_regexes()
        group_regexes = generate_group_regexes()
        lookup = {}
        line = "snmp-server user Someone Somegroup remote Crap v3 auth md5 Secret123 priv des56 PrivSecret"
        result = replace_identities(
            identity_regexes, line, lookup, SALT, RESERVED_WORDS
        )
        result = replace_identities(group_regexes, result, lookup, SALT, RESERVED_WORDS)
        assert result.startswith("snmp-server user ")
        assert " remote " in result
        assert " v3 auth md5 Secret123 priv des56 PrivSecret" in result
        assert "Someone" not in result
        assert "Somegroup" not in result
        assert "Crap" not in result

    def test_context_preserved_juniper(self):
        """Juniper command structure is preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = 'set system login user admin authentication encrypted-password "$6$hash"'
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result.startswith("set system login user ")
        assert ' authentication encrypted-password "$6$hash"' in result

    def test_lookup_consistency(self):
        """Same name across lines produces same replacement."""
        regexes = generate_identity_regexes()
        lookup = {}
        line1 = "username admin password 7 122A00190102180D3C2E"
        line2 = "username admin secret 5 $1$salt$hash"
        result1 = replace_identities(regexes, line1, lookup, SALT, RESERVED_WORDS)
        result2 = replace_identities(regexes, line2, lookup, SALT, RESERVED_WORDS)
        # Extract the replacement from both lines
        anon_name = lookup[("user", "admin")]
        assert anon_name in result1
        assert anon_name in result2

    def test_non_identity_line_unchanged(self):
        """Lines without identity patterns pass through unchanged."""
        regexes = generate_identity_regexes()
        lookup = {}
        lines = [
            "ip address 10.0.0.1 255.255.255.0\n",
            "hostname router1\n",
            "interface GigabitEthernet0/0\n",
            "! This is a comment\n",
        ]
        for line in lines:
            result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
            assert result == line

    def test_no_false_positive_description(self):
        """Description lines with 'username' keyword are not matched."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = " description Link to username server\n"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result == line

    def test_reserved_word_skipped(self):
        """Reserved words in identity positions are not replaced."""
        regexes = generate_identity_regexes()
        lookup = {}
        # "v3" is in reserved words, so the group name "v3" should not be replaced
        line = "snmp-server user Someone v3 v3 auth sha Secret123"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "v3 auth" in result
        # But "Someone" should be replaced
        assert "Someone" not in result

    def test_view_in_user_view_line(self):
        """Both user and view are replaced in username+view lines."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = "username Someone view Someview password 7 122A00190102180D3C2E"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "Someone" not in result
        assert "Someview" not in result
        assert "user_" in result
        assert "view_" in result
        assert " password 7 122A00190102180D3C2E" in result

    def test_snmp_group_replaced(self):
        """SNMP group name is replaced with group_ prefix using group regexes."""
        regexes = generate_group_regexes()
        lookup = {}
        line = "snmp-server user Someone Somegroup v3 auth sha Secret123"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "group_" in result
        assert "Somegroup" not in result

    # --- Hierarchical pattern context preservation tests ---

    def test_context_preserved_hier_user(self):
        """Hierarchical user block structure is preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = "    user rancid {"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result.endswith("{")
        assert "rancid" not in result
        assert "user_" in result

    def test_context_preserved_fullname_unquoted(self):
        """Unquoted full-name value is anonymized, structure preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = "    full-name RANCID;"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "full-name" in result
        assert result.rstrip().endswith(";")
        assert "RANCID" not in result
        assert "fullname_" in result

    def test_context_preserved_fullname_quoted(self):
        """Quoted full-name value is anonymized, quotes preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = '    full-name "Network Operations Center";'
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "full-name" in result
        assert result.rstrip().endswith(";")
        assert "Network Operations Center" not in result
        assert "fullname_" in result

    def test_context_preserved_security_name(self):
        """Security-name block structure is preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = "                security-name observium {"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "security-name" in result
        assert result.endswith("{")
        assert "observium" not in result
        assert "user_" in result

    def test_context_preserved_hier_group(self):
        """Hierarchical group block structure is preserved."""
        regexes = generate_group_regexes()
        lookup = {}
        line = "            group netops {"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result.endswith("{")
        assert "netops" not in result
        assert "group_" in result

    def test_context_preserved_hier_view(self):
        """Hierarchical view block structure is preserved."""
        regexes = generate_group_regexes()
        lookup = {}
        line = "        view myview {"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert result.endswith("{")
        assert "myview" not in result
        assert "view_" in result

    # --- Reserved word protection tests for hierarchical patterns ---

    @pytest.mark.parametrize("line,reserved_name", hier_group_reserved_lines)
    def test_hier_group_reserved_word_skipped(self, line, reserved_name):
        """Reserved words in hierarchical group position are not replaced."""
        regexes = generate_group_regexes()
        lookup = {}
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert reserved_name in result
        assert "group_" not in result

    @pytest.mark.parametrize("line,reserved_name", hier_view_reserved_lines)
    def test_hier_view_reserved_word_skipped(self, line, reserved_name):
        """Reserved words in hierarchical view position are not replaced."""
        regexes = generate_group_regexes()
        lookup = {}
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert reserved_name in result
        assert "view_" not in result

    # --- False positive tests for hierarchical patterns ---

    @pytest.mark.parametrize("line", false_positive_lines)
    def test_hier_false_positives_unchanged(self, line):
        """Lines that look similar to hierarchical patterns pass through unchanged."""
        for regexes in [generate_identity_regexes(), generate_group_regexes()]:
            lookup = {}
            result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
            assert result == line

    # --- Set-style context preservation tests ---

    def test_context_preserved_set_user_uid(self):
        """Set-style user with uid is anonymized, structure preserved."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = "set groups MyGroup system login user rancid uid 164"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "rancid" not in result
        assert "user_" in result
        assert " uid 164" in result

    def test_context_preserved_set_user_fullname(self):
        """Set-style user+fullname has both anonymized."""
        regexes = generate_identity_regexes()
        lookup = {}
        line = 'set system login user rancid full-name "RANCID User"'
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "rancid" not in result
        assert "RANCID User" not in result
        assert "user_" in result
        assert "fullname_" in result

    # --- Multi-match tests ---

    def test_multi_match_three_groups_on_one_line(self):
        """Multi-match: three group names on one line are all replaced."""
        regexes = generate_group_regexes()
        lookup = {}
        line = "set groups Group1 protocols bgp group Group2 apply-groups Group3"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "Group1" not in result
        assert "Group2" not in result
        assert "Group3" not in result
        # Three distinct group_ replacements
        import re as _re

        group_matches = _re.findall(r"group_[a-z2-7]{8}", result)
        assert len(group_matches) == 3

    def test_multi_match_vacm_group_and_view(self):
        """Multi-match: VACM access group + view on one line both replaced."""
        regexes = generate_group_regexes()
        lookup = {}
        line = "set snmp v3 vacm access group netops default-context-prefix security-model any security-level none read-view myview"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "netops" not in result
        assert "myview" not in result
        assert "group_" in result
        assert "view_" in result


class TestReplaceGroups:
    """Tests for replace_identities() with group regexes."""

    @pytest.mark.parametrize("line,original_name", all_group_lines)
    def test_group_replaced(self, line, original_name):
        """Original group/view name does not appear in output."""
        regexes = generate_group_regexes()
        lookup = {}
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert original_name not in result

    @pytest.mark.parametrize("line,original_name", all_group_lines)
    def test_group_replacement_format(self, line, original_name):
        """Output contains a properly formatted group/view replacement prefix."""
        regexes = generate_group_regexes()
        lookup = {}
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert any(prefix + "_" in result for prefix in ("group", "view"))

    def test_snmp_group_only_replaces_group(self):
        """Group regexes on SNMP line replace group but not user."""
        regexes = generate_group_regexes()
        lookup = {}
        line = "snmp-server user Someone Somegroup v3 auth sha Secret123"
        result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
        assert "group_" in result
        assert "Somegroup" not in result
        # User should NOT be touched by group regexes
        assert "Someone" in result

    def test_non_group_line_unchanged(self):
        """Lines without group patterns pass through unchanged."""
        regexes = generate_group_regexes()
        lookup = {}
        lines = [
            "ip address 10.0.0.1 255.255.255.0\n",
            "hostname router1\n",
            "username Someone password 7 122A00190102180D3C2E\n",
        ]
        for line in lines:
            result = replace_identities(regexes, line, lookup, SALT, RESERVED_WORDS)
            assert result == line
