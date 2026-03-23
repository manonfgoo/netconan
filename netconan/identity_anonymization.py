"""Anonymize identity names (usernames, remote hosts) and group/view names."""

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

import base64
import hashlib
import logging
import re

# Cisco/Arista username with view (must be checked before plain username regex)
_CISCO_USER_VIEW_REGEX = re.compile(
    r"username\s+(?P<user>\S+)\s+view\s+(?P<view>\S+)"
    r"(?=\s+(?:sha256-password|password|secret)\s)"
)

# Cisco/Arista username without view
_CISCO_USER_REGEX = re.compile(
    r"username\s+(?P<user>\S+)"
    r"(?=(?:\s+\S+)*\s+(?:sha256-password|password|secret)\s)"
)

# Cisco bsd-username (TACACS+ attribute)
_BSD_USERNAME_REGEX = re.compile(r"bsd-username\s+(?P<user>\S+)(?=\s+secret\s)")

# SNMP server user + group + optional remote host
_SNMP_USER_REGEX = re.compile(
    r"snmp-server\s+user\s+(?P<user>\S+)\s+(?P<group>\S+)"
    r"(?:\s+remote\s+(?P<rhost>\S+))?"
    r"(?=(?:\s+\S+)*\s+(?:(?:v3\s+)?(?:encrypted\s+)?auth)\s)"
)

# Juniper set-style login user + full-name (captures both on one line)
_JUNIPER_SET_USER_FULLNAME_REGEX = re.compile(
    r"set\s+(?:\S+\s+)*?system\s+login\s+user\s+(?P<user>[^\s{;]+)"
    r'\s+full-name\s+"?(?P<fullname>[^"]+?)"?\s*$'
)

# Juniper set-style login user (broadened to support groups prefix and more keywords)
_JUNIPER_SET_USER_REGEX = re.compile(
    r"set\s+(?:\S+\s+)*?system\s+login\s+user\s+(?P<user>[^\s{;]+)"
    r"(?=\s+(?:authentication|full-name|uid|class)\s)"
)

# Juniper hierarchical full-name (quoted or unquoted)
_FULLNAME_REGEX = re.compile(r'full-name\s+"?(?P<fullname>[^";]+)"?\s*;')

# SNMP v3 security-name (hierarchical and set-style)
_SNMP_SECURITY_NAME_REGEX = re.compile(
    r"security-name\s+(?P<user>[^\s{;]+)(?=\s|[{;]|$)"
)

# Juniper hierarchical user block opener
_JUNIPER_HIER_USER_REGEX = re.compile(r"^\s*user\s+(?P<user>\S+)\s*\{")

# Hierarchical group (SNMP VACM or similar)
_HIER_GROUP_REGEX = re.compile(r"^\s*group\s+(?P<group>\S+)\s*[{;]")

# Hierarchical SNMP view block opener
_HIER_VIEW_REGEX = re.compile(r"^\s*view\s+(?P<view>\S+)\s*\{")

# Juniper config group name: set groups <NAME> ...
_SET_GROUPS_REGEX = re.compile(r"set\s+groups\s+(?P<group>[^\s{;]+)")

# BGP peer group: bgp group <NAME>
_BGP_GROUP_REGEX = re.compile(r"\bbgp\s+group\s+(?P<group>[^\s{;]+)")

# Apply-groups reference: apply-groups <NAME>
_APPLY_GROUPS_REGEX = re.compile(r"\bapply-groups\s+(?P<group>[^\s{;]+)")

# VACM security-to-group group assignment (set-style)
_VACM_SET_GROUP_REGEX = re.compile(
    r"security-to-group\s+.*\bgroup\s+(?P<group>[^\s{;]+)"
)

# VACM access group + optional view (set-style, combined)
_VACM_ACCESS_SET_REGEX = re.compile(
    r"vacm\s+access\s+group\s+(?P<group>[^\s{;]+)"
    r"(?:.*(?:read-view|write-view|notify-view)\s+(?P<view>[^\s{;]+))?"
)


def anonymize_identity(name, prefix, lookup, salt):
    """Generate a deterministic anonymized identity name.

    Args:
        name: Original identity name.
        prefix: Prefix for the replacement (e.g., "user", "group").
        lookup: Dict keyed by (prefix, name) for consistent replacements.
        salt: Salt string for deterministic hashing.

    Returns:
        Anonymized identity string like "user_ab2cd3ef".
    """
    key = (prefix, name)
    if key in lookup:
        return lookup[key]

    hash_input = (salt + name).encode()
    digest = hashlib.sha256(hash_input).digest()
    b32 = base64.b32encode(digest).decode().lower()[:8]
    replacement = "{}_{}".format(prefix, b32)

    lookup[key] = replacement
    return replacement


def generate_identity_regexes():
    """Return identity regexes with their group-to-prefix mappings.

    These regexes handle usernames, remote hosts, fullnames, and Cisco
    inline views.  Group/view patterns are in generate_group_regexes().

    Returns:
        List of (compiled_regex, [(group_name, prefix), ...]) tuples,
        ordered most-specific first.
    """
    return [
        # Existing flat-style patterns (most specific first)
        (_CISCO_USER_VIEW_REGEX, [("user", "user"), ("view", "view")]),
        (_CISCO_USER_REGEX, [("user", "user")]),
        (_BSD_USERNAME_REGEX, [("user", "user")]),
        (_SNMP_USER_REGEX, [("user", "user"), ("rhost", "rhost")]),
        # Juniper set-style (most specific first: user+fullname, then user-only)
        (
            _JUNIPER_SET_USER_FULLNAME_REGEX,
            [("user", "user"), ("fullname", "fullname")],
        ),
        (_JUNIPER_SET_USER_REGEX, [("user", "user")]),
        # Juniper hierarchical patterns (less specific, tried last)
        (_FULLNAME_REGEX, [("fullname", "fullname")]),
        (_SNMP_SECURITY_NAME_REGEX, [("user", "user")]),
        (_JUNIPER_HIER_USER_REGEX, [("user", "user")]),
    ]


def generate_group_regexes():
    """Return group/view regexes with their group-to-prefix mappings.

    These regexes handle SNMP inline group names, hierarchical group
    blocks, and hierarchical view blocks.  They are used by the
    ``--anonymize-groups`` flag independently from identity regexes.

    Returns:
        List of (compiled_regex, [(group_name, prefix), ...]) tuples.
    """
    return [
        (_SNMP_USER_REGEX, [("group", "group")]),
        (_SET_GROUPS_REGEX, [("group", "group")]),
        (_BGP_GROUP_REGEX, [("group", "group")]),
        (_APPLY_GROUPS_REGEX, [("group", "group")]),
        (_VACM_SET_GROUP_REGEX, [("group", "group")]),
        (_VACM_ACCESS_SET_REGEX, [("group", "group"), ("view", "view")]),
        (_HIER_GROUP_REGEX, [("group", "group")]),
        (_HIER_VIEW_REGEX, [("view", "view")]),
    ]


def replace_identities(compiled_regexes, line, lookup, salt, reserved_words):
    """Replace identity names in the given line.

    All matching regexes are applied (not just the first match).  When
    multiple regexes match overlapping positions, the first regex in
    the list wins at each position.  Replacements are applied
    right-to-left to preserve string positions.

    Args:
        compiled_regexes: List from generate_identity_regexes() or
            generate_group_regexes().
        line: Input configuration line.
        lookup: Dict for consistent replacements across lines.
        salt: Salt string for deterministic hashing.
        reserved_words: Set of words to skip (config keywords).

    Returns:
        The line with identity names anonymized.
    """
    all_replacements = []
    for regex, group_prefixes in compiled_regexes:
        match = regex.search(line)
        if match is None:
            continue

        for group_name, prefix in group_prefixes:
            value = match.group(group_name)
            if value is None:
                continue
            if value in reserved_words:
                logging.debug(
                    "Skipping reserved word '%s' in group '%s'", value, group_name
                )
                continue
            anon_value = anonymize_identity(value, prefix, lookup, salt)
            start = match.start(group_name)
            end = match.end(group_name)
            all_replacements.append((start, end, anon_value))

    # Remove overlapping replacements (first regex wins at each position)
    all_replacements.sort(key=lambda x: x[0])
    non_overlapping = []
    last_end = -1
    for start, end, anon_value in all_replacements:
        if start >= last_end:
            non_overlapping.append((start, end, anon_value))
            last_end = end

    # Apply right-to-left to preserve positions
    for start, end, anon_value in reversed(non_overlapping):
        line = line[:start] + anon_value + line[end:]

    if non_overlapping:
        logging.debug("Anonymized identity names in line")

    return line
