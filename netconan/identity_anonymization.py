"""Anonymize identity names (usernames, remote hosts) in configuration lines."""

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
    r"username\s+(?P<user>\S+)\s+view\s+(?P<view>\S+)" r"(?=\s+(?:password|secret)\s)"
)

# Cisco/Arista username without view
_CISCO_USER_REGEX = re.compile(
    r"username\s+(?P<user>\S+)" r"(?=(?:\s+\S+)*\s+(?:password|secret)\s)"
)

# SNMP server user + optional remote host (group capture excluded from identity pass)
_SNMP_USER_REGEX = re.compile(
    r"snmp-server\s+user\s+(?P<user>\S+)\s+\S+"
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
    inline views.

    Returns:
        List of (compiled_regex, [(group_name, prefix), ...]) tuples,
        ordered most-specific first.
    """
    return [
        (_CISCO_USER_VIEW_REGEX, [("user", "user"), ("view", "view")]),
        (_CISCO_USER_REGEX, [("user", "user")]),
        (_SNMP_USER_REGEX, [("user", "user"), ("rhost", "rhost")]),
        (
            _JUNIPER_SET_USER_FULLNAME_REGEX,
            [("user", "user"), ("fullname", "fullname")],
        ),
        (_JUNIPER_SET_USER_REGEX, [("user", "user")]),
    ]


def replace_identities(compiled_regexes, line, lookup, salt, reserved_words):
    """Replace identity names in the given line.

    The first matching regex is applied (break on first match).

    Args:
        compiled_regexes: List from generate_identity_regexes().
        line: Input configuration line.
        lookup: Dict for consistent replacements across lines.
        salt: Salt string for deterministic hashing.
        reserved_words: Set of words to skip (config keywords).

    Returns:
        The line with identity names anonymized.
    """
    for regex, group_prefixes in compiled_regexes:
        match = regex.search(line)
        if match is None:
            continue

        replacements = []
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
            replacements.append((start, end, anon_value))

        # Apply right-to-left to preserve positions
        for start, end, anon_value in reversed(replacements):
            line = line[:start] + anon_value + line[end:]

        if replacements:
            logging.debug("Anonymized identity names in line")

        # Break on first matching regex
        break

    return line
