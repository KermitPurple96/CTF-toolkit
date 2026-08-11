#!/usr/bin/env python3

'''

    psobfuscator.py
    Shared obfuscation engine for shellpy and PyFuscation.py.

    Both tools used to carry their own copy of this code. They drifted: the
    copy inside shellpy lost the PSconfig.ini load, so the reserved variable
    list stayed empty and powershell automatic variables got renamed. Keeping
    one implementation is what stops that from happening again.

'''

import ast
import configparser
import os
import random
import re
import string

current_dir = os.path.dirname(os.path.abspath(__file__))
wordList = os.path.join(current_dir, 'wordList.txt')
PSconfigFile = os.path.join(current_dir, 'PSconfig.ini')


def printR(out): print("\033[91m{}\033[00m" .format("[!] " + out))
def printG(out): print("\033[92m{}\033[00m" .format("[*] " + out))
def printY(out): print("\033[93m{}\033[00m" .format("[+] " + out))
def printP(out): print("\033[95m{}\033[00m" .format("[-] " + out))


# Automatic/preference variables missing from PSconfig.ini. Renaming any of
# these silently breaks the script at runtime (e.g. $PSBoundParameters becomes
# $null and .ContainsKey() blows up), so they must be treated as reserved too.
EXTRA_RESERVED = [
    '$ProgressPreference', '$WarningPreference', '$VerbosePreference',
    '$DebugPreference', '$ConfirmPreference', '$InformationPreference',
    '$PSDefaultParameterValues', '$PSEdition', '$OutputEncoding',
    '$IsWindows', '$IsLinux', '$IsMacOS', '$IsCoreCLR',
    # Scope and provider qualifiers: in "$global:Verbose" the name before the
    # colon is not a variable, and renaming it yields "$xxx:Verbose" ->
    # "Cannot find drive. A drive with the name 'xxx' does not exist."
    '$global', '$script', '$local', '$private', '$using',
    '$env', '$function', '$variable', '$alias',
]

# Words that must never be handed out as a new function name: picking one of
# these shadows a real command and the obfuscated script stops working.
PS_KEYWORDS = {
    'begin', 'break', 'catch', 'class', 'continue', 'data', 'define', 'do',
    'dynamicparam', 'else', 'elseif', 'end', 'enum', 'exit', 'filter',
    'finally', 'for', 'foreach', 'from', 'function', 'hidden', 'if', 'in',
    'inlinescript', 'parallel', 'param', 'process', 'return', 'sequence',
    'static', 'switch', 'throw', 'trap', 'try', 'until', 'using', 'var',
    'while', 'workflow',
}

_reserved_cache = None
_wordList_cache = None
_ps_commands_cache = None


def loadReserved():
    # PSconfig.ini holds the powershell special/automatic/preference variables
    # that must never be renamed. Cached and looked up lazily by the find*
    # functions, so no caller can forget to load it.
    global _reserved_cache
    if _reserved_cache is None:
        reserved = list(EXTRA_RESERVED)
        if os.path.isfile(PSconfigFile):
            config = configparser.ConfigParser()
            config.read(PSconfigFile)
            try:
                reserved += ast.literal_eval(config.get("PS_Reserverd", "f"))
            except (configparser.Error, ValueError, SyntaxError):
                printR("PSconfig.ini is unreadable, reserved variables are not protected")
        else:
            printR("PSconfig.ini not found at " + PSconfigFile)
        _reserved_cache = list(map(lambda x: x.lower(), reserved))
    return _reserved_cache


def loadWordList():
    # Cached: randomString() used to re-read all 73k lines for every single
    # function name it generated.
    global _wordList_cache
    if _wordList_cache is None:
        words = []
        with open(wordList, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                w = ''.join(e for e in line if e.isalnum())
                # A powershell identifier cannot be empty and should not start
                # with a digit; the wordList contains such lines.
                if len(w) >= 4 and not w[0].isdigit() and w.lower() not in PS_KEYWORDS:
                    words.append(w)
        _wordList_cache = words
    return _wordList_cache


def loadPSCommands():
    # Built in aliases and the handful of cmdlets without a verb-noun dash.
    # Those are the only real commands a wordList entry can ever collide with,
    # and taking one of them as a function name shadows the command for the
    # rest of the script. The list is static on purpose: asking the local pwsh
    # costs about a second per run and gives nothing on a host without it.
    global _ps_commands_cache
    if _ps_commands_cache is None:
        _ps_commands_cache = {
            'ac', 'asnp', 'cat', 'cd', 'chdir', 'clc', 'clear', 'clhy', 'cli',
            'clp', 'cls', 'clv', 'cnsn', 'compare', 'copy', 'cp', 'cpi', 'cpp',
            'curl', 'cvpa', 'dbp', 'del', 'diff', 'dir', 'dnsn', 'ebp', 'echo',
            'epal', 'epcsv', 'epsn', 'erase', 'etsn', 'exec', 'exit', 'exsn',
            'fc', 'fhx', 'fl', 'foreach', 'ft', 'fw', 'gal', 'gbp', 'gc',
            'gcb', 'gci', 'gcm', 'gcs', 'gdr', 'gerr', 'ghy', 'gi', 'gin',
            'gjb', 'gl', 'gm', 'gmo', 'gp', 'gps', 'gpv', 'group', 'gsn',
            'gsnp', 'gsv', 'gtz', 'gu', 'gv', 'gwmi', 'h', 'help', 'history',
            'icm', 'iex', 'ihy', 'ii', 'ipal', 'ipcsv', 'ipmo', 'ipsn', 'irm',
            'ise', 'iwmi', 'iwr', 'kill', 'lp', 'ls', 'man', 'md', 'measure',
            'mi', 'more', 'mount', 'move', 'mp', 'mv', 'nal', 'ndr', 'ni',
            'nmo', 'npssc', 'nsn', 'nv', 'ogv', 'oh', 'pause', 'popd', 'print',
            'prompt', 'ps', 'pushd', 'pwd', 'r', 'rbp', 'rcjb', 'rcsn', 'rd',
            'rdr', 'ren', 'ri', 'rjb', 'rm', 'rmdir', 'rmo', 'rni', 'rnp',
            'rp', 'rsn', 'rsnp', 'rujb', 'rv', 'rvpa', 'rwmi', 'sajb', 'sal',
            'saps', 'sasv', 'sbp', 'sc', 'scb', 'select', 'set', 'shcm', 'si',
            'sl', 'sleep', 'sls', 'sort', 'sp', 'spjb', 'spps', 'spsv',
            'start', 'stz', 'sujb', 'sv', 'swmi', 'tee', 'trcm', 'type',
            'where', 'wget', 'wjb', 'write',
        }
    return _ps_commands_cache


def randomString(taken=None, forbidden=None):
    # Returns a unique identifier that does not collide with an existing name.
    words = loadWordList()
    taken = taken if taken is not None else set()
    forbidden = forbidden if forbidden is not None else set()
    for _ in range(100):
        candidate = random.choice(words)
        low = candidate.lower()
        if low in taken or low in forbidden:
            continue
        return candidate
    # The wordList is exhausted or heavily filtered: fall back to a random
    # identifier rather than returning a colliding (or empty) name.
    while True:
        candidate = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        if candidate.lower() not in taken and candidate.lower() not in forbidden:
            return candidate


def removeJunk(oF):
    # Strips <# #> block comments, whole line # comments and empty lines.
    #
    # This used to run three `sed -i` commands built by string concatenation
    # and split with shlex, so it needed GNU sed and broke on any path
    # containing a space. Same result, no shell.
    with open(oF, 'r', encoding='utf-8', errors='surrogateescape') as f:
        data = f.read()
    # sed leaves a file that ended without a newline exactly as it found it.
    trailingNewline = data.endswith('\n')
    lines = data.split('\n')

    kept = []
    inBlock = False
    for line in lines:
        if inBlock:
            # sed replaced the whole /<#/,/#>/ range, and left the range open
            # to the end of the file when #> never showed up.
            if '#>' in line:
                inBlock = False
            continue
        if '<#' in line:
            if '#>' not in line:
                inBlock = True
            continue
        # A line that is only a comment was blanked and then dropped; a line
        # of nothing but spaces was not, since sed's /^$/ needs it empty.
        if re.match(r'^[ \t]*#', line):
            continue
        if line == '':
            continue
        kept.append(line)

    with open(oF, 'w', encoding='utf-8', errors='surrogateescape') as f:
        f.write('\n'.join(kept) + ('\n' if kept and trailingNewline else ''))


def useSED(DICT, oF):
    # Replaces every name in DICT in a single pass.
    #
    # The old implementation shelled out to `sed -i -e 's/NAME\b/NEW/g'` once
    # per name, which broke the output three ways:
    #   * sed is case sensitive but powershell is not, so a call written
    #     `Start-Powercat` was left behind when the definition said
    #     `Start-PowerCat` -> "is not recognized as the name of a cmdlet".
    #   * there was no \b at the start of the pattern, so any identifier
    #     *ending* with a replaced name got corrupted.
    #   * running the substitutions one after another let a name that had just
    #     been written be rewritten again by a later rule.
    if not DICT:
        return
    # Longest first so that overlapping names cannot mask each other.
    keys = sorted(DICT, key=len, reverse=True)
    lookup = {k.lower(): str(DICT[k]) for k in DICT}

    # The word boundary depends on what kind of name it is, so each branch
    # carries its own.
    branches = []
    for k in keys:
        escaped = re.escape(k)
        if k.startswith('$'):
            # Variable: cannot contain '-', and '$a-$b' must still match $a.
            # ':' closes the boundary so a qualifier such as $global:Verbose is
            # never rewritten into a non-existent drive.
            branches.append(r'(?<![A-Za-z0-9_])' + escaped + r'(?![A-Za-z0-9_:])')
        elif k[0].isalnum() or k[0] == '_':
            # Function: may be Verb-Noun, so '-' has to close the boundary too,
            # otherwise HexArray would match inside ConvertTo-HexArray.
            branches.append(r'(?<![A-Za-z0-9_-])' + escaped + r'(?![A-Za-z0-9_-])')
        else:
            # Parameter, stored as " -Name": the leading space is already the
            # left boundary, so a lookbehind here would only ever reject it.
            branches.append(escaped + r'(?![A-Za-z0-9_-])')
    pattern = re.compile('|'.join(branches), re.IGNORECASE)

    with open(oF, 'r', encoding='utf-8', errors='surrogateescape') as f:
        data = f.read()
    data = pattern.sub(lambda m: lookup[m.group(0).lower()], data)
    with open(oF, 'w', encoding='utf-8', errors='surrogateescape') as f:
        f.write(data)


def findVARs(iFile, lFile):
    VARs = {}
    used = set()
    lower_Reserverd = loadReserved()
    # (?![\w:]) leaves scope and provider qualifiers alone: the name in
    # "$global:Verbose" or "$env:USERNAME" is a drive, not a variable.
    regex = r'(\$\w{6,})(?![\w:])'
    ofHandle = open(lFile, 'w')

    with open(iFile, "r", encoding='utf-8', errors='replace') as f:
        for line in f:
            v = re.findall(regex, line)
            for i in v:
                if i in VARs:
                    continue
                elif i.lower() not in lower_Reserverd:
                    # Powershell vars are case insensitive
                    lowerVARS = {k.lower(): v for k, v in VARs.items()}
                    if i.lower() in lowerVARS:
                        new = lowerVARS.get(i.lower())
                        ofHandle.write("Replacing: " + i + " with: " + new + "\n")
                        VARs[i] = new
                    else:
                        while True:
                            new = "$" + ''.join([random.choice(string.ascii_letters) for n in range(8)]) + "99"
                            if new.lower() not in used:
                                break
                        used.add(new.lower())
                        VARs[i] = new
                        ofHandle.write("Replacing: " + i + " with: " + new + "\n")

    # return dict of variable and their replacements
    printY("Variables Replaced  : " + str(len(VARs)))
    return VARs


def findCustomParams(iFile, oFile, VARs):
    PARAMs = {}
    READ = False
    start = 0
    end = 0
    lower_Reserverd = loadReserved()
    regex = r'([\$-]\w{4,})'
    ofHandle = open(oFile, 'w')

    with open(iFile, "r", encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()

            if re.search(r'\bparam\b', line, re.I):
                # Ok we are at the begining of a custum parameter
                READ = True

                # The open paren is on another line so move until we find it
                start = start + line.count('(')
                if start == 0:
                    continue

                end = end + line.count(')')

                v = re.findall(regex, line)
                for i in v:
                    if i.lower() not in lower_Reserverd and i not in PARAMs:
                        # Lets check to see if this has been replaced already
                        new = VARs.get(i)
                        if not new:
                            continue
                        new = " -" + new[1:]
                        old = " -" + i[1:]
                        PARAMs[old] = new
                        ofHandle.write("Replacing: " + old + " with: " + new + "\n")

                # If the params are all on one line were done here
                if start != 0 and start == end:
                    start = 0
                    end = 0
                    READ = False
                    continue

            # These are the custom parameters
            elif READ:
                v = re.findall(regex, line)
                for i in v:
                    if i.lower() not in lower_Reserverd and i not in PARAMs:
                        new = VARs.get(i)
                        if not new:
                            continue
                        new = " -" + new[1:]
                        old = " -" + i[1:]
                        PARAMs[old] = new
                        ofHandle.write("Replacing: " + old + " with: " + new + "\n")

                start = start + line.count('(')
                end = end + line.count(')')
                if start != 0 and start == end:
                    start = 0
                    end = 0
                    READ = False

            # Keep moving until we have work
            else:
                continue

    printY("Parameters Replaced : " + str(len(PARAMs)))

    return PARAMs


def findFUNCs(iFile, lFile):

    FUNCs = {}
    taken = set()
    lower_Reserverd = loadReserved()
    ofHandle = open(lFile, 'w')

    # Every identifier already present in the script, plus the built in
    # commands. A generated name landing on one of those either shadows a real
    # command or produces a duplicate definition, and the obfuscated script
    # then dies with "is not recognized as the name of a cmdlet, function,
    # script file, or operable program".
    with open(iFile, "r", encoding='utf-8', errors='replace') as f:
        source = f.read()
    forbidden = set(t.lower() for t in re.findall(r'[A-Za-z_][A-Za-z0-9_]{2,}', source))
    forbidden |= loadPSCommands()
    forbidden |= PS_KEYWORDS

    # Matches "function Name", "function Name {", "function Name($a) {" and
    # scope qualifiers such as "function global:Name".
    funcRegex = re.compile(
        r'^\s*function\s+(?:(?:global|script|local|private):)?([a-zA-Z0-9_-]{4,})\s*(?:\(|\{|$)',
        re.IGNORECASE)

    for line in source.splitlines():
        funcMatch = funcRegex.search(line)
        if not funcMatch:
            continue
        name = funcMatch.group(1)
        # Powershell is case insensitive, so a script calling "main" while
        # declaring "Main" must still be skipped.
        if name.lower() == "main" or name.lower() in lower_Reserverd:
            continue
        if any(name.lower() == k.lower() for k in FUNCs):
            continue
        new = randomString(taken=taken, forbidden=forbidden)
        taken.add(new.lower())
        FUNCs[name] = new
        ofHandle.write("Replacing: " + name + " with: " + str(new) + "\n")

    # return dict of variable and their replacements
    printY("Functions Replaced  : " + str(len(FUNCs)))
    return FUNCs
