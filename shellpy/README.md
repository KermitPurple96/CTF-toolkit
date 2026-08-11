# PyFuscation & shellpy

- Shellpy is a reverse shell generator in different languages with the ability to obfuscate code to evade antivirus and provide a macro ready to create a malicious document.

## Obfuscation

`--obfuscate` works with `-powershell`, `-powercat`, `-nishang`, `-conpty`,
`-bash` and `-perl`. Powershell goes through `psobfuscator.py`, bash and perl
through `shobfuscator.py`; the techniques have nothing in common, so the two
are separate.

### Powershell

`shellpy --obfuscate` and the standalone `PyFuscation.py` share one engine,
`psobfuscator.py`. They used to carry a copy each and the copies drifted:
shellpy's lost the `PSconfig.ini` load, so it renamed the powershell automatic
variables and the generated scripts died at runtime.

Renaming covers the variables, parameters and functions of the payload.
Names that powershell resolves itself are left alone, because renaming them is
what used to make the obfuscated script fail at runtime with *"X is not
recognized as the name of a cmdlet, function, script file, or operable
program"*:

- automatic and preference variables (`PSconfig.ini` plus the extras listed in
  `EXTRA_RESERVED`),
- scope and provider qualifiers, so `$global:Verbose` and `$env:USERNAME`
  survive intact,
- generated names are unique, never empty and never shadow a built in alias.

Renaming itself is case insensitive and anchored on both sides, matching how
powershell resolves names: a script declaring `Start-PowerCat` and calling
`Start-Powercat` is renamed consistently.

Known limitation: renaming also reaches inside string literals. A script that
prints its own function name, or builds a call out of a string, sees that text
change too. Powercat relies on this to assemble functions at runtime, so the
behaviour is kept.

### Bash and perl

These payloads are one liners: no functions, no local variables, nothing to
rename. `shobfuscator.py` re-encodes the command instead, printing every
variant that applies so you can pick one:

| Technique | Applies to |
|---|---|
| `base64` | any payload, the command never appears as text |
| `hex ANSI-C` | any payload, `bash -c $'\x62\x61…'` |
| IP in decimal | bash payloads using `/dev/tcp`, which takes an integer host |
| `${IFS}` for spaces | commands with no quotes or redirections |
| `eval(pack("H*",…))` | the whole perl script as a hex blob |
| hex string literals | perl, also renames `$i` and `$p` |

`${IFS}` is restricted on purpose: it expands to space+tab+newline, so next to
a redirection the target file name comes out wrong and the payload stops
connecting. Same for single quotes, inside which it does not expand at all.

### Tests

```bash
python3 tests/test_obfuscation.py --rounds 10   # powershell
python3 tests/test_sh_obfuscation.py            # bash y perl
```

The bash/perl suite runs every generated variant against a local listener and
checks it returns a shell: an obfuscated payload that does not connect is
worthless. Needs `nc` and `perl`.

Obfuscates powercat, nishang, ConPtyShell and `tests/fixtures/functions.ps1`
repeatedly, through both frontends, and checks that:

- every declared function was actually renamed,
- no old name, variable or parameter is left behind,
- automatic variables and scope qualifiers are untouched,
- the powershell parser reports no new errors or unresolved commands,
- the fixture still prints exactly what it printed before obfuscation.

The parser checks need `pwsh`; the rest run without it. The three remote
scripts are downloaded once into `tests/.cache/`.

![shellpy](https://github.com/user-attachments/assets/b8967d23-2f90-4b52-92e9-0068facc9a4b)

![shell1](https://github.com/user-attachments/assets/a70d7de5-6bd1-41c7-b8ff-fca17e26b3e8)

![shell4](https://github.com/user-attachments/assets/4308aeaf-93f5-411f-a7ef-5e142c3bc6d5)

![shell3](https://github.com/user-attachments/assets/9bb1efe9-bcaa-49b8-b99b-b865b758eefe)
