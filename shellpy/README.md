# PyFuscation & shellpy

- Shellpy is a reverse shell generator in different languages with the ability to obfuscate code to evade antivirus and provide a macro ready to create a malicious document.

## Obfuscation

`--obfuscate` renames the variables, parameters and functions of the payload.
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

### Tests

```bash
python3 tests/test_obfuscation.py --rounds 10
```

Obfuscates powercat, nishang and ConPtyShell repeatedly and checks the result
with the powershell parser (needs `pwsh`; the rest of the checks still run
without it). The target scripts are downloaded once into `tests/.cache/`.

![shellpy](https://github.com/user-attachments/assets/b8967d23-2f90-4b52-92e9-0068facc9a4b)

![shell1](https://github.com/user-attachments/assets/a70d7de5-6bd1-41c7-b8ff-fca17e26b3e8)

![shell4](https://github.com/user-attachments/assets/4308aeaf-93f5-411f-a7ef-5e142c3bc6d5)

![shell3](https://github.com/user-attachments/assets/9bb1efe9-bcaa-49b8-b99b-b865b758eefe)
