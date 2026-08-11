#!/usr/bin/env python3
"""Validacion del ofuscador de shellpy.

Ofusca los .ps1 objetivo varias veces y comprueba, en cada pasada, que el
resultado sigue siendo un script valido y coherente:

  * el parser de PowerShell no encuentra errores nuevos (requiere pwsh),
  * ningun comando queda sin resolver que no lo estuviera ya en el original,
  * las variables automaticas de PowerShell no se han renombrado,
  * los nombres generados son unicos, no vacios y no pisan cmdlets,
  * no queda ningun nombre viejo suelto en el fichero ofuscado.

Uso:  python3 tests/test_obfuscation.py [--rounds N]

Se prueban los dos frontends: shellpy --obfuscate y PyFuscation.py.
"""

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TARGETS = {
    "powercat.ps1":
        "https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1",
    "Invoke-PowerShellTcp.ps1":
        "https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1",
    "Invoke-ConPtyShell.ps1":
        "https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1",
}

# Scripts locales. functions.ps1 cubre las formas de declaracion que ninguno
# de los tres objetivos reales usa, y al ser autonomo se puede ejecutar para
# comparar su salida antes y despues de ofuscar.
FIXTURES = ["functions.ps1"]
EXECUTABLE = {"functions.ps1"}

# Variables automaticas que nunca deben desaparecer del script ofuscado.
AUTOVARS = [
    "$PSBoundParameters", "$PSCmdlet", "$ExecutionContext", "$MyInvocation",
    "$PSScriptRoot", "$PSVersionTable", "$ErrorActionPreference",
    "$ProgressPreference", "$PSCommandPath", "$LASTEXITCODE", "$Matches",
]

PS_ANALYZER = r'''
param([string]$Path)
$errors = $null; $tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $Path).Path, [ref]$tokens, [ref]$errors)
# El AST devuelve "global:Nombre" para una declaracion con calificador de
# ambito, mientras que la llamada es "Nombre": hay que quitar el prefijo.
$defs = $ast.FindAll({param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true) |
    ForEach-Object { $_.Name.ToLower() -replace '^(global|script|local|private):', '' }
$calls = $ast.FindAll({param($n)
    $n -is [System.Management.Automation.Language.CommandAst]}, $true) |
    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
$missing = $calls | Where-Object {
    $defs -notcontains $_.ToLower() -and
    -not (Get-Command $_ -ErrorAction SilentlyContinue) } | Sort-Object -Unique
@{
    parseErrors = @($errors | ForEach-Object { $_.Message })
    missing     = @($missing)
    defs        = @($defs)
} | ConvertTo-Json -Compress
'''


def loadShellpy():
    spec = importlib.util.spec_from_loader(
        "shellpy_mod",
        importlib.machinery.SourceFileLoader("shellpy_mod", os.path.join(ROOT, "shellpy")))
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, ROOT)
    spec.loader.exec_module(mod)
    return mod


def havePwsh():
    return shutil.which("pwsh") is not None


def analyze(path, analyzerFile):
    out = subprocess.run(["pwsh", "-NoProfile", "-File", analyzerFile, "-Path", path],
                         capture_output=True, text=True, timeout=120)
    try:
        return json.loads(out.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return {"parseErrors": ["analyzer failed: " + out.stderr.strip()[:200]], "missing": []}


def fetchTargets(workdir):
    cache = os.path.join(HERE, ".cache")
    os.makedirs(cache, exist_ok=True)
    for name, url in TARGETS.items():
        cached = os.path.join(cache, name)
        if not os.path.exists(cached):
            print(f"  descargando {name} ...")
            subprocess.run(["curl", "-sSL", "-o", cached, url], check=True)
        shutil.copy(cached, os.path.join(workdir, name))
    for name in FIXTURES:
        shutil.copy(os.path.join(HERE, "fixtures", name), os.path.join(workdir, name))


def runScript(path):
    out = subprocess.run(["pwsh", "-NoProfile", "-File", path],
                         capture_output=True, text=True, timeout=120)
    return out.stdout.strip(), out.stderr.strip()


def parseMap(path):
    mapping = {}
    if not os.path.exists(path):
        return mapping
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"Replacing: (\S+) with: (\S*)\s*$", line.rstrip("\n"))
            if m:
                mapping[m.group(1)] = m.group(2)
    return mapping


def runPyFuscation(target):
    # The standalone CLI, which shares the engine with shellpy but has its own
    # argument handling and output paths.
    out = subprocess.run(
        [sys.executable, os.path.join(ROOT, "PyFuscation.py"),
         "-f", "-v", "-p", "--ps", target],
        capture_output=True, text=True, timeout=300)
    m = re.search(r"Obfuscated script located at\s*:\s*(\S+\.ps1)",
                  re.sub(r"\033\[[0-9;]*m", "", out.stdout))
    if not m:
        raise RuntimeError("PyFuscation.py produced no script: " + out.stderr.strip()[:300])
    return m.group(1)


def checkRound(mod, target, workdir, baseline, analyzerFile, failures, engine="shellpy",
               declared=None):
    os.chdir(workdir)
    if engine == "shellpy":
        outFile = mod.pyfuscate(target, True, True, True, "10.10.14.5", 4444)
    else:
        outFile = runPyFuscation(target)
    stem = os.path.splitext(outFile)[0]

    with open(outFile, encoding="utf-8", errors="replace") as f:
        obf = f.read()
    with open(os.path.join(workdir, target), encoding="utf-8", errors="replace") as f:
        original = f.read()

    def fail(msg):
        failures.append(f"[{engine}: {target}] {msg}")

    # 1. variables automaticas intactas
    for v in AUTOVARS:
        want = len(re.findall(re.escape(v) + r"\b", original, re.I))
        got = len(re.findall(re.escape(v) + r"\b", obf, re.I))
        if got < want:
            fail(f"variable automatica renombrada: {v} ({want} -> {got})")

    # 2. nombres de funcion generados: no vacios, unicos, sin chocar con cmdlets
    fmap = parseMap(stem + ".functions")
    news = list(fmap.values())
    lowered = [n.lower() for n in news]
    if any(n == "" for n in news):
        fail("se genero un nombre de funcion vacio")
    dups = {n for n in lowered if lowered.count(n) > 1}
    if dups:
        fail(f"nombres de funcion duplicados: {sorted(dups)}")
    clash = sorted(set(lowered) & mod.loadPSCommands())
    if clash:
        fail(f"nombre de funcion pisa un cmdlet/alias real: {clash}")

    # 2b. cobertura: toda funcion declarada en el original tiene que haberse
    # renombrado. Sin esto, un findFUNCs que no detecte nada pasaria el resto
    # de comprobaciones sin problemas, porque no ofuscar nunca rompe el script.
    if declared is not None:
        missed = sorted(declared - {"main"} - set(k.lower() for k in fmap))
        if missed:
            fail(f"funciones declaradas que no se renombraron: {missed}")

    # 3. ningun nombre viejo suelto (powershell no distingue mayusculas)
    for old in fmap:
        left = re.findall(r"(?<![A-Za-z0-9_-])" + re.escape(old) + r"(?![A-Za-z0-9_-])",
                          obf, re.I)
        if left:
            fail(f"quedan {len(left)} usos sin renombrar de {old}")

    # 4. lo mismo para variables y parametros: un renombrado a medias deja el
    # script llamando a algo que ya no existe
    for label, mapFile in (("variable", ".variables"), ("parametro", ".parameters")):
        for old in parseMap(stem + mapFile):
            left = re.findall(re.escape(old) + r"(?![A-Za-z0-9_-])", obf, re.I)
            if left:
                fail(f"quedan {len(left)} usos sin renombrar del {label} {old.strip()!r}")

    # 5. calificadores de ambito/proveedor intactos: renombrar el nombre que
    # va antes de los dos puntos produce "Cannot find drive"
    for qualifier in ("global", "script", "local", "private", "using", "env",
                      "function", "variable"):
        want = len(re.findall(r"\$" + qualifier + r":", original, re.I))
        got = len(re.findall(r"\$" + qualifier + r":", obf, re.I))
        if got < want:
            fail(f"calificador renombrado: ${qualifier}: ({want} -> {got})")

    # 6. equivalencia funcional: para los fixtures autonomos, el script
    # ofuscado tiene que imprimir exactamente lo mismo que el original
    if target in EXECUTABLE and havePwsh():
        wantOut, _ = runScript(os.path.join(workdir, target))
        gotOut, gotErr = runScript(outFile)
        if gotOut != wantOut:
            fail(f"la salida cambio al ofuscar: {wantOut!r} -> {gotOut!r}")
        if gotErr:
            fail(f"el script ofuscado escribio en stderr: {gotErr[:200]}")

    # 7. el parser de PowerShell
    if analyzerFile:
        res = analyze(outFile, analyzerFile)
        if res.get("parseErrors"):
            fail(f"errores de parseo: {res['parseErrors'][:3]}")
        newMissing = sorted(set(n.lower() for n in res.get("missing", [])) - baseline)
        if newMissing:
            fail(f"comandos no reconocidos que no estaban en el original: {newMissing}")

    shutil.rmtree(os.path.dirname(outFile), ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=10,
                    help="pasadas de ofuscacion por script (default: 10)")
    args = ap.parse_args()

    mod = loadShellpy()
    cwd = os.getcwd()
    workdir = tempfile.mkdtemp(prefix="shellpy-test-")
    analyzerFile = None
    failures = []

    try:
        print("Preparando scripts objetivo...")
        fetchTargets(workdir)

        if havePwsh():
            analyzerFile = os.path.join(workdir, "analyze.ps1")
            with open(analyzerFile, "w") as f:
                f.write(PS_ANALYZER)
        else:
            print("  pwsh no disponible: se omite la validacion con el parser de PowerShell")

        # Baseline: comandos que el original ya deja sin resolver (powercat
        # define varias funciones en runtime con IEX).
        baseline = {}
        declared = {}
        for target in list(TARGETS) + FIXTURES:
            path = os.path.join(workdir, target)
            if analyzerFile:
                res = analyze(path, analyzerFile)
                baseline[target] = set(n.lower() for n in res.get("missing", []))
                declared[target] = set(n.lower() for n in res.get("defs", []))
            else:
                baseline[target] = set()
                declared[target] = None

        for engine in ("shellpy", "pyfuscation"):
            for target in list(TARGETS) + FIXTURES:
                print(f"\n== {engine} / {target}: {args.rounds} pasadas")
                for i in range(args.rounds):
                    before = len(failures)
                    checkRound(mod, target, workdir, baseline[target], analyzerFile,
                               failures, engine, declared[target])
                    print("  ." if len(failures) == before else "  X", end="", flush=True)
                print()
    finally:
        os.chdir(cwd)
        shutil.rmtree(workdir, ignore_errors=True)

    print()
    if failures:
        print(f"FALLOS ({len(failures)}):")
        for f in dict.fromkeys(failures):
            print("  - " + f)
        return 1
    print("OK: todas las pasadas produjeron scripts validos y coherentes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
