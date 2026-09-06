import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { realpath, readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const repoRoot = path.resolve(import.meta.dirname, "..");
const pluginName = "project-design-keeper";
const keeperSource = "sources/project-design-keeper";
const physicsName = "physics-simulation-superpowers";
const physicsSource = `sources/${physicsName}`;
const repositoryURL = "https://github.com/EverfIRE/ProjectDesign";
const publisherURL = "https://github.com/EverfIRE";
const archiveHash = ["bf32", "d41b"].join("");
const execFile = promisify(execFileCallback);
const expectedPlugins = [
  {
    name: pluginName,
    source: { source: "local", path: `./plugins/${pluginName}` },
    policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
    category: "Developer Tools",
  },
  {
    name: physicsName,
    source: { source: "local", path: `./plugins/${physicsName}` },
    policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
    category: "Developer Tools",
  },
];

async function readJSON(relativePath) {
  return JSON.parse(await readFile(path.join(repoRoot, relativePath), "utf8"));
}

async function exists(relativePath) {
  try {
    await stat(path.join(repoRoot, relativePath));
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

function assertDocumentLines(document, expectedLines, label) {
  const lines = new Set(document.split(/\r?\n/u));
  for (const expected of expectedLines) {
    assert.ok(lines.has(expected), `${label} missing exact affirmative line: ${expected}`);
  }
}

async function repositoryPaths(directory = repoRoot) {
  const results = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if ([".git", ".package", "coverage", "node_modules"].includes(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    const relative = path.relative(repoRoot, absolute).replaceAll("\\", "/");
    results.push(relative);
    if (entry.isDirectory()) results.push(...(await repositoryPaths(absolute)));
  }
  return results;
}

async function treeFiles(root, directory = root) {
  const results = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) results.push(...(await treeFiles(root, absolute)));
    if (entry.isFile()) results.push(path.relative(root, absolute).replaceAll("\\", "/"));
  }
  return results.sort();
}

function isTrackedGeneratedArtifact(entry) {
  return (
    entry.split("/").includes("artifacts") ||
    path.posix.basename(entry) === "SHA256SUMS.txt" ||
    entry.endsWith(".zip") ||
    entry.endsWith(".pyc") ||
    entry.split("/").some((part) => [".package", "__pycache__", "coverage", "node_modules", "outputs"].includes(part))
  );
}

function workflowModel(workflow) {
  const lines = workflow.split(/\r?\n/u);
  const jobsStart = lines.findIndex((line) => line === "jobs:");
  assert.notEqual(jobsStart, -1, "CI jobs section is missing");
  const jobs = {};
  for (let index = jobsStart + 1; index < lines.length; index += 1) {
    const match = lines[index].match(/^  ([A-Za-z0-9][A-Za-z0-9-]*):\s*$/u);
    if (!match) continue;
    const start = index + 1;
    while (index + 1 < lines.length && !/^  [A-Za-z0-9][A-Za-z0-9-]*:\s*$/u.test(lines[index + 1])) index += 1;
    const block = lines.slice(start, index + 1);
    const value = (key) => block.find((line) => line.match(new RegExp(`^    ${key}:\\s*\\S`, "u")))?.replace(new RegExp(`^    ${key}:\\s*`, "u"), "");
    const steps = [];
    for (let step = 0; step < block.length; step += 1) {
      if (!block[step].startsWith("      - ")) continue;
      const startStep = step;
      while (step + 1 < block.length && !block[step + 1].startsWith("      - ")) step += 1;
      const stepLines = block.slice(startStep, step + 1);
      const fields = {};
      const first = stepLines[0].slice("      - ".length);
      if (first.includes(":")) {
        const separator = first.indexOf(":");
        fields[first.slice(0, separator)] = first.slice(separator + 1).trimStart();
      }
      for (let lineIndex = 1; lineIndex < stepLines.length; lineIndex += 1) {
        const field = stepLines[lineIndex].match(/^        ([A-Za-z-]+):\s*(.*)$/u);
        if (!field) continue;
        const [, key, value] = field;
        if (value === "|") {
          const content = [];
          while (lineIndex + 1 < stepLines.length) {
            const next = stepLines[lineIndex + 1];
            if (next.startsWith("          ")) {
              lineIndex += 1;
              content.push(next.slice(10));
            } else if (next === "" && stepLines[lineIndex + 2]?.startsWith("          ")) {
              lineIndex += 1;
              content.push("");
            } else break;
          }
          fields[key] = content.join("\n");
        } else if (value === "") {
          const nested = {};
          while (lineIndex + 1 < stepLines.length && stepLines[lineIndex + 1].startsWith("          ")) {
            lineIndex += 1;
            const nestedField = stepLines[lineIndex].match(/^          ([A-Za-z0-9_-]+):\s*(.*)$/u);
            if (nestedField) nested[nestedField[1]] = nestedField[2];
          }
          fields[key] = nested;
        } else fields[key] = value;
      }
      steps.push(fields);
    }
    jobs[match[1]] = { needs: value("needs"), runsOn: value("runs-on"), block: block.join("\n"), steps };
  }
  return jobs;
}

function workflowStep(job, name) {
  const matches = job.steps.filter((candidate) => candidate.name === name);
  assert.equal(matches.length, 1, `CI step ${name} must occur exactly once`);
  return matches[0];
}

function assertStepContract(job, name, expected) {
  assert.deepEqual(workflowStep(job, name), { name, ...expected }, `CI step ${name} changed`);
}

function assertNamedStepConditions(jobs) {
  const names = [];
  for (const [jobName, job] of Object.entries(jobs)) {
    for (const step of job.steps) {
      assert.equal(typeof step.name, "string", `CI ${jobName} has an unnamed load-bearing step`);
      assert.notEqual(step.name, "", `CI ${jobName} has an empty step name`);
      if (step.if !== undefined) assert.equal(step.if, "runner.os == 'Windows'", `CI step ${step.name} has an unapproved condition`);
      names.push(step.name);
    }
  }
  assert.equal(new Set(names).size, names.length, "CI load-bearing step names must be globally unique");
}

// These readable literals are the CI contract. `python` is intentionally exact:
// wrappers, alternate interpreter spellings, comments, flags, or shell operators require review.
const keeperInstalledSmokeRun = `Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ("KeeperCiFixtureNative" -as [type])) {
  Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Microsoft.Win32.SafeHandles;

public static class KeeperCiFixtureNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string path,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out BY_HANDLE_FILE_INFORMATION information);

    public static string GetDirectoryIdentity(string path)
    {
        const uint FILE_READ_ATTRIBUTES = 0x0080;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint FILE_SHARE_DELETE = 0x00000004;
        const uint OPEN_EXISTING = 3;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

        using (SafeFileHandle handle = CreateFileW(
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open CI fixture directory without following reparse points");
            }
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to identify CI fixture directory");
            }
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                throw new InvalidOperationException("CI fixture path must be a non-reparse directory");
            }
            return string.Format(
                CultureInfo.InvariantCulture,
                "{0:x8}:{1:x8}:{2:x8}",
                information.VolumeSerialNumber,
                information.FileIndexHigh,
                information.FileIndexLow);
        }
    }
}
"@
}

function Assert-NoReparsePathComponents {
  param([string]$Label, [string]$Path)
  $root = [IO.Path]::GetPathRoot($Path)
  if ([string]::IsNullOrWhiteSpace($root)) {
    throw "$Label must be an absolute path"
  }
  $current = $root
  $remainder = $Path.Substring($root.Length)
  foreach ($component in $remainder.Split([char[]]@('\\', '/'), [StringSplitOptions]::RemoveEmptyEntries)) {
    $current = [IO.Path]::Combine($current, $component)
    $item = Get-Item -LiteralPath $current -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Label contains a reparse point: $current"
    }
  }
}

$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd([char[]]@('\\', '/'))
Assert-NoReparsePathComponents -Label 'RUNNER_TEMP' -Path $runnerTemp
$fixture = [IO.Path]::GetFullPath((Join-Path $runnerTemp ("keeper-installed-smoke-" + [guid]::NewGuid().ToString('N'))))
if (-not [string]::Equals([IO.Path]::GetDirectoryName($fixture), $runnerTemp, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Installed smoke fixture escaped RUNNER_TEMP"
}
$runnerTempIdentity = [KeeperCiFixtureNative]::GetDirectoryIdentity($runnerTemp)
$fixtureIdentity = $null
$smokeSucceeded = $false
try {
  New-Item -ItemType Directory -Path $fixture | Out-Null
  Assert-NoReparsePathComponents -Label 'CI installed smoke fixture' -Path $fixture
  $fixtureIdentity = [KeeperCiFixtureNative]::GetDirectoryIdentity($fixture)
  npm run smoke:installed -- "\${{ github.workspace }}\\sources\\project-design-keeper\\.package\\project-design-keeper" "$fixture"
  if ($LASTEXITCODE -ne 0) { throw "Installed package smoke failed with exit code $LASTEXITCODE" }
  $smokeSucceeded = $true
}
finally {
  if (Test-Path -LiteralPath $fixture) {
    if (-not $smokeSucceeded) {
      Write-Warning "Installed smoke failed; preserving evidence at $fixture"
    }
    else {
      if ($null -eq $fixtureIdentity) {
        throw "CI installed smoke fixture identity was never captured; preserving the ambiguous path at $fixture"
      }
      if (-not [string]::Equals([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($fixture)), $runnerTemp, [StringComparison]::OrdinalIgnoreCase)) {
        throw "CI installed smoke fixture no longer has the verified direct parent; preserving $fixture"
      }
      Assert-NoReparsePathComponents -Label 'RUNNER_TEMP' -Path $runnerTemp
      Assert-NoReparsePathComponents -Label 'CI installed smoke fixture' -Path $fixture
      $currentRunnerTempIdentity = [KeeperCiFixtureNative]::GetDirectoryIdentity($runnerTemp)
      if ($currentRunnerTempIdentity -cne $runnerTempIdentity) {
        throw "RUNNER_TEMP identity changed before CI fixture cleanup; preserving $fixture"
      }
      $currentFixtureIdentity = [KeeperCiFixtureNative]::GetDirectoryIdentity($fixture)
      if ($currentFixtureIdentity -cne $fixtureIdentity) {
        throw "CI installed smoke fixture identity changed before cleanup; preserving $fixture"
      }
      $fixtureEnumerator = [IO.Directory]::EnumerateFileSystemEntries($fixture).GetEnumerator()
      try {
        $fixtureHasEntry = $fixtureEnumerator.MoveNext()
      }
      finally {
        if ($fixtureEnumerator -is [IDisposable]) { $fixtureEnumerator.Dispose() }
      }
      if ($fixtureHasEntry) {
        throw "CI installed smoke fixture is not empty after successful smoke; preserving evidence at $fixture"
      }
      $currentFixtureIdentity = [KeeperCiFixtureNative]::GetDirectoryIdentity($fixture)
      if ($currentFixtureIdentity -cne $fixtureIdentity) {
        throw "CI installed smoke fixture identity changed during bounded cleanup validation; preserving $fixture"
      }
      $currentRunnerTempIdentity = [KeeperCiFixtureNative]::GetDirectoryIdentity($runnerTemp)
      if ($currentRunnerTempIdentity -cne $runnerTempIdentity) {
        throw "RUNNER_TEMP identity changed during CI fixture cleanup validation; preserving $fixture"
      }
      [IO.Directory]::Delete($fixture, $false)
    }
  }
}`;

const physicsJsonRun = `set -euo pipefail
while IFS= read -r -d '' file; do
  case "$file" in
    *.json) python -m json.tool "$file" > /dev/null ;;
  esac
done < <(git ls-files -z -- sources/physics-simulation-superpowers)`;

const physicsSuiteRun = `set -euo pipefail
standalone="$(mktemp -d "$RUNNER_TEMP/physics-ci-XXXXXX")"
case "$standalone" in "$RUNNER_TEMP"/physics-ci-*) ;; *) exit 1 ;; esac
trap 'rm -rf "$standalone"' EXIT
git -C "$GITHUB_WORKSPACE" archive --format=tar HEAD sources/physics-simulation-superpowers | tar -C "$standalone" -xf -
git -C "$GITHUB_WORKSPACE" archive --format=tar HEAD plugins/physics-simulation-superpowers | tar -C "$standalone" -xf -
test ! -e "$standalone/sources/physics-simulation-superpowers/.git"
git -C "$standalone" init -q
git -C "$standalone" config core.autocrlf false
git -C "$standalone" config user.name 'CI'
git -C "$standalone" config user.email 'ci@example.invalid'
git -C "$standalone" add --all
git -C "$standalone" commit -qm 'physics source snapshot'
(
  cd "$standalone/sources/physics-simulation-superpowers"
  python -m unittest discover -s tests -p "test_*.py" -q
  python -m unittest tests.test_repository_distribution -q
)`;

const physicsValidationRun = `set -euo pipefail
python tools/validate_codex_plugin.py plugin sources/physics-simulation-superpowers
python tools/validate_codex_plugin.py plugin plugins/physics-simulation-superpowers
mapfile -t skills < <(find plugins/physics-simulation-superpowers/skills -mindepth 1 -maxdepth 1 -type d | sort)
test "\${#skills[@]}" -eq 25
for skill in "\${skills[@]}"; do python tools/validate_codex_plugin.py skill "$skill"; done`;

const physicsRegenerationRun = `set -euo pipefail
temporary="$(mktemp -d "$RUNNER_TEMP/physics-release-XXXXXX")"
case "$temporary" in "$RUNNER_TEMP"/physics-release-*) ;; *) exit 1 ;; esac
trap 'rm -rf "$temporary"' EXIT
python sources/physics-simulation-superpowers/scripts/package_plugin.py --source sources/physics-simulation-superpowers --archive "$temporary/release.zip" --install-dir "$temporary/generated"
python - "$temporary/generated" plugins/physics-simulation-superpowers <<'PY'
import sys
from pathlib import Path
expected, committed = map(Path, sys.argv[1:])
def entries(root):
    result = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise SystemExit(f"non-regular release entry: {relative}")
        result[relative] = ("file", path.read_bytes()) if path.is_file() else ("directory", None)
    return result
if entries(expected) != entries(committed):
    raise SystemExit("committed physics release does not exactly match generated release")
PY`;

const physicsGitModesRun = `set -euo pipefail
! git ls-files -s -- plugins/project-design-keeper plugins/physics-simulation-superpowers | awk '$1 == "120000" { found=1 } END { exit found ? 0 : 1 }'`;

const physicsArtifactsRun = `set -euo pipefail
violations=0
while IFS= read -r file; do
  case "$file" in
    *.zip|SHA256SUMS.txt|*/SHA256SUMS.txt|artifacts|*/artifacts|artifacts/*|*/artifacts/*|sources/physics-simulation-superpowers/outputs/*)
      printf 'tracked generated artifact: %s\\n' "$file"
      violations=1
      ;;
  esac
done < <(git ls-files)
test "$violations" -eq 0`;

function workflowJob(workflow, jobName) {
  const escapedName = jobName.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const jobPattern = new RegExp(
    `^  ${escapedName}:\\s*$([\\s\\S]*?)(?=^  [A-Za-z0-9][A-Za-z0-9-]*:\\s*$|(?![\\s\\S]))`,
    "mu",
  );
  const match = workflow.match(jobPattern);
  assert.ok(match, `CI job ${jobName} is missing`);
  return match[1];
}

function workflowJobNames(workflow) {
  const jobsOffset = workflow.indexOf("jobs:\n");
  assert.notEqual(jobsOffset, -1, "CI jobs section is missing");
  const jobs = workflow.slice(jobsOffset + "jobs:\n".length);
  return Array.from(jobs.matchAll(/^  ([A-Za-z0-9][A-Za-z0-9-]*):\s*$/gmu), (match) => match[1]);
}

test("repo marketplace exposes both isolated installable releases", async () => {
  const marketplace = await readJSON(".agents/plugins/marketplace.json");
  assert.equal(marketplace.name, "project-design");
  assert.equal(marketplace.interface.displayName, "ProjectDesign");
  assert.deepEqual(marketplace.plugins, expectedPlugins);
});

test("marketplace paths remain inside the repository and point to manifests", async () => {
  const marketplace = await readJSON(".agents/plugins/marketplace.json");
  const resolvedRepoRoot = await realpath(repoRoot);

  for (const plugin of marketplace.plugins) {
    assert.match(plugin.source.path, /^\.\/plugins\//u);
    const releaseRoot = path.resolve(repoRoot, plugin.source.path);
    const resolvedReleaseRoot = await realpath(releaseRoot);
    const relativeReleaseRoot = path.relative(resolvedRepoRoot, resolvedReleaseRoot);
    assert.equal(
      relativeReleaseRoot === "" || (!relativeReleaseRoot.startsWith("..") && !path.isAbsolute(relativeReleaseRoot)),
      true,
      `${plugin.name} resolves outside the repository`,
    );

    const manifest = path.join(resolvedReleaseRoot, ".codex-plugin", "plugin.json");
    const resolvedManifest = await realpath(manifest);
    const relativeManifest = path.relative(resolvedRepoRoot, resolvedManifest);
    assert.equal(
      !relativeManifest.startsWith("..") && !path.isAbsolute(relativeManifest),
      true,
      `${plugin.name} manifest resolves outside the repository`,
    );
    assert.equal((await stat(resolvedManifest)).isFile(), true);
  }
});

test("plugin source and release roots do not overlap", async () => {
  const roots = await Promise.all(
    [keeperSource, physicsSource, ...expectedPlugins.map((plugin) => plugin.source.path)].map(async (root) => ({
      root,
      resolved: await realpath(path.resolve(repoRoot, root)),
    })),
  );

  for (const [index, current] of roots.entries()) {
    for (const other of roots.slice(index + 1)) {
      const currentInsideOther = path.relative(other.resolved, current.resolved);
      const otherInsideCurrent = path.relative(current.resolved, other.resolved);
      assert.notEqual(current.resolved, other.resolved, `${current.root} aliases ${other.root}`);
      assert.equal(
        currentInsideOther === "" || currentInsideOther.startsWith("..") || path.isAbsolute(currentInsideOther),
        true,
        `${current.root} is nested inside ${other.root}`,
      );
      assert.equal(
        otherInsideCurrent === "" || otherInsideCurrent.startsWith("..") || path.isAbsolute(otherInsideCurrent),
        true,
        `${other.root} is nested inside ${current.root}`,
      );
    }
  }
});

test("physics release excludes development trees and tracked generated artifacts", async () => {
  for (const excluded of ["tests", "evaluations", "docs", ".superpowers", "outputs"]) {
    assert.equal(await exists(`plugins/${physicsName}/${excluded}`), false, `${excluded} is in the physics release`);
  }

  const { stdout } = await execFile("git", ["ls-files", "-z"], { cwd: repoRoot });
  const tracked = stdout.split("\0").filter(Boolean);
  const generated = tracked.filter(isTrackedGeneratedArtifact);
  assert.deepEqual(generated, []);
});

test("tracked generated-artifact predicate rejects the exact checksum asset name", () => {
  assert.equal(isTrackedGeneratedArtifact("release/SHA256SUMS.txt"), true);
  assert.equal(isTrackedGeneratedArtifact("release/sha256sums.txt"), false);
});

test("tracked generated-artifact predicate rejects nested artifact directories", () => {
  for (const entry of ["artifacts", "nested/artifacts", "artifacts/a.txt", "sources/physics/artifacts/a.txt", "plugins/physics/artifacts/a.txt"]) {
    assert.equal(isTrackedGeneratedArtifact(entry), true, entry);
  }
});

test("public release paths have no Git symlink entries", async () => {
  const { stdout } = await execFile("git", ["ls-files", "-s", "--", "plugins/project-design-keeper", "plugins/physics-simulation-superpowers"], { cwd: repoRoot });
  const symlinks = stdout.split("\n").filter((line) => line.startsWith("120000 "));
  assert.deepEqual(symlinks, []);
});

test("legacy singular source root is absent", async () => {
  assert.equal(await exists("source"), false);
  assert.equal(await exists(`${keeperSource}/src/index.ts`), true);
  assert.equal(await exists(`${keeperSource}/test`), true);
  assert.equal(await exists(`${keeperSource}/scripts/package-plugin.mjs`), true);
});

test("README explains source/release separation and both plugin activations", async () => {
  const readme = await readFile(path.join(repoRoot, "README.md"), "utf8");
  assertDocumentLines(readme, [
    "| `sources/project-design-keeper/` | Hand-maintained TypeScript source, tests, build scripts, and package metadata for Keeper. |",
    "| `sources/physics-simulation-superpowers/` | Hand-maintained physics skills, research resources, tests, validators, and packaging source. |",
    "| `plugins/project-design-keeper/` | Deterministic, installable Keeper release tree. |",
    "| `plugins/physics-simulation-superpowers/` | Deterministic, installable physics release tree. |",
    "codex plugin marketplace add EverfIRE/ProjectDesign --ref main",
    "codex plugin marketplace upgrade project-design",
    "1. Restart Codex so it reloads the marketplace.",
    "2. Open the Plugins Directory and install `project-design-keeper`, `physics-simulation-superpowers`, or both.",
    "3. Create a new task after installation; the task that performed the installation does not hot-refresh newly installed plugins.",
    "4. Activate the installed plugin in that new task with `@project-design-keeper` or `@physics-simulation-superpowers`.",
    "Physics Simulation Superpowers is Unreal Engine / Chaos first. Its physics tasks 17–23 concentrate on Unreal Engine; other engines remain concise unless their physics systems are unusually strong, such as Jolt, PhysX, Rapier, or Box2D.",
  ], "README");
});

test("physics release notes pin identity, artifacts, and source provenance", async () => {
  const notes = await readFile(path.join(repoRoot, "docs", "releases", "physics-simulation-superpowers-0.1.0.md"), "utf8");
  assertDocumentLines(notes, [
    "- Tag: `physics-simulation-superpowers-v0.1.0`",
    "- ZIP asset: `physics-simulation-superpowers-0.1.0.zip`",
    "- Checksum asset: `SHA256SUMS.txt`",
    "- Imported source provenance: commit `690f0295d406a4007d50fa6133dc4671345092ad` from branch `feat/physics-simulation-superpowers`",
  ], "release notes");
});

test("physics release notes define the 25-skill scope and Unreal-first engine policy", async () => {
  const notes = await readFile(path.join(repoRoot, "docs", "releases", "physics-simulation-superpowers-0.1.0.md"), "utf8");
  assertDocumentLines(notes, [
    "The plugin contains 25 skills covering:",
    "- real-time physics architecture and development;",
    "- debugging, profiling, testing, and evidence analysis;",
    "- research discovery, paper review, and controlled experiment design;",
    "- isolated, reproducible paper and simulation artifact reproduction;",
    "Unreal Engine / Chaos is the flagship target. Physics tasks 17–23 prioritize Unreal Engine; other engines are treated concisely unless they provide unusually strong physics systems, including focused native coverage for Jolt, PhysX, Rapier, and Box2D.",
  ], "release notes");
});

test("physics release notes cover installation, validation, and generated-asset safety", async () => {
  const notes = await readFile(path.join(repoRoot, "docs", "releases", "physics-simulation-superpowers-0.1.0.md"), "utf8");
  assertDocumentLines(notes, [
    "codex plugin marketplace add EverfIRE/ProjectDesign --ref main",
    "codex plugin marketplace upgrade project-design",
    "Restart Codex, open the Plugins Directory, and install `physics-simulation-superpowers`. Create a new task after installation and activate the plugin with `@physics-simulation-superpowers`; the installation task itself does not hot-refresh the plugin.",
    "The ZIP and checksum are generated from verified merged source as GitHub Release assets. They are not tracked repository files.",
    "- root distribution suite: 20 tests passed;",
    "- complete physics suite: 627 tests ran on Python 3.11 with 1 intentional skip, and 627 tests ran on Python 3.14 with 1 intentional skip;",
    "- physics repository source/release parity: 6 tests passed on both Python 3.11 and Python 3.14;",
    "- repository validator: both physics plugin roots and all 25 released skills passed;",
    "- tracked physics JSON validation: 56 files parsed;",
    "- deterministic Windows release-source/install tree digest after regeneration: `6981a689b69729cbcf98ba7cdaf529a8610de4b71bbac606bcb4f0d6002b514d`.",
    "## Verify the downloaded SHA-256",
    String.raw`$expected = ((Get-Content .\SHA256SUMS.txt -Raw) -split '\s+')[0].ToLowerInvariant()`,
    String.raw`$actual = (Get-FileHash .\physics-simulation-superpowers-0.1.0.zip -Algorithm SHA256).Hash.ToLowerInvariant()`,
    "if ($actual -ne $expected) { throw \"SHA-256 mismatch: expected $expected, got $actual\" }",
  ], "release notes");
});

test("physics source snapshot is complete", async () => {
  assert.equal(await exists(`${physicsSource}/.codex-plugin/plugin.json`), true);
  assert.equal(await exists(`${physicsSource}/skills/unreal-chaos-physics/SKILL.md`), true);
  assert.equal(await exists(`${physicsSource}/tests/test_packaging.py`), true);
  assert.equal(await exists(`${physicsSource}/evaluations`), true);
  const manifest = await readJSON(`${physicsSource}/.codex-plugin/plugin.json`);
  assert.equal(manifest.name, physicsName);
  assert.equal(manifest.version, "0.1.0");
});

test("release and complete source are separate trees", async () => {
  assert.equal(await exists(`${keeperSource}/src/index.ts`), true);
  assert.equal(await exists(`${keeperSource}/test`), true);
  assert.equal(await exists(`${keeperSource}/scripts/package-plugin.mjs`), true);
  assert.equal(await exists(`plugins/${pluginName}/src`), false);
  assert.equal(await exists(`plugins/${pluginName}/test`), false);
  assert.equal(await exists(`plugins/${pluginName}/scripts`), false);

  const releasePackage = await readJSON(`plugins/${pluginName}/package.json`);
  assert.equal(releasePackage.name, pluginName);
  assert.equal(releasePackage.version, "1.0.2");
  assert.equal(Object.hasOwn(releasePackage, "scripts"), false);
  assert.equal(Object.hasOwn(releasePackage, "devDependencies"), false);
  const releaseSkill = await readFile(path.join(repoRoot, "plugins", pluginName, "skills", "distill-project-design", "SKILL.md"), "utf8");
  assert.match(releaseSkill, /codex plugin marketplace upgrade project-design-keeper/u);
  assert.doesNotMatch(releaseSkill, /codex plugin upgrade project-design-keeper/u);
});

test("committed release exactly matches the source packager output", async () => {
  const sourceRoot = path.join(repoRoot, keeperSource);
  await execFile(process.execPath, [path.join(sourceRoot, "scripts/package-plugin.mjs")], {
    cwd: sourceRoot,
  });

  const builtRoot = path.join(sourceRoot, ".package", pluginName);
  const releaseRoot = path.join(repoRoot, "plugins", pluginName);
  const builtFiles = await treeFiles(builtRoot);
  const releaseFiles = await treeFiles(releaseRoot);
  assert.deepEqual(releaseFiles, builtFiles);
  for (const relativePath of builtFiles) {
    assert.deepEqual(
      await readFile(path.join(releaseRoot, relativePath)),
      await readFile(path.join(builtRoot, relativePath)),
      `${relativePath} differs from the source packager output`,
    );
  }
});

test("published plugin metadata uses stable repository URLs", async () => {
  for (const manifestPath of [
    `plugins/${pluginName}/.codex-plugin/plugin.json`,
    `${keeperSource}/.codex-plugin/plugin.json`,
  ]) {
    const manifest = await readJSON(manifestPath);
    assert.equal(manifest.name, pluginName);
    assert.equal(manifest.version, "1.0.2");
    assert.equal(manifest.interface.displayName, "ProjectDesignKeeper");
    assert.equal(manifest.author.url, publisherURL);
    assert.equal(manifest.homepage, repositoryURL);
    assert.equal(manifest.repository, repositoryURL);
    assert.equal(manifest.interface.websiteURL, repositoryURL);
  }

  const sourcePackage = await readJSON(`${keeperSource}/package.json`);
  assert.deepEqual(sourcePackage.author, { name: "EverfIRE", url: publisherURL });
  assert.equal(sourcePackage.homepage, `${repositoryURL}#readme`);
  assert.deepEqual(sourcePackage.repository, {
    type: "git",
    url: `${repositoryURL}.git`,
    directory: keeperSource,
  });
  assert.deepEqual(sourcePackage.bugs, { url: `${repositoryURL}/issues` });
});

test("CI rebuilds the runtime before distribution checks and covers Linux", async () => {
  const workflow = await readFile(path.join(repoRoot, ".github", "workflows", "ci.yml"), "utf8");
  const install = workflow.indexOf("npm ci");
  const build = workflow.indexOf("npm run build");
  const distribution = workflow.indexOf("node --test test/distribution.test.mjs");
  assert.ok(install >= 0 && build > install && distribution > build);
  assert.match(workflow, /git diff --exit-code -- sources\/project-design-keeper\/dist\/index\.js plugins\/project-design-keeper\/dist\/index\.js/u);
  assert.match(workflow, /os:\s*\[windows-latest, ubuntu-latest\]/u);
});

function assertWorkflowContracts(workflow) {
  const jobs = workflowModel(workflow);
  assert.deepEqual(Object.keys(jobs), [
    "project-design-keeper",
    "physics-simulation-superpowers",
    "distribution",
  ]);
  assertNamedStepConditions(jobs);
  const keeper = jobs["project-design-keeper"];
  const physics = jobs["physics-simulation-superpowers"];
  const distribution = jobs.distribution;

  assert.equal(keeper.runsOn, "${{ matrix.os }}");
  assert.match(keeper.block, /sources\/project-design-keeper/u);
  assert.match(keeper.block, /windows-latest/u);
  assert.match(keeper.block, /ubuntu-latest/u);
  assertStepContract(keeper, "Checkout Keeper source", { uses: "actions/checkout@v4" });
  assertStepContract(keeper, "Configure Keeper test temp on Windows", {
    if: "runner.os == 'Windows'",
    shell: "pwsh",
    run: `"TEMP=$env:RUNNER_TEMP" >> $env:GITHUB_ENV
"TMP=$env:RUNNER_TEMP" >> $env:GITHUB_ENV`,
  });
  assertStepContract(keeper, "Set up Keeper Node.js 20", {
    uses: "actions/setup-node@v4",
    with: {
      "node-version": "20",
      cache: "npm",
      "cache-dependency-path": "sources/project-design-keeper/package-lock.json",
    },
  });
  assertStepContract(keeper, "Install Keeper dependencies", { run: "npm ci" });
  assertStepContract(keeper, "Typecheck Keeper source", { run: "npm run typecheck" });
  assertStepContract(keeper, "Build Keeper runtime", { run: "npm run build" });
  assertStepContract(keeper, "Verify Keeper repository distribution", {
    if: "runner.os == 'Windows'",
    "working-directory": ".",
    run: "node --test test/distribution.test.mjs",
  });
  assertStepContract(keeper, "Verify Keeper runtime parity", {
    if: "runner.os == 'Windows'",
    "working-directory": ".",
    run: "git diff --exit-code -- sources/project-design-keeper/dist/index.js plugins/project-design-keeper/dist/index.js",
  });
  assertStepContract(keeper, "Run Keeper CI tests", {
    run: "npm run test:ci",
    env: { PLUGIN_DATA: "${{ runner.temp }}/keeper-test-ci" },
  });
  assertStepContract(keeper, "Run Keeper coverage", {
    if: "runner.os == 'Windows'",
    run: "npm run test:coverage",
    env: { PLUGIN_DATA: "${{ runner.temp }}/keeper-coverage" },
  });
  assertStepContract(keeper, "Run Keeper smoke test", {
    run: "npm run smoke",
    env: { PLUGIN_DATA: "${{ runner.temp }}/keeper-smoke" },
  });
  assertStepContract(keeper, "Run Keeper performance tests", {
    if: "runner.os == 'Windows'",
    run: "npm run test:perf",
    env: { PLUGIN_DATA: "${{ runner.temp }}/keeper-perf" },
  });
  assertStepContract(keeper, "Verify Keeper package", {
    run: "npm run package:verify",
    env: { PLUGIN_DATA: "${{ runner.temp }}/keeper-package-verify" },
  });
  assertStepContract(keeper, "Smoke installed Keeper package", {
    if: "runner.os == 'Windows'",
    shell: "pwsh",
    run: keeperInstalledSmokeRun,
  });

  assert.equal(physics.runsOn, "ubuntu-latest");
  assertStepContract(physics, "Checkout physics source", { uses: "actions/checkout@v4" });
  assertStepContract(physics, "Set up physics Python 3.11", {
    uses: "actions/setup-python@v5",
    with: { "python-version": "'3.11'" },
  });
  assertStepContract(physics, "Parse every tracked physics JSON document", { shell: "bash", run: physicsJsonRun });
  assertStepContract(physics, "Run the full physics suite in a disposable standalone repository", { shell: "bash", run: physicsSuiteRun });
  assertStepContract(physics, "Validate physics plugins and every released skill", { shell: "bash", run: physicsValidationRun });
  assertStepContract(physics, "Regenerate and compare the complete physics release tree", { shell: "bash", run: physicsRegenerationRun });
  assertStepContract(physics, "Reject public release symlink modes", { shell: "bash", run: physicsGitModesRun });
  assertStepContract(physics, "Reject tracked physics release artifacts", { shell: "bash", run: physicsArtifactsRun });
  assert.doesNotMatch(physics.block, /\.codex[\\/]skills/u);

  assert.equal(distribution.needs, "[project-design-keeper, physics-simulation-superpowers]");
  assert.equal(distribution.runsOn, "ubuntu-latest");
  assertStepContract(distribution, "Checkout repository distribution", { uses: "actions/checkout@v4" });
  assertStepContract(distribution, "Set up distribution Node.js 22", {
    uses: "actions/setup-node@v4",
    with: { "node-version": "22" },
  });
  assertStepContract(distribution, "Run repository distribution contract", {
    run: "node --test test/distribution.test.mjs",
  });
}

test("CI verifies both plugins and repository distribution independently", async () => {
  const workflow = await readFile(path.join(repoRoot, ".github", "workflows", "ci.yml"), "utf8");
  assertWorkflowContracts(workflow);
});

test("exact CI step contracts reject every reviewed command neutralization", async () => {
  const workflow = await readFile(path.join(repoRoot, ".github", "workflows", "ci.yml"), "utf8");
  const replaceOnce = (label, before, after) => {
    const offset = workflow.indexOf(before);
    assert.notEqual(offset, -1, `${label} mutation target is missing`);
    assert.equal(workflow.indexOf(before, offset + before.length), -1, `${label} mutation target is ambiguous`);
    return `${workflow.slice(0, offset)}${after}${workflow.slice(offset + before.length)}`;
  };
  const sourceValidator = "python tools/validate_codex_plugin.py plugin sources/physics-simulation-superpowers";
  const releaseValidator = "python tools/validate_codex_plugin.py plugin plugins/physics-simulation-superpowers";
  const skillLoop = 'for skill in "${skills[@]}"; do python tools/validate_codex_plugin.py skill "$skill"; done';
  const mutations = [
    ["false-and-group", replaceOnce("false-and-group", `          ${sourceValidator}`, `          false && ( ${sourceValidator} )`)],
    ["skipped-process-substitution", replaceOnce("skipped-process-substitution", `          ${releaseValidator}`, `          true || cat < <(${releaseValidator})`)],
    ["zero-loop", replaceOnce("zero-loop", `          ${skillLoop}`, `          for skill in; do python tools/validate_codex_plugin.py skill "$skill"; done`)],
    [
      "if-false",
      replaceOnce(
        "if-false",
        "      - name: Validate physics plugins and every released skill\n        shell: bash",
        "      - name: Validate physics plugins and every released skill\n        if: false\n        shell: bash",
      ),
    ],
    ["unused-function", replaceOnce("unused-function", `          ${sourceValidator}`, `          validate_source() { ${sourceValidator}; }`)],
    ["after-exit", replaceOnce("after-exit", `          ${sourceValidator}`, `          exit 0\n          ${sourceValidator}`)],
    ["failed-pipeline", replaceOnce("failed-pipeline", `          ${sourceValidator}`, `          false | ${sourceValidator}`)],
    ["unquoted-argument-suffix", replaceOnce("unquoted-argument-suffix", sourceValidator, `${sourceValidator}#ignored`)],
    ["run-comment", replaceOnce("run-comment", `          ${sourceValidator}`, `          ${sourceValidator}\n          # exact contract changed`)],
    [
      "installed-smoke-middle",
      replaceOnce(
        "installed-smoke-middle",
        "                [IO.Directory]::Delete($fixture, $false)",
        "                Write-Output 'fixture cleanup neutralized'",
      ),
    ],
    [
      "required-help",
      replaceOnce(
        "required-help",
        "      - name: Run repository distribution contract\n        run: node --test test/distribution.test.mjs",
        "      - name: Run repository distribution contract\n        run: node --test test/distribution.test.mjs --help",
      ),
    ],
  ];

  for (const [label, mutated] of mutations) {
    assert.throws(() => assertWorkflowContracts(mutated), /CI step|unapproved condition/u, `${label} must fail its exact step contract`);
  }
});

test("public distribution contains no generated hash suffix", async () => {
  const paths = await repositoryPaths();
  const hashSuffixed = paths.filter((entry) =>
    entry.split("/").some((part) => /-[a-f0-9]{8}(?:\.|$)/iu.test(part)),
  );
  assert.deepEqual(hashSuffixed, []);

  for (const relativePath of paths) {
    const absolute = path.join(repoRoot, relativePath);
    if (!(await stat(absolute)).isFile()) continue;
    const bytes = await readFile(absolute);
    assert.equal(
      bytes.toString("utf8").toLowerCase().includes(archiveHash.toLowerCase()),
      false,
      `${relativePath} contains the generated archive hash`,
    );
  }
});
