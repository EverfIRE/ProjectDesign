# ProjectDesign

ProjectDesign is a two-plugin Codex monorepo. It publishes Project Design Keeper for maintaining reusable project-design context and Physics Simulation Superpowers for evidence-driven physics development, research, analysis, and paper reproduction.

## Plugins

| Plugin | Purpose | Activate in a new task |
| --- | --- | --- |
| `project-design-keeper` | Distills repository evidence into validated design documentation and reusable project context. | `@project-design-keeper` |
| `physics-simulation-superpowers` | Develops, investigates, evaluates, and reproduces real-time physics simulations. | `@physics-simulation-superpowers` |

Physics Simulation Superpowers is Unreal Engine / Chaos first. Its physics tasks 17–23 concentrate on Unreal Engine; other engines remain concise unless their physics systems are unusually strong, such as Jolt, PhysX, Rapier, or Box2D.

## Install from the Codex plugin marketplace

Add this repository's `project-design` marketplace at `main`, or upgrade the existing marketplace registration:

```powershell
codex plugin marketplace add EverfIRE/ProjectDesign --ref main
codex plugin marketplace upgrade project-design
```

Then complete the Codex UI steps:

1. Restart Codex so it reloads the marketplace.
2. Open the Plugins Directory and install `project-design-keeper`, `physics-simulation-superpowers`, or both.
3. Create a new task after installation; the task that performed the installation does not hot-refresh newly installed plugins.
4. Activate the installed plugin in that new task with `@project-design-keeper` or `@physics-simulation-superpowers`.

You can then invoke a plugin skill directly, for example `$distill-project-design`, `$unreal-chaos-physics`, `$surveying-real-time-physics-research`, or `$reproducing-simulation-papers`.

## Keeper settings (1.1.0)

Ask Keeper “打开 Keeper 设置” to open its clickable local browser panel. The panel contains an **Easy 模式** switch and a **单次更新合计上限** input (1–64 MiB; default 8). Settings persist for the current user's Keeper installation across projects and upgrades. Save applies to the next operation without restarting.

Easy skips Keeper's human confirmation prompts while preserving automatic validation, evidence, path, signature, expiry, concurrency and recovery checks. It has no independent single-file write cap; final file contents must fit the configured aggregate limit. Normal mode remains the default and retains its 2 MiB single-file cap. Large preview diffs are available in complete authenticated pages through `read_preview`. Changing settings requires a fresh preview. Host tool permissions are unaffected.

The panel runs on loopback only and expires after 15 minutes. Use the browser page opened by Keeper to edit; the returned tokenless URL is read-only in a different browser session. No tool saves settings on the model's behalf.

## Repository layout and maintenance boundary

| Path | Purpose |
| --- | --- |
| `.agents/plugins/marketplace.json` | The `project-design` marketplace catalog for both plugins. |
| `sources/project-design-keeper/` | Hand-maintained TypeScript source, tests, build scripts, and package metadata for Keeper. |
| `sources/physics-simulation-superpowers/` | Hand-maintained physics skills, research resources, tests, validators, and packaging source. |
| `plugins/project-design-keeper/` | Deterministic, installable Keeper release tree. |
| `plugins/physics-simulation-superpowers/` | Deterministic, installable physics release tree. |
| `test/distribution.test.mjs` | Repository-wide source/release, marketplace, artifact, and CI contracts. |

For plugin content, `sources/*` is the only hand-maintained source of release bytes. The `plugins/*` directories are deterministic installable outputs produced from their matching source trees and committed so the marketplace can install them. Do not hand-edit `plugins/*`; change the corresponding `sources/*` tree, regenerate the release, and verify byte parity.

Generated ZIP files and `SHA256SUMS.txt` are GitHub Release assets, not tracked repository files.

## Build and verify

Project Design Keeper requires Node.js 20 or newer:

```powershell
cd sources/project-design-keeper
npm ci
npm run typecheck
npm run test:ci
npm run build
npm run smoke
npm run package:verify
```

Run the repository distribution contract from the repository root:

```powershell
node --test test/distribution.test.mjs
```

Run the physics suite from its source root with Python 3.11 or newer:

```powershell
cd sources/physics-simulation-superpowers
python -X utf8 -m unittest discover -s tests -p "test_*.py" -q
python -X utf8 -m unittest tests.test_repository_distribution -q
```

## Links

- [Repository](https://github.com/EverfIRE/ProjectDesign)
- [Issues](https://github.com/EverfIRE/ProjectDesign/issues)
- [Publisher](https://github.com/EverfIRE)
