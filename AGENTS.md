# Agent Directives: Rules of Engagement

## Core Philosophy (Hacker Ethos & Unix Tradition)
- **Avoid complexity like the plague**: Elegance is simplicity. If code feels complicated, it is poorly designed. Write the simplest thing that could possibly work.
- **The Three Virtues (Larry Wall)**:
  - *Laziness*: Automate toil, don't repeat yourself, don't write bloated boilerplate when clean functions and existing tools suffice.
  - *Impatience*: Tight feedback loops. Keep tests fast, run them early, don't linger.
  - *Hubris*: Take pride in craftsmanship. Zero-defect mindset. Write code that others will respect, not complain about.
- **Unix Philosophy**:
  - Write single-purpose, modular components connected by clean interfaces.
  - *Rule of Silence*: When there are no errors, output nothing. Don't chatter.
  - Plain text over bespoke formats.
- **No Assumptions**: Inspect before acting. Never guess file paths, node trees, API signatures, or types. Verify with tools and code exploration.

## Working Guidelines
- **Concise & Direct**: State what changed, what was verified, or what failed. No pleasantries, no sycophantic preamble, no filler.
- **No Speculative Engineering (YAGNI)**: Implement only what is asked. Do not build abstract framework wrappers or dead helper functions.
- **Refactoring & Hygiene**: Delete dead code, unused imports, and obsolete comments. Leave the campsite cleaner than you found it.

## Quality & Verification
- Unverified code is broken code.
- Operational workflows and test suites are encapsulated in workspace skills (see `.agents/skills/qa`). Always verify changes using the project `Makefile`.
- Once QA passes, changes undergo multi-agent code review across 5 dimensions (see `.agents/skills/code-review`).

## Language Best Practices & Conventions
<!-- Document language-specific idioms and conventions agreed upon with the user during code reviews -->
- **POSIX Shell (`#!/bin/sh`)**: Use `set -e`, avoid bashisms, quote all variable expansions, use `printf '%s\n'` instead of `echo` for arbitrary strings, guard path arguments with `--`, and redirect any diagnostic/init output to `stderr` (`>&2`) to preserve wire protocols and the Rule of Silence.
- **Python 3**: Rely strictly on the standard library (`from __future__ import annotations`, `pathlib.Path` with explicit `encoding="utf-8"`, `unittest`), reject symlinks when reconciling privileged directories/files (`follow_symlinks=False`), and perform atomic file updates via `tempfile.mkstemp` + `os.replace`.
