# Contributing to ReticulumKit

Thanks for your interest in contributing! ReticulumKit is an independent Swift implementation of the Reticulum protocol, and contributions (bug reports, fixes, tests, docs, and features) are all welcome.

By participating in this project you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Report a bug:** open an [issue](https://github.com/J-Krush/ReticulumKit/issues). For wire-compatibility bugs (ReticulumKit disagreeing with Python RNS), include a packet capture or a byte-level fixture if you can.
- **Suggest a feature:** open an issue to discuss it first so we can agree on scope before you invest time.
- **Send a pull request:** fix a bug, add tests, or implement an agreed feature.
- **Improve docs:** typos, clarifications, and examples are genuinely valuable.

## Development setup

You'll need Swift 6.1+ and Xcode 16+ (macOS) or a Swift 6.1 toolchain on Linux.

```bash
git clone https://github.com/J-Krush/ReticulumKit.git
cd ReticulumKit
swift build
swift test
```

The full test suite must pass before you open a PR.

## Pull request workflow

The `main` branch is protected: it does not accept direct pushes or force-pushes, and all changes land through pull requests. To contribute:

1. **Fork** the repository and create a topic branch from `main`:
   ```bash
   git checkout -b fix/announce-ratchet-length
   ```
2. **Make your change.** Keep the PR focused: one logical change per PR.
3. **Add or update tests.** New behavior needs test coverage; bug fixes should include a regression test.
4. **Run `swift build` and `swift test`** locally and make sure both are green.
5. **Open a pull request** against `main`. Fill out the PR template, describe what changed and why, and link any related issue.
6. A maintainer will review. Address feedback by pushing new commits to your branch (don't force-push during review unless asked, since it makes re-review harder).
7. Once approved and all conversations are resolved, a maintainer will merge.

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/). Use a type, an optional scope, and an imperative summary:

```
feat(link): support link keepalive renegotiation
fix(announce): correct 10-byte random_hash layout
docs(readme): add propagation example
test(transport): cover path-request rate limiting
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`.

## Coding standards

- **Swift 6 strict concurrency.** Code must compile cleanly with concurrency checking. Prefer actors and `Sendable` types over manual locking, consistent with the existing design.
- **Match the existing style.** Look at neighboring files for naming, doc-comment density, and structure before adding code.
- **Document public API** with `///` doc comments.
- **License headers.** Every source file starts with `// SPDX-License-Identifier: MIT`. Keep that line when you add new files.
- **Never log key material.** Private keys and shared secrets must never be written to logs.

## Wire compatibility

ReticulumKit's defining constraint is byte-for-byte compatibility with the reference Python RNS implementation. When you touch anything that serializes to the wire (packets, headers, announces, the link handshake, hashing), cite the corresponding Python source in a code comment and back the change with a fixture-based test. A change that is "cleaner" but breaks interop with Sideband / MeshChat / NomadNet will not be merged.

## Licensing of contributions

ReticulumKit is MIT-licensed. By submitting a pull request, you agree that your contribution is licensed under the [MIT License](LICENSE) and that you have the right to license it.

## Questions

Open a [discussion](https://github.com/J-Krush/ReticulumKit/discussions) or an issue. We're happy to help you get started.
