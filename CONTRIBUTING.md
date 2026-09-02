# Contributing

Contributions are welcome after the public repository is created.

1. Do not add collection of prompts, responses, code, paths, hostnames,
   credentials, plan type, raw identity, or undocumented provider fields.
2. Changes to `UsageSnapshotV1`, signing text, canonicalization, or consent must
   increment the relevant version and include cross-language golden fixtures.
3. Keep `codex app-server` behind the adapter in `src/codex.rs`.
4. Add tests for malformed, null, oversized, reordered, replayed, or unsupported
   inputs. Never use real account data in fixtures.
5. Run formatting, Clippy with warnings denied, tests, and a locked release build.

All commits must certify that the contributor has the right to submit the work
under the MIT license (Developer Certificate of Origin, version 1.1).
