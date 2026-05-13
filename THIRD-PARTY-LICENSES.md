# Third-party licenses

This project is distributed under the Apache License, Version 2.0 (see `LICENSE`). Per Apache-2.0 §4(d), redistributions must preserve the upstream `NOTICE` text from Apache-licensed dependencies. See the separate `NOTICE` file at the repo root for those notices.


This file summarizes the third-party open-source components included in or linked from `mongobetween` (generated from a CycloneDX SBOM of the dependency tree). The full per-package bill of materials is not committed to this repo to keep diffs reviewable; regenerate it with the script below.


## Summary by license category

| Category | Count |
|---|---:|
| Permissive | 5 |
| Permissive (with attribution) | 118 |
| Weak copyleft | 4 |
| **Total third-party components** | **127** |

## What each category means

**Permissive** — Licenses like MIT, BSD, ISC, 0BSD, Unlicense, CC0, Boost, etc. Allow use, modification, and redistribution with minimal restrictions. No source-disclosure or attribution-in-derivative-works requirement beyond preserving the upstream LICENSE text in the package itself.

**Permissive (with attribution)** — Licenses like Apache-2.0, Artistic, CC-BY. Allow use, modification, and redistribution like other permissive licenses, but additionally require preserving any upstream NOTICE file and crediting the original authors. Honored by keeping the LICENSE/NOTICE text in the installed package.

**Weak copyleft** — Licenses like MPL-2.0, LGPL, EPL, CDDL. File-level or library-level copyleft: modifications to the licensed files themselves must be released under the same license, but using the library as a dependency does not force the surrounding project to be open source. Safe for unmodified library use.


## Weak-copyleft dependencies (explicit list)

These are the entries a license-compliance reviewer needs to confirm. All are safe as unmodified library deps; none would force this project to be relicensed.


| Package | Version | Ecosystem | License(s) |
|---|---|---|---|
| `github.com/hashicorp/aws-sdk-go-base/v2` | v2.0.0-beta.65 | golang | MPL-2.0 |
| `github.com/hashicorp/go-cleanhttp` | v0.5.2 | golang | MPL-2.0 |
| `github.com/hashicorp/go-getter` | v1.8.3 | golang | MPL-2.0 |
| `github.com/hashicorp/go-version` | v1.6.0 | golang | MPL-2.0 |

## Permissive dependencies

There are 123 permissive third-party components. They are not enumerated here to keep this file readable. Each is honored by preserving the upstream LICENSE/NOTICE text in the installed package.

Full attribution is available by:

- Running `syft <repo>/. -o cyclonedx-json` to regenerate the SBOM, or
- Inspecting `node_modules/**/LICENSE` (npm/bun) or `$GOPATH/pkg/mod/.../LICENSE` (Go) in an installed checkout.


## Regenerating this file

This file is auto-generated. To regenerate from the current dep tree:

```bash
# 1. Install dependencies so package metadata is available.
go mod download

# 2. Generate a CycloneDX SBOM with license enrichment.
SYFT_ENRICH=all \
  SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true \
  SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES=true \
  syft . -o cyclonedx-json=sbom.cdx.json
```

The SBOM is the canonical source of truth; this file is a human-readable summary derived from it.
