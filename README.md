Project to automate CVE scanning of my development projects

Install cdxgen

```sh
npm install -g @cdxgen/cdxgen --ignore-scripts --min-release-age=2
```

Install cve-bin-tool with uv:

```sh
git clone https://github.com/ossf/cve-bin-tool.git
uv venv
uv pip install --user -e cve-bin-tool
```

## Scanning

The scanner reads `config.toml`, and for each directory listed there runs
cdxgen to write a CycloneDX SBOM:

```sh
cdxgen --output sbom-out/matt/goalkeepr/sbom.cdx.json \
       --type npm \
       --project-name goalkeepr \
       --project-version c0c4364 \
       ../goalkeepr
```

The project version is the short hash of the project's current git commit,
from `git rev-parse --short HEAD` in the project directory, so an SBOM names
exactly which revision was scanned. A project that is not in git falls back
to the version in its npm manifest.

The SBOM is then scanned for known vulnerabilities with cve-bin-tool:

```sh
uv run cve-bin-tool --sbom cyclonedx \
                    --sbom-file sbom-out/matt/goalkeepr/sbom.cdx.json \
                    --output-file sbom-out/matt/goalkeepr/cve-report.json \
                    --format json \
                    --product goalkeepr \
                    --release c0c4364 \
                    --vendor mattsmith24
```

The product is the project's name, the release is the same commit hash the
SBOM records, and the vendor is the project's `vendor` setting in the config.
Everything cve-bin-tool needs comes from the SBOM and from its own database,
so nothing here asks npm for its advisories.

Run the scanner with:

```sh
cargo run -- config.toml
```

SBOMs and CVE reports are written to `output_dir` — `sbom-out` by default —
laid out as `<output>/<parent>/<name>/sbom.cdx.json` and
`<output>/<parent>/<name>/cve-report.json`, so projects with the same name in
different places do not collide.

cdxgen stamps each document with the time of the scan and a random serial
number. Both are rewritten to refer to the scanned commit instead, so
scanning an unchanged project twice produces the same file byte for byte
and any real change to the dependencies shows up as a difference.

Note that cdxgen consults the package registry as well as the project's
lockfile, so a scan needs network access and may list packages that are not
pinned in the lockfile.

cve-bin-tool keeps its CVE database in `~/.cache/cve-bin-tool`, and downloads
it on first use. A scan of a project with a few hundred packages takes about
half a minute.

cve-bin-tool will not write over an existing report: it writes to a freshly
named file instead. The scanner removes the previous report first, so that a
scan always writes to the same path and leaves no stray files behind.

Set `CVE_BIN_TOOL_PATH` to the path of a cve-bin-tool binary to run that
instead of going through `uv`.
