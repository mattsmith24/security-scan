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

Progress goes to stderr while the scan runs: each directory, when its SBOM is
being generated, and when the SBOM is being scanned. The output of cdxgen and
cve-bin-tool is passed through as they produce it, so cve-bin-tool's download
messages appear while it is fetching vulnerability data rather than all at
once at the end. Results stay on stdout.

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
it on first use. The scanner notes when the database is missing, and prints
cve-bin-tool's own progress while it downloads. A scan of a project with a
few hundred packages takes about half a minute.

cve-bin-tool will not write over an existing report: it writes to a freshly
named file instead. The scanner removes the previous report first, so that a
scan always writes to the same path and leaves no stray files behind.

Set `CVE_BIN_TOOL_PATH` to the path of a cve-bin-tool binary to run that
instead of going through `uv`.

## Vulnerability data

cve-bin-tool does not ask an advisory service for vulnerabilities. It
downloads them from several sources into a local database, and scans
against that database. A source that fails to download leaves the scan
quietly incomplete: cve-bin-tool still writes its report and exits
successfully, so the findings are simply missing whatever that source
knew.

The scanner therefore checks the database after every run, and reports any
source that has no data at all, or data that is too old to trust:

```
vulnerability data:
    CURL      ok       239 entries    downloaded 2 days ago
    EPSS      missing  no data       downloaded 2 days ago
    GAD       ok       42216 entries downloaded a day ago
    NVD       missing  no data       downloaded 2 days ago
    OSV       missing  no data       downloaded 2 days ago
    PURL2CPE ok       2790044 entries downloaded 3 days ago
    REDHAT    ok       26946 entries downloaded 3 days ago
```

A source with no data is always reported. A source whose newest record is
older than `cve_data_stale_days` — seven days by default — is reported as
stale. The same report is written to `data-sources.json` in the output
directory, so that whatever runs the scanner can read it.

The database is `~/.cache/cve-bin-tool/cve.db`, or wherever
`XDG_CACHE_HOME` points; set `cve_bin_tool_cache_dir` in the config to
look somewhere else.

## Limiting OSV ecosystems

cve-bin-tool downloads OSV data for every ecosystem by default, including
the Linux distributions, whose advisories an npm or Rust project never
matches. To download only the ecosystems you scan, set `osv_ecosystems` in
the config:

```toml
osv_ecosystems = ["npm", "PyPI", "crates.io"]
```

Names are OSV's own and are matched case-insensitively. A distribution
name without a release covers every release of it, so `Debian` selects
`Debian:11` and `Debian:12`. The scanner passes the list to cve-bin-tool as
`--osv-ecosystems`.

After generating an SBOM, the scanner reads the purl type of every component
and checks it against that list. If the SBOM contains a package from an
ecosystem that is not listed — a `deb` package when only `npm` is configured,
say — the scan stops with an error naming the ecosystem and its packages.
Those packages' OSV advisories would not be downloaded, so reporting the
remaining findings as if the scan were complete could hide vulnerabilities
that only OSV knows about.

Leaving `osv_ecosystems` unset downloads every ecosystem and disables the
check.
