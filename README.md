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

Run the scanner with:

```sh
cargo run -- config.toml
```

SBOMs are written to `output_dir` — `sbom-out` by default — laid out as
`<output>/<parent>/<name>/sbom.cdx.json`, so projects with the same name in
different places do not collide.

cdxgen stamps each document with the time of the scan and a random serial
number. Both are rewritten to refer to the scanned commit instead, so
scanning an unchanged project twice produces the same file byte for byte
and any real change to the dependencies shows up as a difference.

Note that cdxgen consults the package registry as well as the project's
lockfile, so a scan needs network access and may list packages that are not
pinned in the lockfile.
