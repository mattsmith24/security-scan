Project to automate CVE scanning of my development projects

Building the scanner needs `pkg-config` and the OpenSSL development headers,
because its SMTP dependency (`lettre`) uses the system TLS library:

```sh
sudo apt install pkg-config libssl-dev
```

Install cdxgen

```sh
npm install -g @cdxgen/cdxgen --ignore-scripts --min-release-age=2
```

Install cve-bin-tool with uv, from my fork rather than upstream, into a
virtual environment at the root of this checkout:

```sh
git clone --branch fix/npm-scope-preservation \
          https://github.com/mattsmith24/cve-bin-tool.git
uv venv
uv pip install --user -e cve-bin-tool
```

The scanner relies on fixes that are not in `ossf/cve-bin-tool` yet, so it
needs the fork's `fix/npm-scope-preservation` branch. That branch is a small
set of commits on top of upstream `main`, which is rebased onto upstream as it
moves; the fork also keeps a `main` that tracks upstream.

Cloning the fork sets `origin` to the fork. To keep up with upstream, add it as
a second remote:

```sh
git remote add upstream https://github.com/ossf/cve-bin-tool.git
git fetch upstream
```

Because the package is installed editable, changes made in `cve-bin-tool` are
picked up by the next scan without reinstalling.

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

`cve-bin-tool` is a Python program, so the scanner runs it through `uv` rather
than calling it directly. `uv` looks for its environment in the working
directory, and the scanner runs it in the directory holding the config file.
Keep `config.toml` in this checkout beside the `.venv` created above — being
gitignored only keeps it out of version control. A config in another directory
has no environment next to it, so `uv` fails to find `cve-bin-tool`. If the
config has to live elsewhere, set `CVE_BIN_TOOL_PATH` to a cve-bin-tool
executable to bypass `uv`.

Run the scanner with:

```sh
cargo run -- config.toml
```

Progress goes to stderr while the scan runs: each directory, when its SBOM is
being generated, and when the SBOM is being scanned. The output of cdxgen and
cve-bin-tool is passed through as they produce it, so cve-bin-tool's download
messages appear while it is fetching vulnerability data rather than all at
once at the end. Results stay on stdout.

SBOMs, CVE reports and VEX documents are written to `output_dir` — `sbom-out`
by default — laid out as `<output>/<parent>/<name>/sbom.cdx.json`,
`<output>/<parent>/<name>/cve-report.json` and
`<output>/<parent>/<name>/vex.cdx.json`, so projects with the same name in
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
instead of going through `uv`. It is the escape hatch for a config that is not
in this checkout, or for a cve-bin-tool installed outside the uv environment.

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

## VEX

Each project gets a CycloneDX VEX next to its SBOM and CVE report:

```
sbom-out/matt/goalkeepr/vex.cdx.json
```

The first scan generates it with cve-bin-tool. Every finding starts in the
`in_triage` state, so the new VEX does not filter anything yet. Later scans
pass it back to cve-bin-tool with `--vex-file` and write a refreshed VEX:
existing decisions are applied, new findings are added as `in_triage`, and
entries for packages that are no longer in the SBOM are dropped.

The refreshed VEX is written to a temporary path and renamed into place, so a
failed scan leaves the previous VEX untouched. This also avoids the numbered
backup files cve-bin-tool leaves when it updates a VEX in place.

Findings marked `not_affected`, `false_positive` or `resolved` are left out of
the summary and counted as filtered by the VEX. They stay in
`cve-report.json`, which records the state of every finding. The scanner
filters on the `remarks` cve-bin-tool writes rather than passing
`--filter-triage`, because cve-bin-tool applies that flag before it writes a
refreshed VEX, which would drop the filtered findings from the new VEX.

The VEX is generated by cve-bin-tool and, unlike the SBOM, is not normalized:
it carries the time it was written and a random serial number. Set
`vex = false` in the config to turn VEX generation and use off.

## Triaging findings

A project's findings are triaged from the terminal:

```sh
cargo run -- triage goalkeepr
```

The project is named the way it is in its VEX: the `name` from the config, or
the name of its directory. `--config` and `--output` override where the config
and output directory are read from, and default to `config.toml` and the
config's `output_dir`. The command finds the project's `vex.cdx.json` under
the output directory and shows each finding in turn, most severe first:
critical, then high, medium, low and unrated. The severity and score come
from the `cve-report.json` next to the VEX; without one, findings stay in the
order the VEX lists them. Each finding is shown with its description and the
decision already recorded for it.

One keypress records a decision:

```
n  not affected     ask for a CycloneDX justification, then optional detail
f  false positive   ask for a reason
r  resolved         ask for what fixed it, e.g. the version
e  exploitable      ask for optional detail
t  back to triage   clear any decision
s  skip             leave the finding as it is
q  quit             keep the decisions made so far
```

For `not affected`, the justification is chosen by number: `1` code not
present through `9` protected by mitigating control, or `b` to go back. The
decision and its detail are what cve-bin-tool reports for the finding, so the
detail is worth filling in for anything but the obvious.

Decisions are written to the VEX in place, through a temporary file, so an
interrupted session leaves the previous VEX untouched. The next scan hands
the VEX back to cve-bin-tool, which applies the decisions: `not affected`,
`false positive` and `resolved` findings drop out of the summary, while
`exploitable` and `in triage` ones stay visible. Every finding stays in
`cve-report.json` either way.

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

## Running a daily scan

`systemd/` holds a user service and timer that scan once a day. Install them
with:

```sh
systemd/install.sh
```

The script builds the release binary, writes
`security-scan.service` and `security-scan.timer` to
`~/.config/systemd/user`, and enables the timer. It needs no root.

As with any user unit, the timer only runs while the user manager does. On a
machine you log out of, enable lingering so the timer keeps running:

```sh
loginctl enable-linger
```

The timer runs the scan at 04:17 local time with up to fifteen minutes of
random delay, so it does not wake the machine at exactly the same moment as
other nightly jobs. `Persistent=true` means a run missed while the machine was
off happens at the next boot instead of being skipped. To use another time,
change `OnCalendar` in `systemd/security-scan.timer.in` and reinstall:

```sh
systemd/install.sh                                    # after editing the timer
systemctl --user list-timers security-scan.timer      # when it runs next
systemctl --user start security-scan.service          # run a scan now
journalctl --user -u security-scan                    # what a run did
```

`systemd/run-scan.sh` is what the service runs. A user service starts with a
minimal `PATH`, which holds neither `uv` (`~/.local/bin`) nor `cdxgen` (in the
Node.js nvm manages, whose directory changes with each Node.js version), so
the script adds both before starting the scanner. It runs
`target/release/security-scan`, so rebuild after changing the scanner; the
install script does that. A Node.js installed system-wide needs nothing
special, and `NVM_DIR` can be set in the unit if nvm lives elsewhere.

The scan needs network access: a run that starts while the machine is offline
fails and is retried by the next day's timer. The service runs at a low
priority, and a failed scan — including one that finds cve-bin-tool data
sources with missing or stale data — shows up as a failed unit:

```sh
systemctl --user status security-scan.service
```

To remove the units:

```sh
systemd/uninstall.sh
```

## Email alerts

A scan can email its report when it finishes. Email stays off unless
`email_to`, `email_from` and `smtp_host` are all set, so a config without
these keys behaves exactly as before:

```toml
email_to = ["you@gmail.com", "other@example.com"]
email_from = "Security Scan <you@gmail.com>"
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_user = "you@gmail.com"
smtp_password = "xxxx xxxx xxxx xxxx"

# Optional: inferred from the port. 587 uses STARTTLS, 465 uses implicit TLS.
# smtp_tls = "starttls"

# Master switch; --no-email suppresses a single run.
# email = true
```

`config.toml` now holds the password, so keep it private:

```sh
chmod 600 config.toml
```

The scanner prints a warning at startup when the file is readable by group or
others. It also rejects malformed addresses, a `smtp_user` without a
`smtp_password` (and the reverse), and an unknown `smtp_tls` when the config
loads.

### Gmail setup

Gmail will not accept your normal account password here. Use an App Password:

1. Turn on two-step verification for the Google account.
2. Create an App Password at <https://myaccount.google.com/apppasswords>.
3. Put the generated password in `smtp_password`, spaces included.

`email_from` must be the authenticated address or an alias verified for it;
Gmail rejects anything else. When the two differ, the scanner warns before
scanning rather than letting the message fail after it. The display name is
allowed (`Security Scan <you@gmail.com>`).

Ports and TLS:

| Setting | Use |
|---|---|
| `smtp_port = 587` (default) | STARTTLS, what Gmail uses |
| `smtp_port = 465` | Implicit TLS; chosen automatically unless `smtp_tls` says otherwise |
| `smtp_tls = "none"` | No TLS and, with no `smtp_user`, no auth — only for a local test relay |

### Running and flags

```sh
cargo run -- config.toml                    # scan and email
cargo run -- config.toml --no-email         # scan without emailing
cargo run -- config.toml --email-dry-run    # print the message, send nothing
```

`--email-dry-run` prints the formatted MIME message to stdout, including the
RFC 2047-encoded subject, so the body and attachments can be checked without a
mail server or mailbox. Email failures (connection, authentication, a rejected
message) print a warning and do not change the scan's exit code.

The subject shows the worst active findings across all projects:

- `✅ [security-scan] 2 projects clean` when no active finding is CRITICAL or
  HIGH.
- `🚨 [security-scan] 1 critical, 3 high` otherwise, with every severity that
  has an active finding.

Findings dismissed by the VEX (`NotAffected`, `FalsePositive`, `Mitigated`) do
not count, matching the console summary, so triage can turn the subject green.
MEDIUM and LOW findings leave the tick in place but are still counted.

The body lists each project's package and dev-only counts, its severity
breakdown, its ten worst active findings and how many the VEX filtered out,
then the state of cve-bin-tool's vulnerability data and any directories that
failed. Each project's `cve-report.json` is attached as
`<project>-cve-report.json`, along with `data-sources.json`. Attachments over
10 MB in total are left out and named in the body instead.

The `triage` subcommand never emails: decisions made there are picked up by the
next scan, and only `scan_command` can reach the send path.

### Testing with Mailpit

A local relay such as [Mailpit](https://mailpit.axllent.org/) is the easiest
way to check delivery without a real mailbox:

```sh
mailpit                       # listens on 127.0.0.1:1025, UI on :8025
```

Point a copy of the config at it, with no credentials:

```toml
smtp_host = "127.0.0.1"
smtp_port = 1025
smtp_tls = "none"
email_to = ["inbox@example.test"]
email_from = "Security Scan <scan@example.test>"
```

Messages and the rendered body then appear at <http://localhost:8025>.

The systemd units need no changes: the daily scan reads the same `config.toml`,
so alerts work from the timer, and no password is placed in the unit's
environment. Remember to rebuild the release binary after changing the scanner.

