# Releases with CN minus HK

This fork follows release assets from `Loyalsoldier/v2ray-rules-dat`. It does not
rebuild upstream domain lists or merge upstream code into the default branch.

The workflow checks the upstream latest release at minute 17 of every hour
(UTC schedule). GitHub may delay scheduled runs. It also supports manual runs.
Only a new upstream release is processed; published versions are skipped.

For each upstream version it:

1. Downloads all release assets and checks their API digests and SHA256 files.
2. Computes `CN minus HK` for IPv4 and IPv6, preserving other GeoIP categories.
3. Updates both the standalone `geoip.dat` and the copy inside `rules.zip`.
4. Regenerates the two affected SHA256 files and adds `patch-info.json`.
5. Uploads everything to a draft release, then publishes it as latest.
6. Commits `upstream-release.json` to record the processed version.

Release tags match the upstream tag exactly, for example `202610312203`.
Standard download URLs work:

```text
https://github.com/YOUR_USERNAME/v2ray-rules-dat/releases/latest/download/geoip.dat
https://github.com/YOUR_USERNAME/v2ray-rules-dat/releases/latest/download/geoip.dat.sha256sum
```

The original upstream build workflow is replaced in this fork to prevent it
from publishing unpatched files. No `release` branch is maintained; consumers
should use the release download URLs, not raw branch or jsDelivr URLs.

Only the automatically provided `GITHUB_TOKEN` with `contents: write` is needed.
Use a public fork and standard Ubuntu runner on GitHub Free. No PAT or Pro
subscription is required by this workflow.

Fork Actions must be enabled. GitHub's public-repository inactivity rules still
apply: new release tracking commits keep the repository active while upstream
continues publishing. If scheduled runs are disabled after a long inactive
period, re-enable this workflow manually.

Local checks:

```sh
python3 -B -m unittest discover -s scripts -p 'test_*.py' -v
```
