# Releasing SentinelCore (private source, public downloads)

The source repository stays **private**. Users download from a separate
**public releases repository** that holds only build outputs, so no GitHub login
is needed to install.

```
private repo (this one)                       public repo (sentinelcore-releases)
  tag vX.Y.Z  ->  release.yml  ---publish--->   GitHub Release: .deb, offline bundle,
  tests, e2e, build, scan, sign                 install.sh, SHA256SUMS(+.asc), latest.json(+.asc),
                    |                           release-key.asc, SBOMs. No source code.
                    +--> ghcr.io/<owner>/sentinelcore-{backend,helper,frontend}:X.Y.Z  (public packages)
```

## What stays hidden, honestly

| Part | Protection |
|---|---|
| Source repository | Private. Never pushed to the releases repo. |
| Frontend | Minified static bundle, no sourcemaps (`frontend/Dockerfile.prod` fails the build if any `.map` exists). |
| Backend and helper | Python images still contain readable `.py` files. For this project that is accepted. Compiling with Nuitka/Cython is an optional stretch; measure image size and startup time before keeping it. |
| Tests, `.git`, `.env`, prompt files | Excluded; `scripts/release/verify-image-contents.sh` fails the release if any appear. |

The licence is "All rights reserved" ([LICENSE](../LICENSE)); the installer shows
[packaging/EULA.txt](../packaging/EULA.txt) and requires acceptance.

## One-time setup

1. **Create the public repo** `dhruvpatel2440/sentinelcore-releases` containing only the
   files in [`releases-repo/`](../releases-repo/) (README). Enable Releases.
2. **Create a signing key** (keep the private key only in CI secrets):
   ```bash
   gpg --quick-generate-key "SentinelCore Releases <releases@example.com>" ed25519 sign 2y
   gpg --armor --export <KEYID> > packaging/release-key.asc        # PUBLIC key, commit it
   gpg --armor --export-secret-keys <KEYID>                        # -> secret RELEASE_GPG_PRIVATE_KEY
   ```
   Also publish `release-key.asc` in the releases repo and on the website, and
   print the fingerprint (`gpg --fingerprint <KEYID>`) on the website so users can
   compare it.
3. **Repository settings (private repo)**
   - Variable `RELEASES_REPO` = `dhruvpatel2440/sentinelcore-releases`.
   - Secrets `RELEASE_GPG_PRIVATE_KEY`, `RELEASE_GPG_PASSPHRASE`.
   - Secret `RELEASES_REPO_TOKEN`: a **fine-grained personal access token** limited
     to the releases repo with *Contents: read and write* and nothing else.
   - Environment `release`: add yourself as a required reviewer for a manual
     approval before anything is published.
4. **Image registry (GHCR).** The first release pushes
   `ghcr.io/dhruvpatel2440/sentinelcore-backend|helper|frontend`. New packages from a
   private repo are private; open each package's *Package settings* and set
   **Change visibility -> Public** (package visibility is independent of repo
   visibility, and GitHub offers no API to automate this). Do it once; later tags
   reuse the setting.
   *Closed-distribution alternative:* keep packages private and give each customer
   a read-only pull token (`docker login ghcr.io`). Trade-off: you control who can
   install, but every user needs a token and the one-line installer cannot pull
   anonymously.
5. The GitHub owner `dhruvpatel2440` is baked into (`install.sh`, `.deb` control file, systemd unit,
   `DEFAULT_UPDATE_URL` in `installer/sentinelcore_installer/common.py`).

## Cutting a release

```bash
python scripts/release/bump_version.py minor      # edits VERSION and CHANGELOG.md
# edit CHANGELOG.md, commit, merge to main
git tag v0.2.0 && git push origin v0.2.0
```

`release.yml` then:

1. checks the tag equals `VERSION` and the changelog has a section for it;
2. scans history with gitleaks;
3. runs backend, helper, installer and frontend tests **and the full e2e suite**; any failure stops the release;
4. builds the three images (multi-stage, non-root, no dev dependencies/tests), checks their contents and `docker history`, scans with **Trivy (fails on CRITICAL)**, makes **Syft SBOMs**;
5. pins every image (including postgres/redis/nginx) by **digest** in `images.json`;
6. builds the `.deb`, `install.sh` (with the release-key fingerprint baked in) and the offline bundle;
7. writes `SHA256SUMS`, `latest.json`, and signs them (and `install.sh`) with the release key;
8. after approval, publishes everything as a GitHub Release on the public repo.

## How users verify what they download

Everything is anchored in the release key:

- `install.sh` has the key **fingerprint** baked in, downloads the key, refuses a
  key with a different fingerprint, verifies `SHA256SUMS.asc`, then verifies the
  `.deb` checksum, then installs.
- `sentinelcore update` downloads `latest.json` + `.asc`, verifies the signature
  with the key installed by the package, checks the `.deb` SHA-256 listed inside
  the signed JSON, backs up, installs, and rolls back if the stack is not healthy.
- Container images are verified by **digest**: `images.json` is covered by the
  signed `SHA256SUMS`, and the installer compares each pulled image's digest with
  it. Per-image Cosign signatures are deliberately not used: keyless signing
  records the workflow identity (and therefore the private repo's name) in the
  public Rekor log, and key-based Cosign would add a second key to manage without
  adding trust beyond the signed digest list.
- Manual check on a clean machine with no GitHub account:
  ```bash
  curl -fsSLO https://github.com/dhruvpatel2440/sentinelcore-releases/releases/latest/download/{SHA256SUMS,SHA256SUMS.asc,release-key.asc}
  gpg --show-keys release-key.asc            # compare the fingerprint with the website
  gpg --import release-key.asc && gpg --verify SHA256SUMS.asc SHA256SUMS
  sha256sum -c --ignore-missing SHA256SUMS
  ```

## Updater contract: `latest.json`

```json
{
  "version": "0.2.0",
  "released": "2026-03-01",
  "min_compatible_version": "0.1.0",
  "migration_notes": "Database migrations run automatically on first start.",
  "files": {
    "deb":             {"name": "...", "url": "https://.../sentinelcore_0.2.0_all.deb", "sha256": "..."},
    "offline_bundle":  {"name": "...", "url": "...", "sha256": "..."},
    "install_sh":      {"name": "install.sh", "url": "...", "sha256": "..."},
    "images_manifest": {"name": "images.json", "url": "...", "sha256": "..."}
  }
}
```

`min_compatible_version`: the oldest installed version that may update directly;
older installs must step through it first.

## Secrets hygiene

- `gitleaks` runs on every PR/push (`.github/workflows/gitleaks.yml`) and before
  every release; `.gitleaks.toml` lists the few documented non-secrets.
- A second job fails if `.env`, keys or the prompt folder are ever tracked.
- `.dockerignore`/Dockerfiles exclude env files; `verify-image-contents.sh`
  inspects the final image filesystem and `docker history`.
- Private keys exist only as CI secrets; the release job refuses to proceed if
  the committed `packaging/release-key.asc` is still the placeholder.
