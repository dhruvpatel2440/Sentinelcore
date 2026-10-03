# First release runbook (v0.1.0)

## Where the files live

| Repo | Visibility | Contains |
|---|---|---|
| `dhruvpatel2440/Sentinelcore` | **private** | all source: `backend/`, `frontend/`, `helper/`, `installer/`, `packaging/`, `website/`, `scripts/`, workflows, docs |
| `dhruvpatel2440/sentinelcore-releases` | public | only `README.md`, `LICENSE` and the release assets (installer package, `install.sh`, `.deb`, offline bundle, checksums, signatures, `latest.json`, `release-key.asc`, SBOMs). **Never source code or history from the private repo.** |
| `ghcr.io/dhruvpatel2440/sentinelcore-{backend,helper,frontend}` | public packages | the compiled application images, pinned by digest in `images.json` |

Check after each change: in a private browser window the private repo must return 404.

Run these on your own machine, in order, from a clone of
`dhruvpatel2440/Sentinelcore` with this work copied in. Needs `git`, `gh`
(logged in: `gh auth login`) and `gpg`. Nothing here has been run for you.

## 1. Branch with the new files

```bash
git checkout main && git pull
git checkout -b product/real-release-installer
# copy in: installer/ packaging/ scripts/release/ website/ docs/ releases-repo/
#          frontend/Dockerfile.prod .github/workflows/{release,gitleaks,installer-ci}.yml
#          .gitleaks.toml .gitattributes LICENSE VERSION CHANGELOG.md
git add -A && git status        # check: no .env, no node_modules, no dist
```

## 2. Public releases repo

```bash
gh repo create dhruvpatel2440/sentinelcore-releases --public \
  --description "SentinelCore signed downloads (no source code)"
git clone https://github.com/dhruvpatel2440/sentinelcore-releases.git ../sentinelcore-releases
cp releases-repo/README.md ../sentinelcore-releases/README.md
(cd ../sentinelcore-releases && git add README.md && git commit -m "Add README" && git push -u origin HEAD)
```

## 3. Signing key (keep the private key OFF the repo)

```bash
gpg --quick-generate-key "SentinelCore Releases <dhruvpatel2440@gmail.com>" ed25519 sign 2y
# (you will be asked for a passphrase: remember it)
FPR=$(gpg --list-keys --with-colons "SentinelCore Releases" | awk -F: '$1=="fpr"{print $10; exit}')
echo "$FPR"                                   # publish this fingerprint on the website
gpg --armor --export "$FPR" > packaging/release-key.asc          # PUBLIC key: commit it
gpg --armor --export-secret-keys "$FPR" > ~/sentinelcore-release-private.asc   # back up offline, never commit
```

## 4. Secrets and settings on the private repo

```bash
R=dhruvpatel2440/Sentinelcore
gpg --armor --export-secret-keys "$FPR" | gh secret set RELEASE_GPG_PRIVATE_KEY --repo $R
gh secret set RELEASE_GPG_PASSPHRASE --repo $R          # paste the passphrase when asked
gh variable set RELEASES_REPO --repo $R --body dhruvpatel2440/sentinelcore-releases
gh api -X PUT repos/$R/environments/release             # approval gate (add yourself as reviewer in the UI)
```

Create the publishing token **in the browser** (no CLI for this):
GitHub -> Settings -> Developer settings -> Fine-grained tokens -> Generate.
Repository access: **only** `sentinelcore-releases`. Permission: **Contents: Read and write**. Then:

```bash
gh secret set RELEASES_REPO_TOKEN --repo $R             # paste the token
```

## 5. Merge, then tag

```bash
git commit -m "Add installer, release pipeline and website"
git push -u origin product/real-release-installer
gh pr create --fill && gh pr merge --merge        # after CI is green
git checkout main && git pull
# edit CHANGELOG.md: change "## [0.1.0] - unreleased" to today's date, commit and push
git tag v0.1.0 && git push origin v0.1.0
```

The `Release` workflow now runs. Watch it: `gh run watch`. If you added a reviewer to
the `release` environment, approve the publish step in the Actions UI.

## 6. Make the images public (once)

After the first run, for each of `sentinelcore-backend`, `sentinelcore-helper`,
`sentinelcore-frontend`: GitHub -> your profile -> Packages -> the package ->
Package settings -> Change visibility -> **Public**. (No API exists for this.)

## 7. Put the real links on the website

```bash
gh release download v0.1.0 -R dhruvpatel2440/sentinelcore-releases -p SHA256SUMS -p latest.json
cat SHA256SUMS
```

Edit `website/src/data/releases.json`: `status: "available"`, `version: "0.1.0"`,
`released`, the signing key `fingerprint`, and for each download its `url`
(`https://github.com/dhruvpatel2440/sentinelcore-releases/releases/download/v0.1.0/<file>`),
`sha256` from SHA256SUMS, and for the one-line installer the `command`:

```
curl -fsSL https://github.com/dhruvpatel2440/sentinelcore-releases/releases/download/v0.1.0/install.sh | sudo sh
```

Then `cd website && npm run build && npm run check` and deploy `dist/` (see `website/README.md`).

## 8. Test on a clean Ubuntu 24.04 VM

Follow `docs/installer-test.md` and record the results there. Only after it passes, mark
Ubuntu 24.04 as **tested** in `docs/supported-platforms.md`.

## If the workflow fails

| Failure | Meaning |
|---|---|
| `tag does not match VERSION` | `VERSION` must be `0.1.0` before tagging |
| `no section for 0.1.0` in CHANGELOG | keep a `## [0.1.0]` heading |
| e2e job | the dev stack or e2e suite failed on the runner; read `docker compose logs` in the job |
| Trivy | a CRITICAL vulnerability with a fix exists in an image; update the base image |
| `release-key.asc is not a real public key` | step 3 not committed |
| `RELEASE_GPG_PRIVATE_KEY secret is missing` | step 4 |
