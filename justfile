set shell := ["bash", "-uc"]
set positional-arguments

releaser_image := "torii-releaser:latest"

default:
    @just --list

# Print the current release version.
version:
    @cat VERSION

# Build the release-runner image (go + bun + goreleaser + docker-cli). Run
# once after cloning, and again whenever Dockerfile.releaser changes.
release-image:
    docker build -f Dockerfile.releaser -t {{ releaser_image }} .

# Cut a release: bump VERSION, tag, push, then hand off to goreleaser running
# inside the release-runner container which builds cross-platform binaries,
# builds + pushes the docker image (via the bind-mounted host docker socket),
# and creates the GitHub release with changelog + asset uploads.
#
# Requires: docker login (on host), GITHUB_TOKEN in env (or gh auth token).
# KIND is patch (default), minor, or major.
release KIND="patch":
    #!/usr/bin/env bash
    set -euo pipefail

    if ! docker image inspect {{ releaser_image }} >/dev/null 2>&1; then
        echo "error: {{ releaser_image }} not built. Run: just release-image" >&2
        exit 1
    fi
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "error: working tree is dirty — commit or stash first" >&2
        exit 1
    fi
    branch=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$branch" != "main" ]]; then
        echo "error: must release from main (currently on '$branch')" >&2
        exit 1
    fi

    cur=$(cat VERSION)
    IFS=. read -r maj min pat <<< "$cur"
    case "{{ KIND }}" in
        major) maj=$((maj + 1)); min=0; pat=0 ;;
        minor) min=$((min + 1)); pat=0 ;;
        patch) pat=$((pat + 1)) ;;
        *) echo "error: KIND must be major|minor|patch (got '{{ KIND }}')" >&2; exit 1 ;;
    esac
    next="${maj}.${min}.${pat}"
    tag="v${next}"
    echo "==> bumping ${cur} → ${next}"

    echo "${next}" > VERSION

    git add VERSION
    git commit -m "chore: release ${tag}"
    git tag -a "${tag}" -m "release ${tag}"

    echo "==> pushing commit + tag"
    git push origin HEAD
    git push origin "${tag}"

    # GITHUB_TOKEN is consumed by goreleaser to publish the release. Fall back
    # to `gh auth token` so users who already have gh logged in don't need to
    # juggle a PAT.
    if [[ -z "${GITHUB_TOKEN:-}" ]] && command -v gh >/dev/null 2>&1; then
        export GITHUB_TOKEN=$(gh auth token)
    fi
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        echo "error: GITHUB_TOKEN not set and gh not available" >&2
        exit 1
    fi

    echo "==> goreleaser release ${tag}"
    docker run --rm \
        -v "$PWD:/workspace" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "${HOME}/.docker:/root/.docker:ro" \
        -e GITHUB_TOKEN \
        -e TORII_VERSION="${next}" \
        -w /workspace \
        {{ releaser_image }} \
        release --clean

    echo "==> released ${tag}"

# Dry-run goreleaser without publishing — useful to validate config changes.
release-snapshot:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! docker image inspect {{ releaser_image }} >/dev/null 2>&1; then
        echo "error: {{ releaser_image }} not built. Run: just release-image" >&2
        exit 1
    fi
    docker run --rm \
        -v "$PWD:/workspace" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "${HOME}/.docker:/root/.docker:ro" \
        -e TORII_VERSION="$(cat VERSION)-snapshot" \
        -w /workspace \
        {{ releaser_image }} \
        release --snapshot --clean --skip=publish
