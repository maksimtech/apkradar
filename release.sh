#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "❌ Usage: ./release.sh <version>"
    echo "   Example: ./release.sh 2026.09.1"
    exit 1
fi

VERSION="$1"
TAG="v${VERSION}"

echo "🚀 Releasing APKRadar ${TAG}"

if [ -n "$(git status --porcelain)" ]; then
    echo "❌ Working tree not clean — commit your changes first"
    exit 1
fi

if git tag | grep -q "^${TAG}$"; then
    echo "❌ Tag ${TAG} already exists"
    exit 1
fi

OLD_VERSION=$(python3 -c "import re; content=open('apkradar/__init__.py').read(); print(re.search(r'__version__ = \"(.+?)\"', content).group(1))")
echo "📝 Version bump: ${OLD_VERSION} → ${VERSION}"
sed -i "s/__version__ = \"${OLD_VERSION}\"/__version__ = \"${VERSION}\"/" apkradar/__init__.py

git add apkradar/__init__.py
git commit -m "chore: bump version to ${VERSION}"

# Annotated and with a message, not a bare `git tag`: where `tag.gpgsign` is
# true a bare tag is a signed tag, a signed tag needs a message, and git answers
# `fatal: no tag message?` — which it did on 2026-10-03, after main had already
# been pushed.
echo "🏷️  Tag ${TAG}..."
git tag -a "${TAG}" -m "APKRadar ${VERSION}"

# Atomic, and the tag made first: either both refs arrive or neither does. The
# old order pushed main and then tagged, so a failure at the tag step left a
# version on the remote that nothing pointed at and no workflow reacted to —
# they trigger on `push: tags: v*`.
echo "📤 Push main + tag ${TAG}..."
git push --atomic origin main "${TAG}"

echo "✅ Done! GitHub Actions takes it from here"
echo "   → Release: github.com/maksimtech/apkradar/releases"
echo "   → PyPI:    pypi.org/project/apkradar"
echo "   → Docker:  hub.docker.com/r/maksimtech/apkradar"
