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

echo "📤 Push main..."
git push origin main

echo "🏷️  Tag ${TAG}..."
git tag ${TAG}
git push origin ${TAG}

echo "✅ Done! GitHub Actions takes it from here"
echo "   → Release: github.com/maksimtech/apkradar/releases"
echo "   → PyPI:    pypi.org/project/apkradar"
echo "   → Docker:  hub.docker.com/r/maksimtech/apkradar"
