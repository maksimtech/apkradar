"""
APKRadar — what changed between two releases of the same app.

A store's release notes say what the developer chose to say. This compares what
the two files themselves declare and carry: version and SDK levels, permissions,
trackers and the extra-EU transfers they bring, the hosts in the manifest and in
the code, and the ABIs the native code is built for.

The last one is the reason the command exists. An app whose new release drops
the native code for an ABI is no longer offered to a device that runs only that
ABI, and nothing in the release notes says so. A Galaxy Tab A SM-T515 runs a
32-bit Android (armeabi-v7a) on a 64-bit CPU: when a release ships native code
for arm64-v8a only, the store stops updating the app on that tablet.

Nothing here reaches the network: both files are scanned offline.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from apkradar.scanner import PermissionFound, ScanResult


def _added(old: list[str], new: list[str]) -> list[str]:
    return sorted(set(new) - set(old))


def _removed(old: list[str], new: list[str]) -> list[str]:
    return sorted(set(old) - set(new))


@dataclass
class ScanDiff:
    """The difference between two scans, the older one first."""

    old: ScanResult
    new: ScanResult
    permissions_added: list[PermissionFound] = field(default_factory=list)
    permissions_removed: list[PermissionFound] = field(default_factory=list)

    @property
    def same_package(self) -> bool:
        return self.old.package_name == self.new.package_name

    @property
    def version_name(self) -> tuple[str, str]:
        return self.old.version_name, self.new.version_name

    @property
    def version_code(self) -> tuple[str, str]:
        return self.old.version_code, self.new.version_code

    @property
    def min_sdk(self) -> tuple[str, str]:
        return self.old.min_sdk, self.new.min_sdk

    @property
    def target_sdk(self) -> tuple[str, str]:
        return self.old.target_sdk, self.new.target_sdk

    @property
    def score(self) -> tuple[int | None, int | None]:
        return self.old.score, self.new.score

    @property
    def trackers_added(self) -> list[str]:
        return _added([t.name for t in self.old.trackers], [t.name for t in self.new.trackers])

    @property
    def trackers_removed(self) -> list[str]:
        return _removed([t.name for t in self.old.trackers], [t.name for t in self.new.trackers])

    @property
    def transfers_added(self) -> list[str]:
        return _added(
            [t.entity for t in self.old.extra_eu_transfers], [t.entity for t in self.new.extra_eu_transfers]
        )

    @property
    def transfers_removed(self) -> list[str]:
        return _removed(
            [t.entity for t in self.old.extra_eu_transfers], [t.entity for t in self.new.extra_eu_transfers]
        )

    @property
    def domains_added(self) -> list[str]:
        """Deep-link hosts the new manifest declares and the old one did not."""
        return _added(self.old.manifest_domains, self.new.manifest_domains)

    @property
    def domains_removed(self) -> list[str]:
        return _removed(self.old.manifest_domains, self.new.manifest_domains)

    @property
    def hosts_added(self) -> list[str]:
        """Servers the new code carries and the old one did not.

        Only servers, as the audit reports them: specifications, schemas and
        licences the DEX also names are not something the app talks to.
        """
        return _added(
            [h.host for h in self.old.dex_endpoints], [h.host for h in self.new.dex_endpoints]
        )

    @property
    def hosts_removed(self) -> list[str]:
        return _removed(
            [h.host for h in self.old.dex_endpoints], [h.host for h in self.new.dex_endpoints]
        )

    @property
    def abis_added(self) -> list[str]:
        return _added(self.old.native_abis, self.new.native_abis)

    @property
    def abis_removed(self) -> list[str]:
        return _removed(self.old.native_abis, self.new.native_abis)

    @property
    def abis_left_behind(self) -> list[str]:
        """The ABIs whose devices the new release leaves behind.

        A device that runs only an ABI the old release shipped and the new one does
        not cannot install the new one. When the new release ships no native code at
        all, it runs on every ABI and leaves nobody behind, whatever it dropped.
        """
        return self.abis_removed if self.new.native_abis else []

    @property
    def has_changes(self) -> bool:
        return any(
            (
                self.version_name[0] != self.version_name[1],
                self.version_code[0] != self.version_code[1],
                self.min_sdk[0] != self.min_sdk[1],
                self.target_sdk[0] != self.target_sdk[1],
                self.permissions_added,
                self.permissions_removed,
                self.trackers_added,
                self.trackers_removed,
                self.transfers_added,
                self.transfers_removed,
                self.domains_added,
                self.domains_removed,
                self.hosts_added,
                self.hosts_removed,
                self.abis_added,
                self.abis_removed,
            )
        )

    def to_dict(self) -> dict:
        """Every finding, in a form json.dumps takes as it stands."""

        def pair(values: tuple) -> dict:
            return {"old": values[0], "new": values[1]}

        def changes(added: list[str], removed: list[str]) -> dict:
            return {"added": added, "removed": removed}

        def permissions(found: list[PermissionFound]) -> list[dict]:
            return [{"permission": p.permission, "sensitive": p.gdpr_relevant} for p in found]

        return {
            "package": self.new.package_name,
            "same_package": self.same_package,
            "packages": pair((self.old.package_name, self.new.package_name)),
            "files": pair((self.old.apk_path, self.new.apk_path)),
            "sha256": pair((self.old.sha256, self.new.sha256)),
            "version_name": pair(self.version_name),
            "version_code": pair(self.version_code),
            "min_sdk": pair(self.min_sdk),
            "target_sdk": pair(self.target_sdk),
            "score": pair(self.score),
            "permissions": {
                "added": permissions(self.permissions_added),
                "removed": permissions(self.permissions_removed),
            },
            "trackers": changes(self.trackers_added, self.trackers_removed),
            "extra_eu_transfers": changes(self.transfers_added, self.transfers_removed),
            "manifest_domains": changes(self.domains_added, self.domains_removed),
            "dex_hosts": changes(self.hosts_added, self.hosts_removed),
            "native_abis": {
                "old": self.old.native_abis,
                "new": self.new.native_abis,
                "added": self.abis_added,
                "removed": self.abis_removed,
                "left_behind": self.abis_left_behind,
            },
            "has_changes": self.has_changes,
        }


def diff(old: ScanResult, new: ScanResult) -> ScanDiff:
    """Compare two scans, the older release first."""
    old_permissions = {p.permission for p in old.permissions}
    new_permissions = {p.permission for p in new.permissions}
    return ScanDiff(
        old=old,
        new=new,
        permissions_added=sorted(
            (p for p in new.permissions if p.permission not in old_permissions),
            key=lambda p: p.permission,
        ),
        permissions_removed=sorted(
            (p for p in old.permissions if p.permission not in new_permissions),
            key=lambda p: p.permission,
        ),
    )
