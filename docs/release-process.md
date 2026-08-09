# Release process

No release is authorized for the current prototype.

Before the first release, require all of the following:

1. A selected license and versioning decision.
2. Final SCM install/start/stop/restart/reboot acceptance on the immutable binary.
3. Code signing compatible with Windows Application Control.
4. Installer and uninstall rollback QA with zero orphaned rules/services/files.
5. Long soak, multi-DPI UI, privacy and security review.
6. Reproducible locked restore and green Windows CI.
7. A documented threat-model review and release-specific changelog.

When releases begin, use semantic versioning and an approved, separately reviewed release workflow. Do not publish packages, installers, tags, or GitHub Releases merely to test CI.
