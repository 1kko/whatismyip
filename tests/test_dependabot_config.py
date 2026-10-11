"""dependabot.yml: pip's minor and patch bumps as one PR a week, with the
OTel packages in a group of their own and any other major on its own.

Dependabot puts a dependency in the first group it matches, so the order of
the pip groups is load-bearing: `otel` above the catch-all is what keeps the
opentelemetry-* packages out of the weekly bundle. A YAML mapping carries that
order, but nothing else checks it. Nor would anything notice `major` added to
the bundle's update-types, which would merge a breaking release unseen, or a
group switched to security updates, which would tie a security fix to
whatever else that group holds.
"""

from pathlib import Path

import pytest

CONFIG = Path(".github/dependabot.yml")
AUDIT = Path(".github/workflows/security-audit.yml")


def _yaml():
    return pytest.importorskip("yaml")


def _updates() -> dict[str, dict]:
    config = _yaml().safe_load(CONFIG.read_text(encoding="utf-8"))
    assert config["version"] == 2
    return {entry["package-ecosystem"]: entry for entry in config["updates"]}


class TestPipGroups:
    def test_otel_stays_ahead_of_the_catch_all(self):
        groups = _updates()["pip"]["groups"]
        assert list(groups) == ["otel", "minor-and-patch"]
        assert groups["otel"] == {"patterns": ["opentelemetry-*"]}

    def test_the_bundle_takes_minor_and_patch_bumps_only(self):
        bundle = _updates()["pip"]["groups"]["minor-and-patch"]
        assert bundle["patterns"] == ["*"]
        assert sorted(bundle["update-types"]) == ["minor", "patch"]

    def test_security_updates_stay_out_of_the_groups(self):
        """A group covers version updates unless it says otherwise. Kept that
        way, a security fix comes as a PR of its own and never waits on a
        bundle that another package's bump broke."""
        for name, group in _updates()["pip"]["groups"].items():
            assert group.get("applies-to", "version-updates") == "version-updates", name

    def test_pip_runs_on_the_security_audit_day(self):
        """security-audit.yml runs at 09:00 UTC on Mondays. With the grouped
        PR on the same day, the week's dependency work ends in one sitting."""
        assert _updates()["pip"]["schedule"] == {
            "interval": "weekly",
            "day": "monday",
        }
        audit = _yaml().safe_load(AUDIT.read_text(encoding="utf-8"))
        # PyYAML reads the bare key `on` as the boolean True.
        triggers = audit.get("on", audit.get(True))
        (entry,) = triggers["schedule"]
        assert entry["cron"].split()[4] == "1"  # cron's Monday


class TestOtherEcosystems:
    def test_actions_are_one_group_and_docker_is_ungrouped(self):
        updates = _updates()
        assert updates["github-actions"]["groups"] == {"actions": {"patterns": ["*"]}}
        assert "groups" not in updates["docker"]
        for entry in updates.values():
            assert entry["schedule"]["interval"] == "weekly"
