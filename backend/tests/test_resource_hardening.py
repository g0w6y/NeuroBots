"""
Real unit tests for autonomous API hardening (bonus feature), added
2026-08-08. Exercises the in-memory fallback path of store.py's new
functions directly - no live Redis needed for these, since the in-memory
and Redis-backed paths share the exact same call signatures and semantics
(see store.py's own docstring on why that equivalence matters). The full
end-to-end behavior against a live gateway, including the anti-collateral-
damage property, is separately proven by attack_sim/simulate.py's phase 4
(cases 13-14) against real Redis - these tests are the fast, no-network
layer underneath that.

Run:
    cd backend && python3 -m pytest tests/test_resource_hardening.py -v
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from store import SharedStore
from detect import resource_hardening_signal, fuse_signals, Signal
from config import settings


@pytest.fixture
def store():
    s = SharedStore()
    # deliberately never dial Redis - exercises the in-memory fallback path,
    # which every function under test falls through to when store.connected
    # is False, same as a real Redis outage would.
    assert s.connected is False
    return s


class TestRecordResourceAttack:
    @pytest.mark.asyncio
    async def test_distinct_attackers_counted_once_each(self, store):
        now = time.time()
        await store.record_resource_attack("account", "bob", now, 300)
        await store.record_resource_attack("account", "scanner", now, 300)
        count = await store.record_resource_attack("account", "ip:1.2.3.4", now, 300)
        assert count == 3

    @pytest.mark.asyncio
    async def test_repeated_same_attacker_does_not_inflate_count(self, store):
        """The anti-gaming property: one attacker hitting the resource 20
        times must never look like 20 distinct attackers. Identity/IP
        auto-escalation already owns the 'one repeat offender' case."""
        now = time.time()
        for _ in range(20):
            count = await store.record_resource_attack("account", "same_attacker", now, 300)
        assert count == 1

    @pytest.mark.asyncio
    async def test_old_entries_fall_out_of_window(self, store):
        old = time.time() - 1000
        recent = time.time()
        await store.record_resource_attack("account", "old_attacker", old, 300)
        count = await store.record_resource_attack("account", "new_attacker", recent, 300)
        # old_attacker's entry is outside the 300s window as of `recent` -
        # only new_attacker should still count
        assert count == 1

    @pytest.mark.asyncio
    async def test_different_resources_tracked_independently(self, store):
        now = time.time()
        await store.record_resource_attack("account", "attacker1", now, 300)
        await store.record_resource_attack("account", "attacker2", now, 300)
        count = await store.record_resource_attack("transfer", "attacker1", now, 300)
        # attacker1 also hitting "transfer" doesn't inflate "account"'s count,
        # and starts "transfer" fresh at 1
        assert count == 1


class TestResourceHardenedState:
    @pytest.mark.asyncio
    async def test_starts_unhardened(self, store):
        now = time.time()
        until = await store.get_resource_hardened_until("account", now)
        assert until == 0.0

    @pytest.mark.asyncio
    async def test_set_and_read_back(self, store):
        now = time.time()
        hardened_until = now + 180
        await store.set_resource_hardened("account", hardened_until, 180)
        until = await store.get_resource_hardened_until("account", now)
        assert until == hardened_until

    @pytest.mark.asyncio
    async def test_expires_and_self_clears(self, store):
        now = time.time()
        await store.set_resource_hardened("account", now - 1, 1)  # already expired
        until = await store.get_resource_hardened_until("account", now)
        assert until == 0.0

    @pytest.mark.asyncio
    async def test_list_only_returns_active(self, store):
        now = time.time()
        await store.set_resource_hardened("account", now + 100, 100)
        await store.set_resource_hardened("expired_one", now - 10, 1)
        active = await store.list_hardened_resources(now)
        resources = [r["resource"] for r in active]
        assert "account" in resources
        assert "expired_one" not in resources


class TestResourceHardeningSignal:
    def test_none_when_not_hardened(self):
        now = time.time()
        assert resource_hardening_signal("account", 0.0, now) is None

    def test_none_when_expired(self):
        now = time.time()
        assert resource_hardening_signal("account", now - 5, now) is None

    def test_none_without_a_resource(self):
        now = time.time()
        assert resource_hardening_signal("", now + 100, now) is None

    def test_real_signal_when_active(self):
        now = time.time()
        sig = resource_hardening_signal("account", now + 100, now)
        assert sig is not None
        assert sig.detector == "resource_hardening_active"
        assert sig.hard is False

    def test_weight_never_reaches_challenge_threshold_alone(self):
        """The safety property that matters most: this signal, alone, must
        never be enough to interrupt a real user. Verified against the
        actual policy function, not just asserted about the weight in
        isolation - fuse_signals is what actually decides."""
        now = time.time()
        sig = resource_hardening_signal("account", now + 100, now)
        action = fuse_signals([sig], settings.block_threshold, settings.challenge_threshold)
        assert action in ("allow", "observe")
        assert action != "challenge"
        assert action != "block"

    def test_corroborated_with_a_real_signal_can_still_matter(self):
        """Hardening alone can't punish anyone, but it's still real
        corroborating evidence - paired with something else genuinely
        suspicious about THIS request, the combination can reach
        challenge, same as any other two soft signals would."""
        now = time.time()
        hardening_sig = resource_hardening_signal("account", now + 100, now)
        other_sig = Signal("control_plane_anomaly", 50,
                            "API6:2023 Unrestricted Access to Sensitive Business Flows",
                            "T1087 Account Discovery", "anomaly: unrelated behavioural signal", hard=False)
        action = fuse_signals([hardening_sig, other_sig], settings.block_threshold, settings.challenge_threshold)
        assert action == "challenge"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
