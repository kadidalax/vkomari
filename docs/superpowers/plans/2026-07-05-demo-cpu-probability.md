# Demo CPU Probability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace CPU min/max hard limits with a presentation-friendly probability model for `low`, `mid`, and `high`.

**Architecture:** Keep CPU generation inside `VirtualAgent`; reuse existing deterministic wave/hash helpers. Remove CPU min/max from the frontend refresh flow while leaving database columns untouched for compatibility.

**Tech Stack:** Python standard library, FastAPI static HTML/JS, existing assert-style Python tests.

---

### Task 1: CPU Probability Generator

**Files:**
- Modify: `agent.py`
- Test: `tests/test_virtual_agent_realism.py`

- [ ] **Step 1: Write failing tests**

Add tests that sample CPU with fixed time, assert 0-100 bounds, assert `low < mid < high` by average and high-load ratio, and assert explicit `cpu_min/cpu_max` no longer hard-limit CPU.

- [ ] **Step 2: Run test to verify failure**

Run: `python tests/test_virtual_agent_realism.py`
Expected: fails because current CPU is still bounded by `cpu_min/cpu_max`.

- [ ] **Step 3: Implement minimal generator**

In `agent.py`, add a small `CPU_PROFILES` table with weighted ranges and profile cadence/chase/jitter. Add helper methods to choose a deterministic target range per time bucket and generate CPU from full 0-100 range. Replace only the current CPU min/max block in `generate_stats`.

- [ ] **Step 4: Run test to verify pass**

Run: `python tests/test_virtual_agent_realism.py`
Expected: pass.

### Task 2: Frontend CPU Controls

**Files:**
- Modify: `static/index.html`
- Modify: `static/js/data.js`
- Test: `tests/test_ui_layout.py`

- [ ] **Step 1: Write failing UI tests**

Update `tests/test_ui_layout.py` so it asserts CPU min/max labels are absent, `applyPreset()` no longer assigns `this.form.cpu_min` or `this.form.cpu_max`, and `loadPresets` no longer carries CPU min/max fields.

- [ ] **Step 2: Run test to verify failure**

Run: `python tests/test_ui_layout.py`
Expected: fails because the UI still exposes and writes CPU min/max.

- [ ] **Step 3: Remove CPU min/max from UI refresh**

Delete the two CPU min/max input blocks from `static/index.html`. Remove CPU fields from `openModal()` defaults, `saveNode()`, template save/update payloads, and `applyPreset()`. In `static/js/data.js`, remove `cpu_min/cpu_max` from low/mid/high presets.

- [ ] **Step 4: Run test to verify pass**

Run: `python tests/test_ui_layout.py`
Expected: pass.

### Task 3: Full Verification and Commit

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run focused suite**

Run: `python tests/test_ui_layout.py; python tests/test_komari_autodiscovery.py; python tests/test_cfmonitor_policy.py; python tests/test_virtual_agent_realism.py`
Expected: exit 0.

- [ ] **Step 2: Run syntax and diff checks**

Run: `python -m py_compile main.py scheduler.py agent.py reporters/komari.py reporters/cfmonitor.py routes/nodes.py`
Expected: exit 0.

Run: `git diff --check`
Expected: exit 0.

- [ ] **Step 3: Commit and push**

Run:

```bash
git add agent.py static/index.html static/js/data.js tests/test_ui_layout.py tests/test_virtual_agent_realism.py docs/superpowers/plans/2026-07-05-demo-cpu-probability.md
git commit -m "Use demo CPU probability model"
git push
```
