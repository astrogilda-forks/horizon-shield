#!/usr/bin/env node
// Offline tests for bot_watch.mjs: canned GitHub API answers and cron strings, no network.
//   node tools/status/bot_watch_test.mjs
import { mkdtempSync, writeFileSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseField, parseCron, fireTimes, expectedIntervalMs, scheduledCrons, writerOf, judge, watch, renderBots, problems, span
} from "./bot_watch.mjs";

let failed = 0, passed = 0;
function chk(name, cond, detail) {
  if (cond) { passed++; console.log("ok   " + name); }
  else { failed++; console.log("FAIL " + name + (detail !== undefined ? "  :: " + JSON.stringify(detail).slice(0, 300) : "")); }
}
const H = 3600000, D = 86400000;
const NOW = Date.parse("2026-10-09T12:00:00Z");
const iso = (msAgo) => new Date(NOW - msAgo).toISOString();

// ---- cron fields and intervals --------------------------------------------------------------------------------
chk("field: list, range, step, star step", JSON.stringify(parseField("1,5-7", 0, 59)) === "[1,5,6,7]" && JSON.stringify(parseField("*/6", 0, 23)) === "[0,6,12,18]" && JSON.stringify(parseField("10-20/5", 0, 59)) === "[10,15,20]");
chk("field: 7 means Sunday in day of week, also inside a range", JSON.stringify(parseCron("0 0 * * 7").dows) === "[0]" && JSON.stringify(parseCron("0 0 * * 5-7").dows) === "[0,5,6]");
let threw = false; try { parseCron("0 0 * *"); } catch { threw = true; }
chk("cron: four fields is an error", threw);
threw = false; try { parseCron("61 * * * *"); } catch { threw = true; }
chk("cron: minute 61 is an error", threw);
threw = false; try { parseCron("0 0 * * MON"); } catch { threw = true; }
chk("cron: names are refused, not guessed", threw);
const iv = (c) => expectedIntervalMs([].concat(c), NOW);
chk("interval: hourly 23 * * * * is 1 h", iv("23 * * * *") === H);
chk("interval: daily 0 0 * * * is 1 d", iv("0 0 * * *") === D);
chk("interval: every 6 h 23 */6 * * *", iv("23 */6 * * *") === 6 * H);
chk("interval: weekly Sunday 23 21 * * 0 is 7 d", iv("23 21 * * 0") === 7 * D);
chk("interval: monthly 23 3 1 * * is the longest month, 31 d", iv("23 3 1 * *") === 31 * D);
chk("interval: quarterly 41 2 1 2,5,8,11 * is 92 d (Aug to Nov, Nov to Feb)", iv("41 2 1 2,5,8,11 *") === 92 * D);
chk("interval: weekdays 0 9 * * 1-5 is 3 d (Friday to Monday)", iv("0 9 * * 1-5") === 3 * D);
chk("interval: two cron lines are merged (00:00 and 12:00 is 12 h)", iv(["0 0 * * *", "0 12 * * *"]) === 12 * H);
{
  // day of month and day of week both restricted: fires when either matches (standard cron)
  const t = fireTimes([parseCron("0 0 13 * 5")], Date.parse("2026-11-01T00:00:00Z"), Date.parse("2026-11-30T23:59:00Z"));
  const days = t.map((x) => new Date(x).getUTCDate());
  chk("fire times: 13th or a Friday in November 2026", JSON.stringify(days) === "[6,13,20,27]", days);
}

// ---- reading workflow text ------------------------------------------------------------------------------------
const WF_BLOG = `name: Auto Blog Post
on:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * *'
jobs:
  post:
    steps:
      - run: |
          git config user.name "KIRA Bot"
          git add blog/
`;
const WF_VARS = `on:
  schedule:
    - cron: "23 * * * *"   # hourly at :23
#    - cron: "0 0 * * *"   commented out, must not count
env:
  SV: workers/x/survive-v0
jobs:
  a:
    steps:
      - run: |
          git config user.name  "hs-mirror"
          D=workers/x/pending-v0
          git add "$D/snapshots" "$D/log.jsonl" 2>/dev/null || true
          git add "\${SV}/kept"
          git add "$UNKNOWN/thing" -A .
`;
chk("crons: quoted with single or double quotes, comments ignored", JSON.stringify(scheduledCrons(WF_BLOG)) === '["0 0 * * *"]' && JSON.stringify(scheduledCrons(WF_VARS)) === '["23 * * * *"]');
chk("crons: no schedule block means not scheduled", scheduledCrons("on:\n  push:\n").length === 0);
{
  const w = writerOf(WF_BLOG), v = writerOf(WF_VARS);
  chk("writer: KIRA Bot writes blog", w.bot === "KIRA Bot" && JSON.stringify(w.paths) === '["blog"]', w);
  chk("writer: plain variables substituted, unknown variables, flags, redirects and . skipped", v.bot === "hs-mirror" &&
    JSON.stringify(v.paths.sort()) === '["workers/x/pending-v0/log.jsonl","workers/x/pending-v0/snapshots","workers/x/survive-v0/kept"]', v);
  chk("writer: nothing to infer gives no bot", writerOf("jobs: {}\n").bot === null);
}

// ---- judging runs -----------------------------------------------------------------------------------------------
const run = (msAgo, conclusion, event = "schedule", status = "completed") =>
  ({ created_at: iso(msAgo), run_started_at: iso(msAgo), status, conclusion: status === "completed" ? conclusion : null, event, html_url: "u" });
const active = { state: "active", created_at: "2026-01-01T00:00:00Z" };
{
  const j = judge({ workflow: active, allRuns: [run(12 * H, "success")], schedRuns: [run(12 * H, "success")], intervalMs: D, nowMs: NOW });
  chk("judge: daily job that succeeded 12 h ago is ok", j.flags.length === 0 && j.consecutive_failures === 0, j);
}
{
  // the blog case: still runs daily, but the last success is 19 days old
  const sched = [1, 2, 3].map((d) => run(d * D, "failure")).concat([run(19 * D, "success")]);
  const j = judge({ workflow: active, allRuns: sched, schedRuns: sched, intervalMs: D, nowMs: NOW });
  chk("judge: failing for days is FAILING and OVERDUE, 3 in a row", j.flags.includes("FAILING") && j.flags.includes("OVERDUE") && j.consecutive_failures === 3, j);
}
{
  const sched = [run(1 * D, "failure"), run(2 * D, "success")];
  const j = judge({ workflow: active, allRuns: sched, schedRuns: sched, intervalMs: D, nowMs: NOW });
  chk("judge: one failure is not FAILING, and 2 d is not past 2 d + 3 h", j.flags.length === 0 && j.consecutive_failures === 1, j);
}
{
  const sched = [run(H, "cancelled"), run(2 * H, "failure"), run(3 * H, "skipped"), run(4 * H, "timed_out"), run(5 * H, "success")];
  const j = judge({ workflow: active, allRuns: sched, schedRuns: sched, intervalMs: H, nowMs: NOW });
  chk("judge: cancelled and skipped are not counted; failure + timed_out is FAILING", j.flags.includes("FAILING") && j.consecutive_failures === 2 && !j.flags.includes("OVERDUE"), j);
}
{
  // the law-watch case: weekly, the last scheduled run never happened; a manual success does not hide it
  const sched = [run(17 * D, "success")];
  const all = [run(2 * H, "success", "workflow_dispatch"), ...sched];
  const j = judge({ workflow: active, allRuns: all, schedRuns: sched, intervalMs: 7 * D, nowMs: NOW });
  chk("judge: weekly job with last scheduled success 17 d ago is OVERDUE even after a manual success", j.flags.join() === "OVERDUE" && j.last_success_any_event === iso(2 * H) && j.last_run.event === "workflow_dispatch", j);
}
{
  const j = judge({ workflow: { state: "active", created_at: iso(5 * H) }, allRuns: [], schedRuns: [], intervalMs: D, nowMs: NOW });
  chk("judge: a workflow added 5 h ago with no runs yet is not OVERDUE", j.flags.length === 0, j);
  const k = judge({ workflow: { state: "active", created_at: iso(3 * D) }, allRuns: [], schedRuns: [], intervalMs: D, nowMs: NOW });
  chk("judge: never ran in 3 d on a daily schedule is OVERDUE", k.flags.join() === "OVERDUE", k);
}
{
  // the jidec-stamp case (bot-watch #4, 2026-10-11): hourly, GitHub ran it 5.8 h ago; that is GitHub's lateness, not a stop
  const j = judge({ workflow: active, allRuns: [run(5.8 * H, "success")], schedRuns: [run(5.8 * H, "success")], intervalMs: H, nowMs: NOW });
  chk("judge: hourly job last run 5.8 h ago is ok (never OVERDUE before 12 h)", j.flags.length === 0 && j.overdue_after_ms === 12 * H, j);
  const k = judge({ workflow: active, allRuns: [run(13 * H, "success")], schedRuns: [run(13 * H, "success")], intervalMs: H, nowMs: NOW });
  chk("judge: hourly job with no success for 13 h is OVERDUE", k.flags.join() === "OVERDUE", k);
  const w = judge({ workflow: active, allRuns: [], schedRuns: [run(8 * D, "success")], intervalMs: 7 * D, nowMs: NOW });
  chk("judge: the 12 h floor does not change a weekly limit (14 d + 3 h)", w.overdue_after_ms === 14 * D + 3 * H && w.flags.length === 0, w);
}
{
  const j = judge({ workflow: { state: "disabled_manually", created_at: "2026-01-01T00:00:00Z" }, allRuns: [], schedRuns: [run(40 * D, "failure"), run(41 * D, "failure")], intervalMs: D, nowMs: NOW });
  chk("judge: disabled is DISABLED only", j.flags.join() === "DISABLED", j);
}
{
  const sched = [run(10 * 60000, "", "schedule", "in_progress"), run(H, "success")];
  const j = judge({ workflow: active, allRuns: sched, schedRuns: sched, intervalMs: H, nowMs: NOW });
  chk("judge: a run in progress is the last run but not a result", j.flags.length === 0 && j.last_run.status === "in_progress", j);
}

// ---- whole watch with a canned API ----------------------------------------------------------------------------
{
  const dir = mkdtempSync(join(tmpdir(), "bot-watch-"));
  writeFileSync(join(dir, "blog-post.yml"), WF_BLOG);
  writeFileSync(join(dir, "mirror.yml"), WF_VARS);
  writeFileSync(join(dir, "push-only.yml"), "on:\n  push:\n");
  writeFileSync(join(dir, "broken.yaml"), "on:\n  schedule:\n    - cron: \"0 0 * * MON\"\n");
  const calls = [];
  const canned = {
    "/repos/o/r/actions/workflows/blog-post.yml": active,
    "/repos/o/r/actions/workflows/blog-post.yml/runs?per_page=20": { workflow_runs: [run(12 * H, "failure"), run(36 * H, "failure"), run(20 * D, "success")] },
    "/repos/o/r/actions/workflows/blog-post.yml/runs?per_page=20&event=schedule": { workflow_runs: [run(12 * H, "failure"), run(36 * H, "failure"), run(20 * D, "success")] },
    "/repos/o/r/commits?per_page=30&path=blog": [
      { commit: { author: { name: "Horizon", date: iso(2 * D) }, committer: { name: "Horizon", date: iso(2 * D) } } },
      { commit: { author: { name: "KIRA Bot", date: iso(19 * D) }, committer: { name: "KIRA Bot", date: iso(19 * D) } } }
    ],
    "/repos/o/r/actions/workflows/mirror.yml/runs?per_page=20": { workflow_runs: [run(H, "success")] },
    "/repos/o/r/actions/workflows/mirror.yml/runs?per_page=20&event=schedule": { workflow_runs: [run(H, "success")] }
    // mirror.yml workflow object missing: the API answers 404 for it
  };
  const api = async (p) => { calls.push(p); if (!(p in canned)) throw new Error("GitHub API 404 for " + p.split("?")[0]); return canned[p]; };
  const rows = await watch({ dir, repo: "o/r", api, nowMs: NOW });
  const by = Object.fromEntries(rows.map((r) => [r.file, r]));
  chk("watch: only scheduled workflows are listed", rows.length === 3 && !by["push-only.yml"], rows.map((r) => r.file));
  chk("watch: blog is FAILING and OVERDUE, last bot commit 19 d ago, quiet", by["blog-post.yml"].flags.join() === "FAILING,OVERDUE" &&
    by["blog-post.yml"].bot_commit.at === iso(19 * D) && by["blog-post.yml"].bot_commit.quiet === true, by["blog-post.yml"]);
  chk("watch: an API error is UNKNOWN, not ok", by["mirror.yml"].flags.join() === "UNKNOWN" && /404/.test(by["mirror.yml"].error), by["mirror.yml"]);
  chk("watch: a cron it cannot read is UNKNOWN", by["broken.yaml"].flags.join() === "UNKNOWN", by["broken.yaml"]);
  chk("watch: problems are the three non disabled flags", problems(rows).length === 3);
  const md = renderBots(rows, NOW);
  chk("render: table row per workflow, red summary line", md.includes("| `blog-post.yml` |") && md.includes("need attention") && md.includes("FAILING, OVERDUE"));
  chk("render: no dash characters", !/[\u2012-\u2015\u2212\uFF0D]/.test(md));
  const okRows = [{ file: "a.yml", crons: ["0 0 * * *"], interval_ms: D, flags: [], last_run: null, consecutive_failures: 0 }];
  chk("render: all good says so", renderBots(okRows, NOW).includes("none needs attention"));
}
chk("span: hours and days", span(H) === "1 h" && span(6 * H) === "6 h" && span(D) === "1 d" && span(92 * D) === "92 d" && span(null) === "n/a");

// ---- every scheduled workflow in this repository parses ------------------------------------------------------
{
  const dir = new URL("../../.github/workflows/", import.meta.url).pathname;
  const bad = [];
  for (const f of readdirSync(dir).filter((x) => /\.ya?ml$/.test(x))) {
    const c = scheduledCrons(readFileSync(join(dir, f), "utf8"));
    if (c.length && !(expectedIntervalMs(c, NOW) > 0)) bad.push(f);
  }
  chk("repo: every scheduled workflow here has a readable cron and an interval", bad.length === 0, bad);
}

console.log("\n" + passed + " passed, " + failed + " failed");
process.exit(failed ? 1 : 0);
