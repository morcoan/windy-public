let meta = #{
    name: "agent-bench-local",
    description: "Free P0/P1 agent-bench A-vs-B via local tools (no Anthropic tokens); optional parallel shards",
    phases: [
        #{ title: "Build", detail: "ensure windy + agent-bench binaries" },
        #{ title: "Run", detail: "local tool agents on P0/P1 tasks" },
        #{ title: "Report", detail: "write docs/benchmarks local report" },
    ],
    when_to_use: "When you want free A-vs-B locate/abstain scores without paying for Anthropic",
};

// args: limit (default 12), profiles default P0+P1
let limit = 12;
let profiles = "P0 P1";
if args != () {
    if args.limit != () { limit = args.limit; }
    if args.profiles != () { profiles = args.profiles; }
}

phase("Build");
let build = agent(
    "In current repository root run: cargo build -p windy -p agent-bench 2>&1 | Select-Object -Last 30. "
        + "Report only whether build succeeded.",
    #{
        label: "build-bins",
        capability_mode: "execute",
        agent_type: "general-purpose",
    },
);
if build == () || !build.success {
    complete(#{ ok: false, error: "build agent failed" });
}

phase("Run");
// Two free shards in parallel: arm A-only and arm B-only (halves wall time, still no paid tokens).
let jobs = [];
jobs.push(#{
    prompt: "Working directory MUST be current repository root. "
        + "Run free local agent-bench for arms A and B on P0/P1 (no Anthropic):\n"
        + "cargo run -q -p agent-bench -- --root . --local --balanced --limit "
        + limit.to_string()
        + " --arm A --arm B --profile P0 --profile P1 "
        + "--output docs/benchmarks/agent-loop-v1-local-report.json "
        + "--markdown docs/benchmarks/agent-loop-v1-local-report.md\n"
        + "Then read the markdown report and return a short summary of arm A vs B success and abstain rates. "
        + "Do not invent numbers; only quote the file.",
    label: "local-a-vs-b",
    capability_mode: "execute",
    agent_type: "general-purpose",
});
// Second agent cross-checks fixture task list exists (cheap verify, no paid API).
jobs.push(#{
    prompt: "In current repository root verify these exist and report sizes: "
        + "eval/agent-bench/fixtures/p0p1_tasks_12.json, target/debug/windy.exe or target/debug/windy, "
        + "and that `cargo run -q -p agent-bench -- --help` mentions --local. "
        + "Return ok=true only if --local is documented in help.",
    label: "verify-flags",
    capability_mode: "execute",
    agent_type: "general-purpose",
});
let results = parallel(jobs);

phase("Report");
let summary = agent(
    "Read current repository root\\docs\\benchmarks\\agent-loop-v1-local-report.md if present "
        + "and current repository root\\docs\\benchmarks\\agent-loop-v1-local-report.json. "
        + "Summarize: synthetic flag, harness name, per-arm success, abstentions, and that tokens are zero. "
        + "If files missing, say so.",
    #{
        label: "summarize",
        capability_mode: "read-only",
        agent_type: "explore",
    },
);

complete(#{
    ok: true,
    limit: limit,
    profiles: profiles,
    parallel_ok: results.len(),
    summary_agent: summary,
});
