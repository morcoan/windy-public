let meta = #{
    name: "dump-mcp-verify",
    description: "Verify Windows .dmp MCP hybrid path: open dump, triage, stackwalk, open_dump_module, evidence",
    phases: [
        #{ title: "Build", detail: "cargo build + dump unit tests" },
        #{ title: "Dogfood", detail: "CLI dump-info + open_dump_module smoke" },
        #{ title: "Report", detail: "summarize readiness for MCP agents" },
    ],
    when_to_use: "After dump analysis changes; optional args.dump_path",
};

let build_schema = #{
    "type": "object",
    "required": ["ok", "summary"],
    "properties": #{
        "ok": #{ "type": "boolean" },
        "summary": #{ "type": "string" },
        "details": #{ "type": "string" },
    },
};

phase("Build");
let build = agent(
    "From the current windy repository root, run verification for dump MCP support. "
        + "Use the shell from the repo root: "
        + "(1) cargo build  "
        + "(2) cargo test sample_dump_smoke_if_present -- --nocapture  "
        + "(3) cargo test open_sample_dump_module_if_present -- --nocapture  "
        + "(4) cargo clippy -- -D warnings. "
        + "Report ok=true only if all four pass. Include recovered function counts in details.",
    #{
        label: "build-verify",
        capability_mode: "execute",
        output_schema: build_schema,
    }
);

if build == () || !build.success || build.output == () || build.output.ok != true {
    let msg = "Build/verify failed";
    if build != () && build.output != () && build.output.summary != () {
        msg = build.output.summary;
    }
    complete(#{
        summary: "FAILED: " + msg,
        ok: false,
    });
}

phase("Dogfood");
let dog_prompt = "From the current windy repository root, dogfood the dump CLI. ";
dog_prompt += "If a local sample_process.dmp exists in the repo root, run: cargo run --quiet -- dump-info sample_process.dmp and summarize modules/threads/memory. ";
dog_prompt += "Grep src/mcp.rs for get_thread_stack and open_dump_module and confirm both exist. ";
dog_prompt += "Set ok=true if tools exist and CLI works or fixture is missing; ok=false only on hard failure.";

let dog = agent(
    dog_prompt,
    #{
        label: "dogfood-cli",
        capability_mode: "execute",
        output_schema: build_schema,
    }
);

phase("Report");
let dog_blob = "none";
if dog != () && dog.success && dog.output != () {
    dog_blob = json_encode(dog.output);
}
let report_prompt = "Write a short agent-facing summary of windy dump MCP readiness. ";
report_prompt += "Build result: " + json_encode(build.output) + ". ";
report_prompt += "Dogfood: " + dog_blob + ". ";
report_prompt += "Cover: same serve-mcp port 8765, tools open_project get_dump_triage list_dump_modules ";
report_prompt += "list_dump_threads get_thread_stack list_memory_regions describe_dump open_dump_module, ";
report_prompt += "and PE tools on dump_module project_id. Return ok + summary.";

let report = agent(
    report_prompt,
    #{
        label: "report",
        capability_mode: "read-only",
        output_schema: build_schema,
    }
);

let ok = true;
if report == () || !report.success || report.output == () || report.output.ok != true {
    ok = false;
}

let summary = "done";
if report != () && report.success && report.output != () && report.output.summary != () {
    summary = report.output.summary;
}

complete(#{
    summary: summary,
    ok: ok,
    build: build.output,
});
