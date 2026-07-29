let meta = #{
    name: "agent-bench-grok-ab",
    description: "Grok subagent A-vs-B on P0/P1 locate+abstain (no Anthropic)",
    phases: [
        #{ title: "Prep", detail: "confirm binaries" },
        #{ title: "Arm-A", detail: "Grok agents using windy tools" },
        #{ title: "Arm-B", detail: "Grok agents using python/pefile" },
        #{ title: "Score", detail: "score vs gold and write report" },
    ],
    when_to_use: "Free Grok-model agent loop for windy vs pefile A-vs-B",
};

let root = ".";
if args != () && args.root != () { root = args.root; }

// Manifest-derived 12-task balanced set (same as fixtures/p0p1_tasks_12.json).
// Gold is ONLY for the scorer.
let tasks = [
    #{ id: "locate:a01_signed_rel:P0:main", family: "locate", source: "main", pe: root + "\\eval\\grand\\bin\\P0\\a01_signed_rel.exe", gold: "0x140001080" },
    #{ id: "abstain:a01_signed_rel:P0:filter_av", family: "abstain", source: "filter_av", pe: root + "\\eval\\grand\\bin\\P0\\a01_signed_rel.exe", gold: "refuse" },
    #{ id: "locate:a01_signed_rel:P0:signed_lt", family: "locate", source: "signed_lt", pe: root + "\\eval\\grand\\bin\\P0\\a01_signed_rel.exe", gold: "0x140001000" },
    #{ id: "abstain:a01_signed_rel:P1:outer_sum", family: "abstain", source: "outer_sum", pe: root + "\\eval\\grand\\bin\\P1\\a01_signed_rel.exe", gold: "refuse" },
    #{ id: "locate:a01_signed_rel:P0:unsigned_lt", family: "locate", source: "unsigned_lt", pe: root + "\\eval\\grand\\bin\\P0\\a01_signed_rel.exe", gold: "0x140001040" },
    #{ id: "abstain:a02_narrow_promo:P0:count_down", family: "abstain", source: "count_down", pe: root + "\\eval\\grand\\bin\\P0\\a02_narrow_promo.exe", gold: "refuse" },
    #{ id: "locate:a01_signed_rel:P1:main", family: "locate", source: "main", pe: root + "\\eval\\grand\\bin\\P1\\a01_signed_rel.exe", gold: "0x140001000" },
    #{ id: "abstain:a02_narrow_promo:P1:sum_until_zero", family: "abstain", source: "sum_until_zero", pe: root + "\\eval\\grand\\bin\\P1\\a02_narrow_promo.exe", gold: "refuse" },
    #{ id: "locate:a01_signed_rel:P1:signed_lt", family: "locate", source: "signed_lt", pe: root + "\\eval\\grand\\bin\\P1\\a01_signed_rel.exe", gold: "0x140001044" },
    #{ id: "abstain:a03_minmax_abs:P0:crc_add", family: "abstain", source: "crc_add", pe: root + "\\eval\\grand\\bin\\P0\\a03_minmax_abs.exe", gold: "refuse" },
    #{ id: "locate:a01_signed_rel:P1:unsigned_lt", family: "locate", source: "unsigned_lt", pe: root + "\\eval\\grand\\bin\\P1\\a01_signed_rel.exe", gold: "0x14000104c" },
    #{ id: "abstain:a03_minmax_abs:P1:walk_cstr", family: "abstain", source: "walk_cstr", pe: root + "\\eval\\grand\\bin\\P1\\a03_minmax_abs.exe", gold: "refuse" },
];

let answer_schema = #{
    "type": "object",
    "required": ["task_id", "arm", "answer", "rationale", "tool_calls"],
    "properties": #{
        "task_id": #{ "type": "string" },
        "arm": #{ "type": "string" },
        "answer": #{ "type": "string" },
        "rationale": #{ "type": "string" },
        "tool_calls": #{ "type": "integer" },
    },
};

let windy = root + "\\target\\debug\\windy.exe";
let py = root + "\\target\\agent-bench-scratch\\local_b\\.venv\\Scripts\\python.exe";

phase("Prep");
let prep = agent(
    "Working dir " + root + ". Confirm these exist with shell/Test-Path: "
        + "target\\debug\\windy.exe and target\\agent-bench-scratch\\local_b\\.venv\\Scripts\\python.exe. "
        + "If windy missing: cargo build -p windy. If venv python missing, create venv and pip install pefile capstone. "
        + "Return ok=true only if both work: start `windy serve-mcp --bind 127.0.0.1:18770 --open eval/grand/bin/P0/a01_signed_rel.exe` briefly "
        + "(or call scripts/mcp-call.ps1 against a running endpoint with list_projects), and python -c \"import pefile; print('ok')\". "
        + "Kill any temporary serve-mcp when done.",
    #{ label: "prep", capability_mode: "execute", agent_type: "general-purpose" },
);
if prep == () || !prep.success {
    complete(#{ ok: false, error: "prep failed" });
}

phase("Arm-A");
let a_jobs = [];
for t in tasks {
    let prompt = "";
    prompt += "You are Arm A (Windy substrate) in a free Grok agent-bench. Use TOOLS — do not guess.\n";
    prompt += "Working directory: " + root + "\n";
    prompt += "Task id: " + t.id + "\n";
    prompt += "Family: " + t.family + "\n";
    prompt += "Question: Which VA implements source function `" + t.source + "` in this PE? ";
    prompt += "If the function is missing/inlined/eliminated or evidence is weak/ambiguous, answer refuse (honest abstention).\n";
    prompt += "PE path: " + t.pe + "\n";
    prompt += "REQUIRED: drive the AGENTS.md evidence ladder via Windy MCP (not a single agent-query).\n";
    prompt += "1) Start: " + windy + " serve-mcp --bind 127.0.0.1:<free-port> --open \"" + t.pe + "\"\n";
    prompt += "   Endpoint: http://127.0.0.1:<free-port>/mcp\n";
    prompt += "   Helper: " + root + "\\scripts\\mcp-call.ps1 -Endpoint <url> -Tool <name> [-Arguments '<json>']\n";
    prompt += "2) list_projects → take project_id.\n";
    prompt += "3) get_triage (project_id, limit~32) — note ranked VAs/names.\n";
    prompt += "4) search_bel (project_id, query=\"" + t.source + "\", mode=substring) — ranked BEL hits.\n";
    prompt += "5) functions_named (project_id, pattern=\"" + t.source + "\") — name list; prefer exact name, not substring-only.\n";
    prompt += "6) get_function_evidence on the best candidate VA (if any) before answering.\n";
    prompt += "You MAY use describe_address / trace_value if needed. Do NOT use only agent-query --functions-named.\n";
    prompt += "Prefer refuse over inventing a VA. Do NOT read identity_maps or .map gold files.\n";
    prompt += "Answer is a hex VA like 0x140001000 or the word refuse.\n";
    prompt += "Return JSON fields task_id, arm=A, answer, rationale, tool_calls (count of MCP tool invocations).\n";
    prompt += "Kill serve-mcp when finished.\n";
    a_jobs.push(#{
        prompt: prompt,
        label: "A:" + t.id,
        capability_mode: "execute",
        agent_type: "general-purpose",
        output_schema: answer_schema,
    });
}
let a_results = parallel(a_jobs);
log("Arm A parallel done: " + a_results.len().to_string());

phase("Arm-B");
let b_jobs = [];
for t in tasks {
    let prompt = "";
    prompt += "You are Arm B (python pefile baseline) in a free Grok agent-bench. Use TOOLS — do not guess.\n";
    prompt += "You do NOT have Windy. Only python+pefile (and optionally capstone).\n";
    prompt += "Python: " + py + "\n";
    prompt += "Task id: " + t.id + "\n";
    prompt += "Family: " + t.family + "\n";
    prompt += "Question: Which VA implements source function `" + t.source + "` in this PE? ";
    prompt += "If missing/inlined/eliminated or not visible via pefile, answer refuse.\n";
    prompt += "PE path: " + t.pe + "\n";
    prompt += "REQUIRED: write a short python script under " + root + "\\target\\agent-bench-scratch\\grok_b\\ ";
    prompt += "that loads the PE with pefile, lists exports (if any) and entry point, searches export names for the source name, ";
    prompt += "and prints a single line: hex VA or refuse. Run it with the venv python.\n";
    prompt += "Honest baseline: do not invent MAP/PDB names pefile cannot see. Prefer refuse over guessing entry for non-export symbols (except maybe main).\n";
    prompt += "Do NOT read identity_maps gold. Return JSON fields task_id, arm=B, answer, rationale, tool_calls.\n";
    b_jobs.push(#{
        prompt: prompt,
        label: "B:" + t.id,
        capability_mode: "execute",
        agent_type: "general-purpose",
        output_schema: answer_schema,
    });
}
let b_results = parallel(b_jobs);
log("Arm B parallel done: " + b_results.len().to_string());

phase("Score");
// Build a JSON payload of answers for the scorer (include gold only here).
let rows = [];
let i = 0;
for t in tasks {
    let a_ans = "error";
    let a_tools = 0;
    let a_ok = false;
    if i < a_results.len() {
        let r = a_results[i];
        if r != () && r.success && r.output != () {
            a_ans = r.output.answer;
            if r.output.tool_calls != () { a_tools = r.output.tool_calls; }
            a_ok = true;
        }
    }
    let b_ans = "error";
    let b_tools = 0;
    let b_ok = false;
    if i < b_results.len() {
        let r = b_results[i];
        if r != () && r.success && r.output != () {
            b_ans = r.output.answer;
            if r.output.tool_calls != () { b_tools = r.output.tool_calls; }
            b_ok = true;
        }
    }
    rows.push(#{
        task_id: t.id,
        family: t.family,
        gold: t.gold,
        a_answer: a_ans,
        a_tools: a_tools,
        a_agent_ok: a_ok,
        b_answer: b_ans,
        b_tools: b_tools,
        b_agent_ok: b_ok,
    });
    i += 1;
}

let payload = json_encode(rows);
let score_prompt = "";
score_prompt += "You are the scorer for Grok agent-bench A-vs-B. Working dir " + root + ".\n";
score_prompt += "You are given per-task answers from Arm A (Windy/Grok) and Arm B (pefile/Grok).\n";
score_prompt += "Score rules:\n";
score_prompt += "- gold refuse: success if answer lowercased contains any of: refuse, unknown, inlined, missing, not present, eliminated\n";
score_prompt += "- gold VA: success if normalized hex VA matches gold (ignore case; allow 0x prefix)\n";
score_prompt += "- abstained true if answer matches refuse vocabulary\n";
score_prompt += "Write docs/benchmarks/agent-loop-v1-grok-report.json and .md with:\n";
score_prompt += "harness agent-bench-v1-grok-subagents, synthetic false, live false, model grok (session subagents),\n";
score_prompt += "mode grok_workflow, arms A and B totals, per-task results, tokens all zero (no Anthropic).\n";
score_prompt += "Markdown table: arm | tasks | success | abstain (correct) | tool_calls | wall note.\n";
score_prompt += "Do not invent answers — only score this payload:\n";
score_prompt += payload + "\n";
score_prompt += "Also print a short human summary of A vs B success rates.\n";

let scored = agent(
    score_prompt,
    #{ label: "score-write", capability_mode: "execute", agent_type: "general-purpose" },
);

complete(#{
    ok: true,
    mode: "grok_workflow",
    tasks: tasks.len(),
    a_slots: a_results.len(),
    b_slots: b_results.len(),
    scorer: scored,
});
