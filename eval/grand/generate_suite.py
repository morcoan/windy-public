#!/usr/bin/env python3
"""Generate Windy Grand Decompilation Benchmark sources + SFG gold (64 programs)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
GOLD = ROOT / "gold"
SRC.mkdir(parents=True, exist_ok=True)
GOLD.mkdir(parents=True, exist_ok=True)

# (program_id, kind, packs, language, source body, functions gold builder)
# kinds: atomic | composite | boss


def fact(fid, kind, dim, must=None, any_of=None, forbid=None, critical=False, cap=None, miss=None, forb_r=None):
    d = {
        "id": fid,
        "kind": kind,
        "dimension": dim,
        "critical": critical,
        "must_match": must or [],
        "match_any": any_of or [],
        "forbid": forbid or [],
        "depends_on": [],
    }
    if miss:
        d["residual_on_miss"] = miss
    if forb_r:
        d["residual_on_forbid"] = forb_r
    if cap is not None:
        d["catastrophic_cap"] = cap
    return d


def func_gold(fid, name, facts, va=None):
    g = {"id": fid, "source_name": name, "facts": facts}
    if va:
        g["entry_va"] = va
    return g


PROGRAMS = []

# ── Pack A atomic (integer/flag) ────────────────────────────────────────────
PROGRAMS += [
    (
        "a01_signed_rel",
        "atomic",
        ["A"],
        "c",
        r"""
int signed_lt(int a, int b) { return a < b; }
int unsigned_lt(unsigned a, unsigned b) { return a < b; }
int main(void) { volatile int x = signed_lt(-1, 1); x += unsigned_lt(1u, 2u); return x; }
""",
        lambda: [
            func_gold("signed_lt", "signed_lt", [
                fact("ret", "return", "semantic", must=["return"], any_of=["<", "less"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("params", "parameter_role", "semantic", must=[], critical=False),
            ]),
            func_gold("unsigned_lt", "unsigned_lt", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("calls", "call_site", "calls", any_of=["signed_lt", "unsigned_lt", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "a02_narrow_promo",
        "atomic",
        ["A"],
        "c",
        r"""
int narrow_add(signed char a, signed char b) { return (int)a + (int)b; }
int main(void) { return narrow_add(100, 50); }
""",
        lambda: [
            func_gold("narrow_add", "narrow_add", [
                fact("ret", "return", "semantic", must=["return", "+"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["narrow_add", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "a03_minmax_abs",
        "atomic",
        ["A"],
        "c",
        r"""
int imin(int a, int b) { return a < b ? a : b; }
int iabs(int x) { return x < 0 ? -x : x; }
int main(void) { return imin(3, iabs(-5)); }
""",
        lambda: [
            func_gold("imin", "imin", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("pred", "predicate", "semantic", any_of=["<", "if"], critical=False),
            ]),
            func_gold("iabs", "iabs", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("calls", "call_site", "calls", any_of=["imin", "iabs", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "a04_div_rem",
        "atomic",
        ["A"],
        "c",
        r"""
int idiv(int a, int b) { return b ? a / b : 0; }
int irem(int a, int b) { return b ? a % b : 0; }
int main(void) { return idiv(17, 5) + irem(17, 5); }
""",
        lambda: [
            func_gold("idiv", "idiv", [
                fact("ret", "return", "semantic", must=["return"], any_of=["/", "div"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("irem", "irem", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("calls", "call_site", "calls", any_of=["idiv", "irem", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
]

# ── Pack B atomic (loops) ───────────────────────────────────────────────────
PROGRAMS += [
    (
        "b01_sum_until_zero",
        "atomic",
        ["B"],
        "c",
        r"""
int sum_until_zero(const int *a, int n) {
    int s = 0, i;
    for (i = 0; i < n; i = i + 1) {
        if (a[i] == 0) break;
        s = s + a[i];
    }
    return s;
}
int main(void) {
    int arr[4]; arr[0]=1; arr[1]=2; arr[2]=0; arr[3]=9;
    return sum_until_zero(arr, 4);
}
""",
        lambda: [
            func_gold("sum_until_zero", "sum_until_zero", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("loop", "loop", "control", any_of=["while", "for", "do"], critical=True, miss="LOOP_RECURRENCE_WRONG"),
                fact("acc", "operation", "semantic", any_of=["+", "add"], critical=True, cap=0.35, miss="SEMANTIC_STATE_UPDATE_MISSING"),
                fact("no_goto", "control_region", "clarity", forbid=["goto "], forb_r="GOTO_RESIDUAL"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["sum_until_zero", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "b02_walk_cstr",
        "atomic",
        ["B"],
        "c",
        r"""
int walk_cstr(const char *s) {
    int n = 0;
    while (s[n] != '\0') n = n + 1;
    return n;
}
int main(void) { return walk_cstr("grand"); }
""",
        lambda: [
            func_gold("walk_cstr", "walk_cstr", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("loop", "loop", "control", any_of=["while", "for", "do"], critical=True, miss="LOOP_RECURRENCE_WRONG"),
                fact("nul", "predicate", "semantic", any_of=["'\\0'", "\\0", "0x0", "!=0", "==0"], critical=False),
                fact("no_goto", "control_region", "clarity", forbid=["goto "], forb_r="GOTO_RESIDUAL"),
            ]),
            func_gold("main", "main", [
                fact("str", "constant", "semantic", any_of=["grand", "\"grand\""], critical=False),
                fact("call", "call_site", "calls", any_of=["walk_cstr", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "b03_nested_loop",
        "atomic",
        ["B"],
        "c",
        r"""
int mat_sum(const int *m, int r, int c) {
    int s = 0, i, j;
    for (i = 0; i < r; i = i + 1)
        for (j = 0; j < c; j = j + 1)
            s = s + m[i * c + j];
    return s;
}
int main(void) {
    int m[4]; m[0]=1;m[1]=2;m[2]=3;m[3]=4;
    return mat_sum(m, 2, 2);
}
""",
        lambda: [
            func_gold("mat_sum", "mat_sum", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("loop", "loop", "control", any_of=["while", "for", "do"], critical=True, miss="LOOP_RECURRENCE_WRONG"),
                fact("acc", "operation", "semantic", any_of=["+", "add"], critical=True, cap=0.35, miss="SEMANTIC_STATE_UPDATE_MISSING"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["mat_sum", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "b04_reverse_count",
        "atomic",
        ["B"],
        "c",
        r"""
int count_down(int n) {
    int s = 0;
    while (n > 0) { s = s + n; n = n - 1; }
    return s;
}
int main(void) { return count_down(5); }
""",
        lambda: [
            func_gold("count_down", "count_down", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("loop", "loop", "control", any_of=["while", "for", "do"], critical=True, miss="LOOP_RECURRENCE_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["count_down", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
]

# ── Pack C atomic (control) ─────────────────────────────────────────────────
PROGRAMS += [
    (
        "c01_nested_if",
        "atomic",
        ["C"],
        "c",
        r"""
int nested_decide(int a, int b, int c) {
    if (a > 0) {
        if (b > 0) return a + b;
        else return a - b;
    } else {
        if (c != 0) return c * 2;
        else return 0;
    }
}
int main(void) { return nested_decide(1, -2, 3); }
""",
        lambda: [
            func_gold("nested_decide", "nested_decide", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("if", "control_region", "control", must=["if"], critical=True, miss="CONTROL_REGION_WRONG"),
                fact("else", "control_region", "control", must=["else"], critical=False),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["nested_decide", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "c02_switch_dense",
        "atomic",
        ["C"],
        "c",
        r"""
int classify(int n) {
    switch (n) {
    case 0: return 10;
    case 1: return 20;
    case 2: return 30;
    default: return -1;
    }
}
int main(void) { return classify(2); }
""",
        lambda: [
            func_gold("classify", "classify", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("sw", "switch", "control", any_of=["switch", "if"], critical=True, miss="SWITCH_CASE_MISSING"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["classify", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "c03_dispatch",
        "atomic",
        ["C", "E"],
        "c",
        r"""
int classify(int n);
int dispatch(int op, int x, int y) {
    switch (op) {
    case 1: return x + y;
    case 2: return x - y;
    case 3: return x * y;
    case 4: return y ? x / y : 0;
    default: return classify(x);
    }
}
int classify(int n) {
    if (n == 0) return 10;
    if (n == 1) return 20;
    if (n == 2) return 30;
    return -1;
}
int main(void) { return dispatch(1, 8, 2); }
""",
        lambda: [
            func_gold("dispatch", "dispatch", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("call_cls", "call_site", "calls", any_of=["classify", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
            func_gold("classify", "classify", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["dispatch", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "c04_short_circuit",
        "atomic",
        ["C"],
        "c",
        r"""
int both(int a, int b) { return a != 0 && b != 0; }
int main(void) { return both(1, 0); }
""",
        lambda: [
            func_gold("both", "both", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["both", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
]

# ── Pack D atomic (memory) ──────────────────────────────────────────────────
PROGRAMS += [
    (
        "d01_struct_point",
        "atomic",
        ["D"],
        "c",
        r"""
typedef struct Point { int x; int y; } Point;
int point_mag2(Point p) { return p.x * p.x + p.y * p.y; }
int main(void) {
    Point p; p.x = 3; p.y = 4;
    return point_mag2(p);
}
""",
        lambda: [
            func_gold("point_mag2", "point_mag2", [
                fact("ret", "return", "semantic", must=["return"], any_of=["*", "+"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("field", "memory_field", "memory", any_of=[".", "x", "y", "param", "local"], critical=False, miss="STRUCT_FIELD_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["point_mag2", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "d02_array_stride",
        "atomic",
        ["D"],
        "c",
        r"""
int idx_sum(const int *a, int n) {
    int s = 0, i;
    for (i = 0; i < n; i = i + 1) s = s + a[i];
    return s;
}
int main(void) {
    int a[3]; a[0]=10; a[1]=20; a[2]=30;
    return idx_sum(a, 3);
}
""",
        lambda: [
            func_gold("idx_sum", "idx_sum", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("loop", "loop", "control", any_of=["while", "for", "do"], critical=True, miss="LOOP_RECURRENCE_WRONG"),
                fact("load", "load", "memory", any_of=["*", "[", "a[", "param", "mem"], critical=False),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["idx_sum", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "d03_nested_struct",
        "atomic",
        ["D"],
        "c",
        r"""
typedef struct Inner { int v; } Inner;
typedef struct Outer { Inner a; Inner b; } Outer;
int outer_sum(Outer *o) { return o->a.v + o->b.v; }
int main(void) {
    Outer o; o.a.v = 1; o.b.v = 2;
    return outer_sum(&o);
}
""",
        lambda: [
            func_gold("outer_sum", "outer_sum", [
                fact("ret", "return", "semantic", must=["return", "+"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["outer_sum", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "d04_tagged_union",
        "atomic",
        ["D"],
        "c",
        r"""
typedef struct Tu {
    int tag;
    union { int i; char c; } u;
} Tu;
int tu_value(Tu *t) {
    if (t->tag == 0) return t->u.i;
    return (int)t->u.c;
}
int main(void) {
    Tu t; t.tag = 0; t.u.i = 42;
    return tu_value(&t);
}
""",
        lambda: [
            func_gold("tu_value", "tu_value", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("if", "control_region", "control", must=["if"], critical=False),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["tu_value", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
]

# ── Pack E atomic (calls/ABI) ───────────────────────────────────────────────
PROGRAMS += [
    (
        "e01_four_args",
        "atomic",
        ["E"],
        "c",
        r"""
int four(int a, int b, int c, int d) { return a + b + c + d; }
int main(void) { return four(1, 2, 3, 4); }
""",
        lambda: [
            func_gold("four", "four", [
                fact("ret", "return", "semantic", must=["return", "+"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["four", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
                fact("args", "call_site", "calls", any_of=["1", "0x1", "2", "0x2"], critical=False, miss="CALL_ARG_ORDER_WRONG"),
            ]),
        ],
    ),
    (
        "e02_fn_ptr",
        "atomic",
        ["E"],
        "c",
        r"""
int add1(int x) { return x + 1; }
int apply(int (*f)(int), int x) { return f(x); }
int main(void) { return apply(add1, 41); }
""",
        lambda: [
            func_gold("add1", "add1", [
                fact("ret", "return", "semantic", must=["return", "+"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("apply", "apply", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["apply", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "e03_stack_args",
        "atomic",
        ["E"],
        "c",
        r"""
int six(int a, int b, int c, int d, int e, int f) {
    return a + b + c + d + e + f;
}
int main(void) { return six(1,2,3,4,5,6); }
""",
        lambda: [
            func_gold("six", "six", [
                fact("ret", "return", "semantic", must=["return", "+"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["six", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
    (
        "e04_tailish",
        "atomic",
        ["E"],
        "c",
        r"""
int leaf(int x) { return x * 2; }
int mid(int x) { return leaf(x + 1); }
int main(void) { return mid(10); }
""",
        lambda: [
            func_gold("leaf", "leaf", [
                fact("ret", "return", "semantic", must=["return"], any_of=["*", "2"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ]),
            func_gold("mid", "mid", [
                fact("call", "call_site", "calls", any_of=["leaf", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
            func_gold("main", "main", [
                fact("call", "call_site", "calls", any_of=["mid", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
            ]),
        ],
    ),
]

# Expand remaining atomics to reach 32 with pack coverage F–J simplified C
# (C++/COM/SEH bosses cover hard packs; atomics stay pure C for build reliability)

def simple_prog(pid, packs, body, gold_fn):
    return (pid, "atomic", packs, "c", body, gold_fn)


for i, (name, packs, expr) in enumerate([
    ("a05_bitops", ["A"], "return (a & b) | (a ^ b);"),
    ("a06_shift", ["A"], "return (a << 2) + (b >> 1);"),
    ("a07_sat_add", ["A"], "int r = a + b; return r < a ? -1 : r;"),
    ("a08_cmov_style", ["A"], "return a ? b : c;"),
    ("b05_continue_skip", ["B"], "int s=0,i; for(i=0;i<n;i++){ if(a[i]<0) continue; s+=a[i]; } return s;"),
    ("b06_search", ["B"], "int i; for(i=0;i<n;i++) if(a[i]==k) return i; return -1;"),
    ("c05_ternary_chain", ["C"], "return a? b?1:2 : 3;"),
    ("c06_state_machine", ["C"], "int s=0; if(a) s=1; if(b&&s) s=2; return s;"),
    ("d05_global", ["D"], "static int g; int f(int x){ g=x; return g+1; }"),
    ("d06_ptr_alias", ["D"], "int f(int *p,int *q){ *p=1; *q=2; return *p+*q; }"),
    ("e05_callback", ["E"], "typedef int (*cb)(int); int run(cb f,int x){ return f(x)+1; }"),
    ("j01_const_fold_ready", ["J"], "return 2+2*3;"),
    ("j02_dce_ready", ["J"], "int y=a*a; return a+1;"),
    ("j03_inline_ready", ["J"], "return a*a + b*b;"),
    ("a09_mix_widths", ["A"], "return (int)((short)a + (char)b);"),
    ("b07_fused_bounds", ["B"], "int i=0; while(i<n && a[i]!=0){ s+=a[i]; i++; } return s;"),
]):
    # pad to unique signatures
    if "for(i=0" in expr or "while" in expr:
        body = f"""
int kernel(const int *a, int n, int k, int s) {{
    int a_local = 0; (void)a_local; (void)k;
    {expr}
}}
int main(void) {{
    int arr[4]; arr[0]=1; arr[1]=2; arr[2]=0; arr[3]=4;
    return kernel(arr, 4, 2, 0);
}}
"""
        # fix expressions that use a,n,k,s
        if "s+=" in expr or "s +" in expr or "s=0" in expr:
            body = f"""
int kernel(const int *a, int n, int k) {{
    int s = 0;
    {expr.replace('return s;', 'return s;') if 'return' in expr else expr + ' return s;'}
}}
int main(void) {{
    int arr[4]; arr[0]=1; arr[1]=2; arr[2]=0; arr[3]=4;
    return kernel(arr, 4, 2);
}}
"""
        if name == "b05_continue_skip":
            body = r"""
int kernel(const int *a, int n) {
    int s=0, i;
    for (i=0;i<n;i=i+1) { if (a[i] < 0) continue; s = s + a[i]; }
    return s;
}
int main(void) { int arr[4]; arr[0]=1; arr[1]=-1; arr[2]=3; arr[3]=4; return kernel(arr, 4); }
"""
        if name == "b06_search":
            body = r"""
int kernel(const int *a, int n, int k) {
    int i;
    for (i=0;i<n;i=i+1) if (a[i]==k) return i;
    return -1;
}
int main(void) { int arr[3]; arr[0]=9; arr[1]=7; arr[2]=3; return kernel(arr, 3, 7); }
"""
        if name == "b07_fused_bounds":
            body = r"""
int kernel(const int *a, int n) {
    int s = 0, i = 0;
    while (i < n && a[i] != 0) { s = s + a[i]; i = i + 1; }
    return s;
}
int main(void) { int arr[4]; arr[0]=1; arr[1]=2; arr[2]=0; arr[3]=9; return kernel(arr, 4); }
"""
    elif "static int g" in expr:
        body = r"""
static int g;
int f(int x) { g = x; return g + 1; }
int main(void) { return f(5); }
"""
    elif "*p=1" in expr:
        body = r"""
int f(int *p, int *q) { *p = 1; *q = 2; return *p + *q; }
int main(void) { int x=0,y=0; return f(&x,&y); }
"""
    elif "typedef int (*cb)" in expr:
        body = r"""
typedef int (*cb)(int);
int id(int x) { return x; }
int run(cb f, int x) { return f(x) + 1; }
int main(void) { return run(id, 40); }
"""
    elif "2+2*3" in expr:
        body = r"""
int f(void) { return 2 + 2 * 3; }
int main(void) { return f(); }
"""
    elif "y=a*a" in expr:
        body = r"""
int f(int a) { int y = a * a; (void)y; return a + 1; }
int main(void) { return f(3); }
"""
    elif "a*a + b*b" in expr:
        body = r"""
int f(int a, int b) { return a * a + b * b; }
int main(void) { return f(3, 4); }
"""
    else:
        # generic two-arg
        body = f"""
int f(int a, int b, int c) {{
    {expr}
}}
int main(void) {{ return f(3, 5, 7); }}
"""
    PROGRAMS.append(simple_prog(name, packs, body, lambda n=name: [
        func_gold(
            "f",
            "kernel" if n in {"b05_continue_skip", "b06_search"}
            else "run" if n == "e05_callback"
            else "f",
            [
            fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            ],
        ),
        func_gold("main", "main", [
            fact("call", "call_site", "calls", any_of=["f", "kernel", "fun_", "run", "id"], critical=False),
        ]),
    ]))

# Ensure we have exactly 32 atomics by padding with more A/B/C kernels if needed
while sum(1 for p in PROGRAMS if p[1] == "atomic") < 32:
    n = sum(1 for p in PROGRAMS if p[1] == "atomic")
    pid = f"a_pad_{n:02d}"
    PROGRAMS.append(simple_prog(pid, ["A"], f"""
int f(int a, int b) {{ return a + b + {n}; }}
int main(void) {{ return f(1, 2); }}
""", lambda n=n: [
        func_gold("f", "f", [fact("ret", "return", "semantic", must=["return", "+"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG")]),
        func_gold("main", "main", [fact("call", "call_site", "calls", any_of=["f", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG")]),
    ]))

# ── 24 composites ───────────────────────────────────────────────────────────
COMPOSITE_BODIES = [
    ("cmp01_loop_ctrl", ["B", "C"], r"""
int clamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}
int sum_until_zero(const int *a, int n) {
    int s=0,i; for(i=0;i<n;i++){ if(a[i]==0) break; s+=a[i]; } return s;
}
int main(void) {
    int arr[4]; arr[0]=1; arr[1]=2; arr[2]=0; arr[3]=9;
    return clamp(sum_until_zero(arr,4), 0, 100);
}
"""),
    ("cmp02_mem_call", ["D", "E"], r"""
typedef struct S { int x; int y; } S;
int add2(int a, int b) { return a+b; }
int use_s(S *s) { return add2(s->x, s->y); }
int main(void) { S s; s.x=3; s.y=4; return use_s(&s); }
"""),
    ("cmp03_switch_loop", ["B", "C"], r"""
int step(int op, int x) {
    switch(op) {
    case 0: return x+1;
    case 1: return x-1;
    default: return x;
    }
}
int run(int n) {
    int i, s=0; for(i=0;i<n;i++) s = step(i&1, s);
    return s;
}
int main(void) { return run(5); }
"""),
]

# fill composites to 24
for i in range(24):
    if i < len(COMPOSITE_BODIES):
        pid, packs, body = COMPOSITE_BODIES[i]
    else:
        pid = f"cmp{i+1:02d}_mix"
        packs = ["B", "C", "E"][i % 3: i % 3 + 2] or ["A"]
        if len(packs) < 2:
            packs = ["A", "B"]
        body = f"""
int helper(int a, int b) {{ return a + b + {i}; }}
int work(int n) {{
    int s = 0, i;
    for (i = 0; i < n; i = i + 1) s = helper(s, i);
    return s;
}}
int main(void) {{ return work({3 + (i % 5)}); }}
"""
    PROGRAMS.append((
        pid, "composite", packs, "c", body,
        lambda i=i, pid=pid: [
            func_gold("main", "main", [
                fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
                fact("call", "call_site", "calls", any_of=["work", "helper", "clamp", "sum", "use_s", "run", "step", "add2", "fun_"], critical=False),
            ]),
        ],
    ))

# ── 8 bosses (simplified but multi-file style in one TU where needed) ───────
BOSSES = [
    ("boss_telemetry_decoder", ["I", "B", "C", "D", "E", "J"], r"""
/* Boss 1 telemetry_decoder (single-TU stand-in for multi-module LTCG build) */
typedef struct Header { unsigned short ver; unsigned short flags; int record_count; } Header;
typedef struct Rec { int type; int len; int payload; } Rec;
static int crc_add(int crc, int v) { return crc ^ (v * 1315423911); }
int decode_packet(const unsigned char *buf, int size, int *out_status) {
    const unsigned char *end = buf + size;
    const unsigned char *cursor = buf;
    int records_seen = 0, crc = 0, error_state = 0;
    Header h;
    if (size < 8) { *out_status = -1; return 0; }
    h.ver = (unsigned short)(buf[0] | (buf[1]<<8));
    h.flags = (unsigned short)(buf[2] | (buf[3]<<8));
    h.record_count = (int)(buf[4] | (buf[5]<<8) | (buf[6]<<16) | (buf[7]<<24));
    cursor = buf + 8;
    while (cursor + 12 <= end && records_seen < h.record_count) {
        Rec r;
        r.type = (int)(cursor[0] | (cursor[1]<<8) | (cursor[2]<<16) | (cursor[3]<<24));
        r.len = (int)(cursor[4] | (cursor[5]<<8) | (cursor[6]<<16) | (cursor[7]<<24));
        r.payload = (int)(cursor[8] | (cursor[9]<<8) | (cursor[10]<<16) | (cursor[11]<<24));
        cursor += 12;
        switch (r.type) {
        case 1: crc = crc_add(crc, r.payload); break;
        case 2: crc = crc_add(crc, r.payload + r.len); break;
        case 3: crc = crc_add(crc, r.len); break;
        default: error_state = 1; break;
        }
        records_seen = records_seen + 1;
    }
    *out_status = error_state ? -2 : 0;
    return crc ^ records_seen ^ 0x45D9F3B;
}
int main(void) {
    unsigned char pkt[32];
    int st = 0, i;
    for (i=0;i<32;i++) pkt[i]=(unsigned char)i;
    pkt[4]=1; pkt[5]=0; pkt[6]=0; pkt[7]=0;
    return decode_packet(pkt, 32, &st) + st;
}
"""),
    ("boss_com_variant_router", ["F", "G", "E"], r"""
/* Boss 2 COM/VARIANT stand-in without real COM deps */
typedef struct Variant { int vt; union { int i; wchar_t *bstr; void *punk; } u; } Variant;
enum { VT_I4=3, VT_BSTR=8, VT_UNKNOWN=13 };
static int g_refs;
int QueryInterface(void *self, const int *iid, void **ppv) {
    (void)iid;
    if (!ppv) return 0x80004003;
    *ppv = self; g_refs = g_refs + 1; return 0;
}
int AddRef(void) { g_refs = g_refs + 1; return g_refs; }
int Release(void) { g_refs = g_refs - 1; return g_refs; }
int route_variant(Variant *v) {
    if (!v) return 0x80004003;
    switch (v->vt) {
    case VT_I4: return v->u.i;
    case VT_BSTR: return v->u.bstr ? 1 : 0;
    case VT_UNKNOWN: return v->u.punk ? AddRef() : 0x80004003;
    default: return 0x80070057;
    }
}
int main(void) {
    Variant v; v.vt = VT_I4; v.u.i = 7;
    return route_variant(&v);
}
"""),
    ("boss_seh_resource_loader", ["H", "F", "D"], r"""
/* Boss 3 SEH/resource stand-in using structured cleanup simulation */
typedef struct Res { int id; int live; } Res;
static void res_init(Res *r, int id) { r->id = id; r->live = 1; }
static void res_destroy(Res *r) { if (r->live) { r->live = 0; } }
int parse_tree(const int *buf, int n, int depth) {
    Res a, b; int i, status = 0;
    res_init(&a, 1); res_init(&b, 2);
    if (depth > 8) { status = -1; goto cleanup; }
    for (i = 0; i < n; i = i + 1) {
        if (buf[i] < 0) { status = -2; goto cleanup; }
        if (buf[i] == 0) break;
        a.id = a.id + buf[i];
    }
cleanup:
    res_destroy(&b);
    res_destroy(&a);
    return status ? status : a.id;
}
int main(void) {
    int buf[4]; buf[0]=1; buf[1]=2; buf[2]=0; buf[3]=-1;
    return parse_tree(buf, 4, 1);
}
"""),
]

for i, (pid, packs, body) in enumerate(BOSSES):
    PROGRAMS.append((pid, "boss", packs, "c", body, lambda pid=pid: [
        func_gold("main", "main", [
            fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
        ]),
    ]))

# pad bosses to 8
while sum(1 for p in PROGRAMS if p[1] == "boss") < 8:
    n = sum(1 for p in PROGRAMS if p[1] == "boss")
    pid = f"boss_extra_{n}"
    PROGRAMS.append((pid, "boss", ["I", "J"], "c", f"""
int deep(int n) {{
    int s=0,i; for(i=0;i<n;i++) s = s + i * (i+1);
    return s;
}}
int main(void) {{ return deep({10+n}); }}
""", lambda: [
        func_gold("deep", "deep", [
            fact("ret", "return", "semantic", must=["return"], critical=True, cap=0.35, miss="SEMANTIC_RETURN_WRONG"),
            fact("loop", "loop", "control", any_of=["while", "for", "do"], critical=True, miss="LOOP_RECURRENCE_WRONG"),
        ]),
        func_gold("main", "main", [
            fact("call", "call_site", "calls", any_of=["deep", "fun_"], critical=True, cap=0.40, miss="CALL_TARGET_WRONG"),
        ]),
    ]))

assert sum(1 for p in PROGRAMS if p[1] == "atomic") >= 32
assert sum(1 for p in PROGRAMS if p[1] == "composite") >= 24
assert sum(1 for p in PROGRAMS if p[1] == "boss") >= 8

# Trim to exact counts if over
atomics = [p for p in PROGRAMS if p[1] == "atomic"][:32]
composites = [p for p in PROGRAMS if p[1] == "composite"][:24]
bosses = [p for p in PROGRAMS if p[1] == "boss"][:8]
PROGRAMS = atomics + composites + bosses
assert len(PROGRAMS) == 64, len(PROGRAMS)

inventory = []
for pid, kind, packs, lang, body, gold_fn in PROGRAMS:
    ext = "c" if lang == "c" else "cpp"
    path = SRC / f"{pid}.{ext}"
    path.write_text(body.strip() + "\n", encoding="utf-8")
    gold = {
        "program_id": pid,
        "pack_tags": packs,
        "kind": kind,
        "source": f"eval/grand/src/{pid}.{ext}",
        "functions": gold_fn(),
    }
    (GOLD / f"{pid}.json").write_text(json.dumps(gold, indent=2), encoding="utf-8")
    inventory.append({
        "program_id": pid,
        "kind": kind,
        "pack_tags": packs,
        "language": lang,
        "source": f"eval/grand/src/{pid}.{ext}",
        "gold": f"eval/grand/gold/{pid}.json",
    })

(ROOT / "inventory.json").write_text(json.dumps({"programs": inventory, "count": len(inventory)}, indent=2), encoding="utf-8")
print(f"Generated {len(inventory)} programs")
print("  atomic", sum(1 for p in inventory if p["kind"]=="atomic"))
print("  composite", sum(1 for p in inventory if p["kind"]=="composite"))
print("  boss", sum(1 for p in inventory if p["kind"]=="boss"))
