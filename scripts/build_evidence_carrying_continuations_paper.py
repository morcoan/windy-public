#!/usr/bin/env python3
"""Build the final Windy evidence-carrying continuations paper.

The document is intentionally authored as a fixed ten-page corporate research
paper.  All source claims remain local and development-set qualifications are
kept adjacent to the results they constrain.
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "paper" / "Windy_Evidence_Carrying_Continuations.pdf"

PAGE_W, PAGE_H = letter
MARGIN = 54
CONTENT_W = PAGE_W - 2 * MARGIN
TOP = 724
BOTTOM = 47

INK = HexColor("#000000")
MUTED = HexColor("#3f3f3f")
FAINT = HexColor("#666666")
LINE = HexColor("#dedede")
LINE_DARK = HexColor("#b8b8b8")
SURFACE = HexColor("#f6f6f6")
WHITE = colors.white


def register_fonts() -> None:
    font_dir = Path("C:/Windows/Fonts")
    faces = {
        "Arial": "arial.ttf",
        "Arial-Bold": "arialbd.ttf",
        "Arial-Italic": "ariali.ttf",
        "Arial-BoldItalic": "arialbi.ttf",
        "Consolas": "consola.ttf",
        "Consolas-Bold": "consolab.ttf",
    }
    fallbacks = {
        "Consolas": "LiberationMono-Regular.ttf",
        "Consolas-Bold": "LiberationMono-Bold.ttf",
    }
    for name, filename in faces.items():
        path = font_dir / filename
        if not path.exists() and name in fallbacks:
            path = font_dir / fallbacks[name]
        if not path.exists():
            raise FileNotFoundError(f"Required font is missing: {path}")
        pdfmetrics.registerFont(TTFont(name, str(path)))
    pdfmetrics.registerFontFamily(
        "Arial",
        normal="Arial",
        bold="Arial-Bold",
        italic="Arial-Italic",
        boldItalic="Arial-BoldItalic",
    )


BODY = ParagraphStyle(
    "Body",
    fontName="Arial",
    fontSize=11,
    leading=15,
    textColor=INK,
    spaceAfter=7,
)
BODY_TIGHT = ParagraphStyle(
    "BodyTight",
    parent=BODY,
    fontSize=10.5,
    leading=14.5,
    spaceAfter=5,
)
SMALL = ParagraphStyle(
    "Small",
    parent=BODY,
    fontSize=9.5,
    leading=13,
    textColor=INK,
    spaceAfter=4,
)
CAPTION = ParagraphStyle(
    "Caption",
    parent=SMALL,
    fontName="Arial",
    fontSize=10,
    leading=13.5,
    alignment=TA_CENTER,
    textColor=HexColor("#333333"),
)
H2 = ParagraphStyle(
    "H2",
    fontName="Arial-Bold",
    fontSize=22,
    leading=25,
    textColor=INK,
    spaceAfter=9,
)
H3 = ParagraphStyle(
    "H3",
    fontName="Arial-Bold",
    fontSize=13,
    leading=16,
    textColor=INK,
    spaceAfter=5,
)
H4 = ParagraphStyle(
    "H4",
    fontName="Arial-Bold",
    fontSize=11,
    leading=14,
    textColor=INK,
    spaceAfter=3,
)
TABLE_HEAD = ParagraphStyle(
    "TableHead",
    fontName="Arial-Bold",
    fontSize=8,
    leading=10,
    textColor=WHITE,
    alignment=TA_LEFT,
)
TABLE_CELL = ParagraphStyle(
    "TableCell",
    fontName="Arial",
    fontSize=8,
    leading=10,
    textColor=INK,
)
TABLE_CELL_RIGHT = ParagraphStyle(
    "TableCellRight",
    parent=TABLE_CELL,
    alignment=TA_RIGHT,
)
REF = ParagraphStyle(
    "Reference",
    fontName="Arial",
    fontSize=10,
    leading=13.5,
    textColor=INK,
    spaceAfter=4.2,
)


def para(c: canvas.Canvas, text: str, x: float, y: float, width: float, style: ParagraphStyle = BODY) -> float:
    p = Paragraph(text, style)
    _, height = p.wrap(width, PAGE_H)
    draw_y = round((y - height) * 2) / 2
    draw_x = round(x * 2) / 2
    p.drawOn(c, draw_x, draw_y)
    return draw_y - style.spaceAfter


def heading(c: canvas.Canvas, text: str, y: float, level: int = 2, x: float = MARGIN, width: float = CONTENT_W) -> float:
    return para(c, text, x, y, width, H2 if level == 2 else H3 if level == 3 else H4)


def page_header(c: canvas.Canvas, page: int, section: str) -> None:
    c.setStrokeColor(LINE_DARK)
    c.setLineWidth(0.55)
    c.line(MARGIN, 752, PAGE_W - MARGIN, 752)
    c.setFillColor(MUTED)
    c.setFont("Arial-Bold", 7.5)
    c.drawString(MARGIN, 762, "WINDY V0.3.0 / EVIDENCE-CARRYING CONTINUATIONS")
    c.drawRightString(PAGE_W - MARGIN, 762, section.upper())
    c.setFont("Arial", 8)
    c.setFillColor(FAINT)
    c.drawCentredString(PAGE_W / 2, 26, str(page))


def begin_page(c: canvas.Canvas, page: int, section: str, bookmark: str | None = None, title: str | None = None) -> float:
    page_header(c, page, section)
    if bookmark:
        c.bookmarkPage(bookmark)
        c.addOutlineEntry(title or section, bookmark, level=0, closed=False)
    return TOP


def end_page(c: canvas.Canvas, y: float, page: int) -> None:
    if y < BOTTOM:
        raise RuntimeError(f"Page {page} overflowed: y={y:.1f}")
    c.showPage()


def section_kicker(c: canvas.Canvas, text: str, x: float, y: float) -> float:
    c.setFillColor(FAINT)
    c.setFont("Arial-Bold", 7.5)
    c.drawString(x, y, text.upper())
    return y - 14


def rule(c: canvas.Canvas, y: float, x: float = MARGIN, width: float = CONTENT_W, tone=LINE) -> float:
    c.setStrokeColor(tone)
    c.setLineWidth(0.55)
    c.line(x, y, x + width, y)
    return y - 10


def callout(c: canvas.Canvas, label: str, text: str, x: float, y: float, width: float, style: ParagraphStyle = BODY_TIGHT) -> float:
    inner = width - 28
    p = Paragraph(text, style)
    _, ph = p.wrap(inner, PAGE_H)
    height = ph + 40
    c.setFillColor(SURFACE)
    c.rect(x, y - height, width, height, fill=1, stroke=0)
    c.setFillColor(INK)
    c.rect(x, y - height, 4, height, fill=1, stroke=0)
    c.setFont("Arial-Bold", 7.5)
    c.drawString(x + 14, y - 16, label.upper())
    c.setStrokeColor(LINE_DARK)
    c.line(x + 14, y - 24, x + width - 14, y - 24)
    p.drawOn(c, round((x + 14) * 2) / 2, round((y - 33 - ph) * 2) / 2)
    return y - height - 10


def bullet_list(c: canvas.Canvas, items: list[str], x: float, y: float, width: float, style: ParagraphStyle = BODY_TIGHT, gap: float = 3) -> float:
    for item in items:
        c.setFillColor(INK)
        c.rect(x, y - 7, 3, 3, fill=1, stroke=0)
        p = Paragraph(item, style)
        _, ph = p.wrap(width - 15, PAGE_H)
        p.drawOn(c, round((x + 15) * 2) / 2, round((y - ph) * 2) / 2)
        y -= ph + gap
    return y


def table_pdf(
    c: canvas.Canvas,
    rows: list[list[str]],
    x: float,
    y: float,
    widths: list[float],
    numeric_cols: set[int] | None = None,
    font_size: float = 8,
) -> float:
    numeric_cols = numeric_cols or set()
    cell_style = ParagraphStyle("DynamicCell", parent=TABLE_CELL, fontSize=font_size, leading=round((font_size + 2) * 2) / 2)
    right_style = ParagraphStyle("DynamicRight", parent=cell_style, alignment=TA_RIGHT)
    data: list[list[Paragraph]] = []
    for row_index, row in enumerate(rows):
        cells: list[Paragraph] = []
        for col_index, value in enumerate(row):
            if row_index == 0:
                style = TABLE_HEAD
            else:
                style = right_style if col_index in numeric_cols else cell_style
            cells.append(Paragraph(value, style))
        data.append(cells)
    t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, -1), "Arial"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 1), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.45, LINE_DARK),
    ]
    for row_index in range(2, len(rows), 2):
        table_style.append(("BACKGROUND", (0, row_index), (-1, row_index), SURFACE))
    t.setStyle(TableStyle(table_style))
    _, th = t.wrap(sum(widths), PAGE_H)
    draw_y = round((y - th) * 2) / 2
    t.drawOn(c, round(x * 2) / 2, draw_y)
    return draw_y - 7


def table_caption(c: canvas.Canvas, text: str, y: float, x: float = MARGIN, width: float = CONTENT_W) -> float:
    return para(c, text, x, y, width, CAPTION)


def cover(c: canvas.Canvas) -> None:
    c.bookmarkPage("cover")
    c.addOutlineEntry("Cover", "cover", level=0, closed=False)
    left = 70
    right = PAGE_W - 70
    c.setFillColor(FAINT)
    c.setFont("Arial-Bold", 8)
    c.drawString(left, 756, "HUSENA R&D / TECHNICAL PAPER 01")

    c.setFillColor(INK)
    c.setFont("Arial", 84)
    c.drawString(left, 616, "Windy")

    c.setFont("Arial", 27)
    c.drawString(left, 503, "The Interface Is the Model")
    c.setFont("Arial", 15)
    c.setFillColor(MUTED)
    c.drawString(left, 470, "Evidence-Carrying Continuations for")
    c.drawString(left, 448, "Small-Model Static Binary Analysis")

    lede = (
        "A terminal-hosted, evidence-first substrate that moves tool selection, state, "
        "verification, and provenance out of the model and into a deterministic local protocol."
    )
    para(c, lede, left, 394, 430, ParagraphStyle("CoverLede", parent=BODY, fontSize=11.5, leading=17, textColor=MUTED))

    c.setStrokeColor(INK)
    c.setLineWidth(0.8)
    c.line(left, 281, right, 281)
    fact_w = (right - left) / 4
    facts = [
        ("RELEASE", "v0.3.0"),
        ("DOMAIN", "Windows PE / MDMP"),
        ("INTERFACE", "Six MCP tools"),
        ("STATUS", "Final technical paper"),
    ]
    for i, (label, value) in enumerate(facts):
        x = left + i * fact_w
        if i:
            c.setStrokeColor(LINE)
            c.line(x, 281, x, 218)
        c.setFillColor(FAINT)
        c.setFont("Arial-Bold", 7)
        c.drawString(x + (10 if i else 0), 257, label)
        c.setFillColor(INK)
        c.setFont("Arial-Bold", 9)
        c.drawString(x + (10 if i else 0), 235, value)
    c.setStrokeColor(LINE)
    c.line(left, 218, right, 218)

    c.setFillColor(MUTED)
    c.setFont("Arial", 9)
    c.drawString(left, 174, "Demetrius Greses Jr. / Husena LLC")
    c.drawRightString(right, 174, "30 August 2026")
    c.setFillColor(FAINT)
    c.setFont("Arial", 8)
    c.drawString(left, 70, "STATIC ANALYSIS ONLY / LOCAL / MODEL-AGNOSTIC")
    c.drawRightString(right, 70, "HUSENA LLC")
    c.showPage()


def executive_summary(c: canvas.Canvas) -> None:
    y = begin_page(c, 2, "Executive summary", "summary", "Executive summary")
    y = section_kicker(c, "Decision brief", MARGIN, y)
    y = heading(c, "Executive summary", y)
    y = callout(
        c,
        "Research question",
        "Can a deterministic analytical substrate improve an untrained small language model's static reverse-engineering performance by removing protocol mechanics and returning only compact, verifiable evidence?",
        MARGIN,
        y,
        CONTENT_W,
    )

    c.setFont("Arial-Bold", 7.5)
    c.setFillColor(FAINT)
    c.drawString(MARGIN, y - 2, "PAIRED BENCHMARK OUTCOMES / DEVELOPMENT SET")
    y -= 16
    card_gap = 8
    card_w = (CONTENT_W - 3 * card_gap) / 4
    cards = [
        ("TASK SUCCESS", "3/12", "12/12", "+75 points"),
        ("VALID CALLS", "82.81%", "100%", "+17.19 points"),
        ("MEDIAN CALLS", "5.5", "2", "-63.6%"),
        ("TOOL OUTPUT", "5,314 B", "1,651 B", "-68.9%"),
    ]
    for i, (label, before, after, delta) in enumerate(cards):
        x = MARGIN + i * (card_w + card_gap)
        c.setFillColor(SURFACE)
        c.rect(x, y - 83, card_w, 83, fill=1, stroke=0)
        c.setFillColor(FAINT)
        c.setFont("Arial-Bold", 7)
        c.drawString(x + 10, y - 15, label)
        c.setFillColor(INK)
        c.setFont("Arial-Bold", 16)
        c.drawString(x + 10, y - 42, after)
        c.setFillColor(MUTED)
        c.setFont("Arial", 7.5)
        c.drawString(x + 10, y - 60, f"from {before}")
        c.setFont("Arial-Bold", 7.5)
        c.drawString(x + 10, y - 73, delta)
    y -= 96

    col_gap = 24
    col_w = (CONTENT_W - col_gap) / 2
    left_x = MARGIN
    right_x = MARGIN + col_w + col_gap
    left_y = heading(c, "Bottom line", y, 3, left_x, col_w)
    left_y = para(
        c,
        "Windy v0.3 asks the analytical substrate to carry the protocol burden that a small model handles poorly. Its Evidence Query VM compiles intent into typed, demand-driven work and returns server-bound continuation tickets with compact, provenance-linked evidence deltas.",
        left_x,
        left_y,
        col_w,
        BODY_TIGHT,
    )
    left_y = para(
        c,
        "In the 12-case local benchmark, a fresh low-effort gpt-5.6-luna agent improved from 3/12 tasks with frozen v0.2 to 12/12 with v0.3. Valid calls reached 100%, median calls fell to 2, median tool output fell to 1,651 bytes, and supported-answer time fell from 46.32 to 9.44 seconds.",
        left_x,
        left_y,
        col_w,
        BODY_TIGHT,
    )
    right_y = heading(c, "Abstract", y, 3, right_x, col_w)
    right_y = para(
        c,
        "Tool-using language models are usually improved by making the model larger, training it on tool traces, or supplying more context. This paper studies the opposite intervention: make the analytical substrate carry more of the protocol burden. Windy v0.3 is a terminal-hosted Model Context Protocol substrate for static Windows binary analysis.",
        right_x,
        right_y,
        col_w,
        BODY_TIGHT,
    )
    right_y = para(
        c,
        "The six-tool surface has a 3,170-byte schema. On a 53.9 MB self binary, mapped, catalog, and sketch stages reached p50 latencies of 79, 206, and 670 ms with 62.6 MiB peak RSS. A compact deep index used 85.9 MB for 10.74 million records. The architecture tests whether weak-model reverse engineering improves when tool use is compiled into evidence-carrying continuations.",
        right_x,
        right_y,
        col_w,
        BODY_TIGHT,
    )
    right_y = para(
        c,
        "<b>Keywords:</b> agentic binary analysis; small language models; MCP; demand-driven analysis; tool use; evidence provenance; continuation protocols",
        right_x,
        right_y,
        col_w,
        SMALL,
    )
    end_page(c, min(left_y, right_y), 2)


def introduction(c: canvas.Canvas) -> None:
    y = begin_page(c, 3, "Introduction and context", "introduction", "1. Introduction")
    y = heading(c, "1. Introduction", y)
    gap = 24
    col_w = (CONTENT_W - gap) / 2
    lx, rx = MARGIN, MARGIN + col_w + gap

    ly = para(c, "Static reverse engineering is a hostile tool-use environment for a small language model. The model must select among many operations, bind virtual addresses and target identifiers, wait for analysis readiness, interpret partial results, preserve provenance, and avoid unsupported claims. Each obligation consumes context and creates a new failure boundary.", lx, y, col_w, BODY)
    ly = para(c, "A conventional interface exposes more expert operations and asks the model to plan more carefully. Windy v0.3 instead asks which obligations can be removed from the model entirely. An investigation begins with a target or path, typed intent, natural-language question, and budget. The server compiles the request into deterministic operators, performs the cheapest useful analysis, and returns an evidence delta with at most three opaque actions.", lx, ly, col_w, BODY)
    ly = para(c, "A common continuation requires only an <font name='Consolas'>action_id</font>; target, revision, arguments, readiness, cost, and expiry are already bound. Large results are immutable paged artifacts rather than prompt payloads. The model still supplies intent and interprets evidence, while mechanics are expressed in code, type checks, budgets, and revision guards.", lx, ly, col_w, BODY)
    ly = heading(c, "Contributions", ly - 2, 3, lx, col_w)
    ly = bullet_list(c, [
        "An Evidence Query VM that compiles investigative intent into typed, deterministic static-analysis operators without embedding a planner or model.",
        "Evidence-carrying continuations that bind analytical state and return compact deltas with support, uncertainty, omissions, and stable evidence identifiers.",
        "A demand-driven analysis lattice and compact function-sketch domain that postpone expensive analysis until requested.",
        "A deterministic microbenchmark showing a 75-point development-set gain with fewer calls, fewer schema bytes, and less tool output.",
    ], lx, ly, col_w, SMALL, 4)

    ry = heading(c, "2. Related Work and Design Position", y, 2, rx, col_w)
    ry = heading(c, "Weak-model tool use", ry, 3, rx, col_w)
    ry = para(c, "Shen et al. split tool use into planning, calling, and summarization because one small model struggles to learn all roles [1]. Windy moves that split across a systems boundary: intent and synthesis remain external; selection, binding, readiness, budgets, and evidence bookkeeping become deterministic server work.", rx, ry, col_w, BODY_TIGHT)
    ry = heading(c, "Tool retrieval and context", ry, 3, rx, col_w)
    ry = para(c, "ToolLLM and Re-Invoke motivate compact capability selection [2, 3], but retrieval still leaves arguments and state transitions to the caller. Windy converts selected work into prevalidated actions. Lost in the Middle motivates short evidence deltas, stable paging, 2 KiB observations, and server-side deduplication [4].", rx, ry, col_w, BODY_TIGHT)
    ry = heading(c, "Demand analysis and binary analysis", ry, 3, rx, col_w)
    ry = para(c, "Demand analysis computes facts required by a query instead of solving a whole program eagerly [5]. Windy applies that discipline across six analysis stages. BINREX demonstrates semantic retrieval, task adaptation, and verifiable reasoning for agentic binary analysis [6]. Windy asks whether a compact, model-agnostic substrate can make a weak caller more reliable and efficient.", rx, ry, col_w, BODY_TIGHT)
    ry = heading(c, "What is potentially novel", ry, 3, rx, col_w)
    ry = para(c, "The ingredients are established: demand analysis, tool retrieval, capabilities, state machines, abstract interpretation, provenance, and static verification. Windy combines them in a reverse-engineering MCP server that issues executable, state-bound continuations carrying evidence identifiers and verification state. The contribution is the architecture and its measured behavior.", rx, ry, col_w, BODY_TIGHT)
    end_page(c, min(ly, ry), 3)


def architecture_figure(c: canvas.Canvas, y: float) -> float:
    c.setFont("Arial-Bold", 12)
    c.setFillColor(INK)
    c.drawCentredString(PAGE_W / 2, y, "Demand-driven analysis lattice")
    c.setFont("Arial", 8.5)
    c.setFillColor(MUTED)
    c.drawCentredString(PAGE_W / 2, y - 14, "Only the stage required by an investigation is promoted")
    y -= 32
    box_gap = 8
    box_w = (CONTENT_W - 5 * box_gap) / 6
    stages = ["mapped", "catalog", "sketch", "function", "global", "deep"]
    for i, stage in enumerate(stages):
        x = MARGIN + i * (box_w + box_gap)
        c.setFillColor(SURFACE if i < 3 else HexColor("#ededed"))
        c.setStrokeColor(INK if i in (0, 5) else LINE_DARK)
        c.setLineWidth(0.8)
        c.roundRect(x, y - 34, box_w, 34, 5, fill=1, stroke=1)
        c.setFillColor(INK)
        c.setFont("Arial-Bold", 8)
        c.drawCentredString(x + box_w / 2, y - 21, stage)
        if i < 5:
            ax = x + box_w
            c.setStrokeColor(MUTED)
            c.line(ax + 1.5, y - 17, ax + box_gap - 2, y - 17)
            c.setFillColor(MUTED)
            c.drawRightString(ax + box_gap - 1, y - 20, ">")
    y -= 62

    widths = [150, 190, 138]
    labels = [
        ("Small language model", "intent + action_id"),
        ("Evidence Query VM", "compile / bind / schedule / verify"),
        ("Evidence delta", "support + uncertainty"),
    ]
    x = MARGIN + (CONTENT_W - sum(widths) - 24) / 2
    for i, ((title, subtitle), bw) in enumerate(zip(labels, widths)):
        c.setFillColor(SURFACE if i != 1 else HexColor("#ededed"))
        c.setStrokeColor(INK)
        c.roundRect(x, y - 52, bw, 52, 5, fill=1, stroke=1)
        c.setFillColor(INK)
        c.setFont("Arial-Bold", 9)
        c.drawCentredString(x + bw / 2, y - 21, title)
        c.setFillColor(MUTED)
        c.setFont("Arial", 8)
        c.drawCentredString(x + bw / 2, y - 37, subtitle)
        if i < 2:
            c.setStrokeColor(MUTED)
            c.line(x + bw + 3, y - 26, x + bw + 9, y - 26)
            c.setFillColor(MUTED)
            c.drawString(x + bw + 9, y - 29, ">")
            x += bw + 12
        else:
            x += bw
    y -= 65
    return table_caption(c, "Figure 1. The model states intent; the server compiles mechanics and returns bounded evidence. Analysis is promoted only as demanded.", y)


def architecture(c: canvas.Canvas) -> None:
    y = begin_page(c, 4, "Architecture and protocol", "architecture", "3. Evidence Query VM")
    y = heading(c, "3. Evidence Query VM", y)
    y = para(c, "Windy's Evidence Query VM is the boundary between a natural-language investigation and typed static-analysis work. It binds identifiers, chooses the cheapest useful operator, preserves revision and budget state, verifies requested high-confidence claims, and emits compact evidence rather than whole-image dumps.", MARGIN, y, CONTENT_W, BODY)
    y = architecture_figure(c, y - 4)

    y = heading(c, "Public protocol", y, 3)
    protocol = [
        ["Tool", "Contract"],
        ["<font name='Consolas'>windy_status</font>", "Inspect target, investigation, job, cache, or runtime state."],
        ["<font name='Consolas'>investigation_start</font>", "Open or reuse a target; compile intent, question, and budget."],
        ["<font name='Consolas'>investigation_step</font>", "Execute a server-issued action ticket, commonly with <font name='Consolas'>action_id</font> only."],
        ["<font name='Consolas'>evidence_read</font>", "Page immutable evidence and large artifacts."],
        ["<font name='Consolas'>change_commit</font>", "Commit a verified proposal with revision and idempotency guards."],
        ["<font name='Consolas'>target_close</font>", "Flush annotations, cancel target work, and close the session."],
    ]
    y = table_pdf(c, protocol, MARGIN, y, [155, CONTENT_W - 155])
    y = table_caption(c, "Table 1. The complete always-advertised Windy v0.3 tool surface.", y)
    y = para(c, "The interface intentionally breaks with v0.2. Specialized decompilation, SSA, dump, workspace, history, vtable, cross-project, and index operations remain internal operators or resource-backed artifacts. Action tickets name the exact operation but remain opaque to the caller and cryptographically bound to investigation state. Expiry, tampering, and revision conflicts return machine-readable repair choices instead of silently changing meaning.", MARGIN, y, CONTENT_W, BODY_TIGHT)
    end_page(c, y, 4)


def continuations(c: canvas.Canvas) -> None:
    y = begin_page(c, 5, "Continuations and analysis", "continuations", "Evidence-carrying continuations")
    gap = 24
    col_w = (CONTENT_W - gap) / 2
    lx, rx = MARGIN, MARGIN + col_w + gap
    ly = heading(c, "Typed intents and deterministic compilation", y, 3, lx, col_w)
    ly = para(c, "The compiler accepts nine intents: <font name='Consolas'>locate</font>, <font name='Consolas'>explain</font>, <font name='Consolas'>trace</font>, <font name='Consolas'>verify</font>, <font name='Consolas'>read_data</font>, <font name='Consolas'>compare</font>, <font name='Consolas'>edit</font>, <font name='Consolas'>capability</font>, and <font name='Consolas'>dump</font>. Natural-language terms remain lexical evidence. A deterministic ontology rewrites phrases into constraints over sketches, metadata, relationships, and proof obligations. Constraint intersection ranks candidates; structural analysis verifies requested high-confidence claims.", lx, ly, col_w, BODY_TIGHT)
    code_style = ParagraphStyle("Code", fontName="Consolas", fontSize=8, leading=11, textColor=INK)
    ly = callout(c, "Protocol shape", "investigation_start(path, intent, question, budget)<br/>  -&gt; investigation_id, state, evidence_delta, [action_id ...]<br/><br/>investigation_step(investigation_id, action_id)<br/>  -&gt; new_evidence_only, completeness, uncertainty, [action_id ...]", lx, ly, col_w, code_style)
    ly = heading(c, "Machine-readable repair", ly, 3, lx, col_w)
    ly = para(c, "Weak callers fail predictably. Invalid calls return a small set of legal repairs instead of a prose error dump. When a requested path is absent, Windy may recover one uniquely missing ASCII filename character; ambiguous repairs fail closed. The mechanism is generic, evaluation-derived, and covered by negative tests.", lx, ly, col_w, BODY_TIGHT)

    ry = heading(c, "Evidence-carrying continuations", y, 2, rx, col_w)
    ry = para(c, "Evidence-carrying describes a protocol property, not a formal proof calculus. Each delta refers to stable evidence records with provenance, target revision, completeness, uncertainty, and omitted counts. The server retains prior evidence and returns only new material.", rx, ry, col_w, BODY)
    ry = para(c, "Continuations are capability-like: possession authorizes one prevalidated transition, while revision and expiry constrain replay. Mutating continuations additionally require idempotency keys and optimistic revision checks. A valid action therefore cannot be redirected to a different target or reinterpret stale arguments.", rx, ry, col_w, BODY)
    ry = callout(c, "Core protocol idea", "Move selection, argument binding, readiness, state, and evidence bookkeeping into the substrate. Leave investigative intent and evidence synthesis with the external model.", rx, ry, col_w, SMALL)
    y = min(ly, ry) - 8

    y = heading(c, "4. Demand-Driven Static Analysis", y)
    stages = [
        ["Stage", "Retained work", "Promotion trigger"],
        ["mapped", "Memory map, image validation, essential identity", "Target open"],
        ["catalog", "Headers, sections, imports, exports, unwind/PDB seeds", "Triage or metadata query"],
        ["sketch", "Streaming decode into compact per-function semantic facts", "Intent ranking"],
        ["function", "CFG, stack, calls, SSA, types, native decompilation window", "Candidate verification or inspect"],
        ["global", "Incoming xrefs, string refs, indirect edges, cross-function indexes", "Trace or global query"],
        ["deep", "Partitioned instruction, token, numeric, and motif indexes", "Explicit deep request"],
    ]
    y = table_pdf(c, stages, MARGIN, y, [60, 287, CONTENT_W - 347], font_size=8)
    y = table_caption(c, "Table 2. Monotone stage promotions make readiness explicit and prevent eager whole-image work.", y)
    end_page(c, y, 5)


def evaluation(c: canvas.Canvas) -> None:
    y = begin_page(c, 6, "Evaluation method", "evaluation", "5. Failure-Driven Evaluation")
    y = heading(c, "5. Failure-Driven Evaluation", y)
    gap = 24
    col_w = (CONTENT_W - gap) / 2
    lx, rx = MARGIN, MARGIN + col_w + gap
    ly = heading(c, "Function sketches and compact indexing", y, 3, lx, col_w)
    ly = para(c, "The sketch stage retains ranking facts - control-flow shape, calls, strings, imports, constants, memory behavior, dependencies, side effects, and semantic motifs - while reconstructing full decoder objects only for active function windows.", lx, ly, col_w, BODY_TIGHT)
    ly = para(c, "Deep indexing stores sorted eight-byte instruction records instead of full instruction objects and per-instruction maps. Checksummed, ABI-keyed partitions are atomically written, memory-mappable, corruption recoverable, and bounded by a 5 GiB disk LRU. Mutable annotations remain separate.", lx, ly, col_w, BODY_TIGHT)
    ly = heading(c, "Scheduling and memory", ly, 3, lx, col_w)
    ly = para(c, "A four-worker priority pool orders foreground work, cache loads, warming, and optional indexing. Single-flight deduplication and bounded waits prevent duplicate work and zero-work polling. Analysis partitions and decoded windows share a 1 GiB process budget.", lx, ly, col_w, BODY_TIGHT)

    ry = heading(c, "Microbenchmark", y, 3, rx, col_w)
    ry = para(c, "The external SQLite evaluator generates three neutral PE programs in P0 and P2 variants, then stages stripped binaries without source, symbols, descriptive filenames, or adjacent gold. Twelve deterministic cases cover location, explanation, relationships, provenance, data, types, verification, abstention, and edit persistence.", rx, ry, col_w, BODY_TIGHT)
    ry = para(c, "Each case used a fresh low-reasoning gpt-5.6-luna agent with only the task, sanitized path, MCP endpoint, schemas, and budgets. Limits were six calls, 8 KiB cumulative tool output, and a 250-token answer. Source or gold inspection invalidated a run.", rx, ry, col_w, BODY_TIGHT)
    ry = heading(c, "Iteration rule", ry, 3, rx, col_w)
    ry = para(c, "Failures were classified by stage. One mechanism changed at a time when practical and remained only when it improved a canary or reduced context or latency by 15% without degrading quality or honest abstention.", rx, ry, col_w, BODY_TIGHT)
    y = min(ly, ry) - 7

    failures = [
        ["Observed failure", "Mechanism introduced", "Protocol effect"],
        ["Hidden operation selection", "Typed intent compiler", "Model chooses task class, not low-level tool"],
        ["Malformed capability arguments", "Server-bound action ticket", "Arguments are prevalidated and cannot drift"],
        ["Intent lost during canonicalization", "Retained descriptive lexemes", "Ranking keeps task-specific constraints"],
        ["Ambiguous data-structure match", "Constraint intersection over sketches", "Pointer walk and side effects jointly rank"],
        ["Zero-work continuation poll", "Bounded foreground wait", "A charged call performs useful progress"],
    ]
    y = table_pdf(c, failures, MARGIN, y, [150, 175, CONTENT_W - 325], font_size=8)
    y = table_caption(c, "Table 3. Failure episodes and general mechanisms retained in v0.3.", y)
    end_page(c, y, 6)


def metric_dashboard(c: canvas.Canvas, y: float) -> float:
    c.setFillColor(INK)
    c.setFont("Arial-Bold", 12.5)
    c.drawString(MARGIN, y, "Paired development-set outcomes")
    c.setFont("Arial", 8)
    c.setFillColor(MUTED)
    c.drawRightString(PAGE_W - MARGIN, y, "FROZEN V0.2  ->  WINDY V0.3")
    y -= 15
    gap = 8.5
    card_w = 94
    cards = [
        ("TASK SUCCESS", "25.0%", "100%", "+75 points"),
        ("VALID CALLS", "82.81%", "100%", "+17.19 points"),
        ("MEDIAN CALLS", "5.5", "2", "-63.6%"),
        ("TOOL OUTPUT", "5,314 B", "1,651 B", "-68.9%"),
        ("ANSWER TIME", "46.32 s", "9.44 s", "4.9x faster"),
    ]
    for i, (label, before, after, delta) in enumerate(cards):
        x = round((MARGIN + i * (card_w + gap)) * 2) / 2
        c.setFillColor(SURFACE)
        c.rect(x, y - 84, card_w, 84, fill=1, stroke=0)
        c.setFillColor(FAINT)
        c.setFont("Arial-Bold", 7)
        c.drawString(x + 8, y - 14, label)
        c.setFillColor(MUTED)
        c.setFont("Arial", 7.5)
        c.drawString(x + 8, y - 34, before)
        c.setFillColor(INK)
        c.setFont("Arial-Bold", 13.5)
        c.drawString(x + 8, y - 56, after)
        c.setFont("Arial-Bold", 7)
        c.setFillColor(MUTED)
        c.drawString(x + 8, y - 73, delta)
    y -= 94
    return table_caption(c, "Figure 2. Exact paired before/after values replace mixed-scale bars.", y)


def results(c: canvas.Canvas) -> None:
    y = begin_page(c, 7, "Results", "results", "6. Results")
    y = heading(c, "6. Results", y)
    y = metric_dashboard(c, y)
    paired = [
        ["Metric", "Frozen v0.2", "Windy v0.3", "Change"],
        ["Cases passed", "3/12 (25.0%)", "12/12 (100%)", "+75.0 points"],
        ["False support", "0", "0", "No regression"],
        ["Valid public calls", "82.81%", "100%", "+17.19 points"],
        ["Median MCP calls", "5.5", "2", "-63.6%"],
        ["Median tool output", "5,314 B", "1,651 B", "-68.9%"],
        ["p95 tool output", "9,101 B", "4,443 B", "-51.2%"],
        ["Median supported-answer time", "46.32 s", "9.44 s", "4.9x faster"],
    ]
    y = table_pdf(c, paired, MARGIN, y, [190, 105, 105, CONTENT_W - 400], {1, 2, 3})
    y = table_caption(c, "Table 4. Paired local results. Timing uses the corrected v0.2 supported-case replay.", y)
    y = para(c, "The agent stopped attempting legacy tools, stopped assembling raw capability arguments, and received evidence sized for the question. The 12/12 run had zero false support and 100% valid public calls. This is development-set evidence that the mechanisms eliminate observed failures.", MARGIN, y, CONTENT_W, BODY_TIGHT)
    y = heading(c, "Schema and context surface", y, 3)
    schema = [
        ["Surface", "Frozen v0.2", "v0.3", "Reduction"],
        ["tools/list JSON", "7,343 B", "3,170 B", "56.8%"],
        ["Always-advertised tools", "12", "6", "50.0%"],
        ["Default inline budget", "4 KiB", "2 KiB", "50.0%"],
        ["Hard inline budget", "64 KiB", "8 KiB", "87.5%"],
    ]
    y = table_pdf(c, schema, MARGIN, y, [190, 105, 105, CONTENT_W - 400], {1, 2, 3})
    y = table_caption(c, "Table 5. The model-visible interface was reduced while internal capability parity was retained.", y)
    end_page(c, y, 7)


def runtime_and_interpretation(c: canvas.Canvas) -> None:
    y = begin_page(c, 8, "Runtime and interpretation", "runtime", "Runtime and interpretation")
    y = heading(c, "Runtime and software verification", y)
    runtime = [
        ["Target", "Cold mapped", "Cold catalog", "Cold sketch", "Warm mapped", "Warm catalog", "Warm sketch", "Peak RSS"],
        ["sample.exe", "21 ms", "28 ms", "50 ms", "3 ms", "9 ms", "30 ms", "12.5 MiB"],
        ["complex.exe", "21 ms", "27 ms", "51 ms", "3 ms", "9 ms", "28 ms", "12.5 MiB"],
        ["Windy self (53.9 MB)", "79 ms", "206 ms", "670 ms", "3 ms", "8 ms", "53 ms", "62.6 MiB"],
    ]
    widths = [116, 55, 57, 55, 55, 55, 55, CONTENT_W - 448]
    y = table_pdf(c, runtime, MARGIN, y, widths, set(range(1, 8)), font_size=7.5)
    y = table_caption(c, "Table 6. Five-run p50 release measurements. Peak RSS is the maximum working set observed by the harness.", y)
    y = para(c, "The self binary met every runtime and memory gate. Its deep index retained 10,740,446 records in 85,923,568 bytes; five fresh-cache builds had a 279 ms median. Versus the earlier eager BEL observation of 202 seconds and 2.28 GB, it was about 724 times faster and 96.2% smaller by estimated index memory; the indexes are not feature-identical. A minimal MDMP parsed in 12-19 ms; rich traversal was not measured.", MARGIN, y, CONTENT_W, BODY_TIGHT)

    verify = [
        ["Gate", "Observed result"],
        ["Build and lint", "cargo build passed; clippy passed with zero warnings"],
        ["cargo test", "431 passed, 0 failed, 1 authoring helper ignored; 30.76 s"],
        ["python -m unittest discover eval/microbench", "4/4 passed in 0.22 s"],
        ["cargo build --release", "Pass; 53,860,864-byte executable"],
        ["Dependency assertion", "No eframe, egui, rfd, wgpu, or winit dependency"],
    ]
    y = table_pdf(c, verify, MARGIN, y, [205, CONTENT_W - 205], font_size=7.5)
    y = table_caption(c, "Table 7. Mandatory local verification completed before manuscript generation.", y)

    y = heading(c, "7. Why the Architecture Helps", y - 2)
    gap = 24
    col_w = (CONTENT_W - gap) / 2
    lx, rx = MARGIN, MARGIN + col_w + gap
    ly = heading(c, "Executable inductive bias", y, 3, lx, col_w)
    ly = para(c, "In v0.2, the caller had to infer a hidden state machine: bind a capability, discover readiness, paginate, preserve citations, and judge support. In v0.3, these requirements are executable server state. The caller states intent, chooses a valid next action, and synthesizes bounded evidence.", lx, ly, col_w, BODY_TIGHT)
    ly = heading(c, "Programming-languages ideas", ly, 3, lx, col_w)
    ly = para(c, "Tickets resemble capabilities; revision and expiry resemble typestate; evidence deltas resemble incremental views; sketches resemble abstract interpretation; and promotion resembles demand-driven dataflow. These analogies provide a design vocabulary and test obligations without implying formal verification.", lx, ly, col_w, BODY_TIGHT)
    ry = heading(c, "Honesty through explicit incompleteness", y, 3, rx, col_w)
    ry = para(c, "Binary analysis is incomplete by construction. Indirect calls, obfuscation, missing symbols, malformed images, and unresolved data can prevent proof. Windy makes completeness explicit. Partial and pending states carry reasons, omissions, stable cursors, and uncertainty. Verification classifies claims as supported, contradicted, or unknown; honest abstention succeeds when support is unavailable.", rx, ry, col_w, BODY_TIGHT)
    ry = callout(c, "Core hypothesis", "For weak tool callers, moving selection, binding, scheduling, state, and provenance into a deterministic substrate can yield a larger practical gain than exposing more tools or context. Fresh tasks must preserve quality, honesty, and efficiency.", rx, ry, col_w, SMALL)
    end_page(c, min(ly, ry), 8)


def validity_and_next(c: canvas.Canvas) -> None:
    y = begin_page(c, 9, "Evaluation boundaries", "validity", "8. Evaluation Boundaries")
    y = heading(c, "8. Evaluation Boundaries", y)
    gap = 28
    col_w = (CONTENT_W - gap) / 2
    lx, rx = MARGIN, MARGIN + col_w + gap

    ly = heading(c, "Development data", y, 3, lx, col_w)
    ly = para(c, "The 12 cases were used during failure-driven iteration. They measure the mechanisms fixed in v0.3; transfer to unseen work requires a fresh sealed run.", lx, ly, col_w, BODY_TIGHT)
    ly = heading(c, "Scope", ly + 2, 3, lx, col_w)
    ly = para(c, "The study covers six small Windows PE fixtures and one low-reasoning model configuration. The MDMP result is a parser smoke, not a rich-dump benchmark.", lx, ly, col_w, BODY_TIGHT)

    ry = heading(c, "Measurement", y, 3, rx, col_w)
    ry = para(c, "Response bytes stand in for unavailable token telemetry. The 4.9x timing uses the corrected supported-case replay rather than a matched all-case sample.", rx, ry, col_w, BODY_TIGHT)
    ry = heading(c, "Attribution and semantics", ry + 2, 3, rx, col_w)
    ry = para(c, "v0.3 combines several mechanisms without a factorial ablation. Tickets reduce argument drift; evidence IDs prove provenance, not semantic truth. Decompilation, recovered types, and function boundaries remain best-effort.", rx, ry, col_w, BODY_TIGHT)
    y = min(ly, ry) - 20

    y = heading(c, "9. Next Validation", y)
    y = para(c, "Freeze the current executable and schema, then run at least 60 unseen sealed cases across compilers, optimization levels, and balanced abstention tasks.", MARGIN, y, CONTENT_W, BODY)
    y = bullet_list(c, [
        "Compare frozen v0.2, full v0.3, and targeted ablations under identical model settings and budgets.",
        "Record deterministic success, false support, valid calls, tokens, time to first supported answer, verified facts, cache behavior, latency, memory, and artifact bytes.",
        "Commit hashes and answers before revealing gold; report paired differences and bootstrap confidence intervals.",
    ], MARGIN, y, CONTENT_W, BODY_TIGHT, 6)
    end_page(c, y, 9)


def conclusion_and_refs(c: canvas.Canvas) -> None:
    y = begin_page(c, 10, "Conclusion and references", "conclusion", "10. Conclusion")
    y = heading(c, "10. Conclusion", y)
    y = para(c, "Windy v0.3 tests a simple proposition: improving an agent does not always require improving its language model. The Evidence Query VM compiles intent into typed static-analysis work, issues state-bound continuations, and returns only new, provenance-linked evidence. In the local benchmark, the redesign converted repeated protocol failures into 12/12 successful tasks while reducing calls, context, latency, and analysis cost.", MARGIN, y, CONTENT_W, BODY)
    y = para(c, "The core contribution is architectural: treat the interface as executable inductive bias, continuation state as a server responsibility, and evidence completeness as part of the contract. The measured benchmark is development data; independent replication is the next test. The design already provides a practical route to capable, private, low-cost agents without training or fine-tuning.", MARGIN, y, CONTENT_W, BODY_TIGHT)

    y = heading(c, "Credits", y - 2, 3)
    y = para(c, "This work was conducted under Husena LLC. Demetrius Greses Jr. directed the project and is the accountable human author. OpenAI Daybreak Blue assisted architecture synthesis, implementation iteration, experimental analysis, and manuscript preparation. OpenAI gpt-5.6-luna was the blinded low-reasoning benchmark subject. AI-generated assistance was reviewed and selected by the human author; AI systems are not listed as human authors. Demetrius Greses Jr. retains responsibility for the claims, interpretation, disclosure, and release of this work.", MARGIN, y, CONTENT_W, SMALL)
    gap = 24
    col_w = (CONTENT_W - gap) / 2
    lx, rx = MARGIN, MARGIN + col_w + gap
    y -= 2
    y = rule(c, y, tone=INK)
    y = heading(c, "References", y, 3)

    refs = [
        "[1] W. Shen et al. <i>Small LLMs Are Weak Tool Learners: A Multi-LLM Agent.</i> EMNLP 2024, pp. 16658-16680. <link href='https://doi.org/10.18653/v1/2024.emnlp-main.929'>doi:10.18653/v1/2024.emnlp-main.929</link>.",
        "[2] Y. Qin et al. <i>ToolLLM: Facilitating Large Language Models to Master 16000+ Real-world APIs.</i> arXiv:2307.16789, 2023. <link href='https://arxiv.org/abs/2307.16789'>arxiv.org/abs/2307.16789</link>.",
        "[3] Y. Chen et al. <i>Re-Invoke: Tool Invocation Rewriting for Zero-Shot Tool Retrieval.</i> Findings of EMNLP 2024, pp. 4705-4726. <link href='https://doi.org/10.18653/v1/2024.findings-emnlp.270'>doi:10.18653/v1/2024.findings-emnlp.270</link>.",
        "[4] N. F. Liu et al. <i>Lost in the Middle: How Language Models Use Long Contexts.</i> TACL 12, 2024, pp. 157-173. <link href='https://doi.org/10.1162/tacl_a_00638'>doi:10.1162/tacl_a_00638</link>.",
        "[5] E. Duesterwald, R. Gupta, and M. L. Soffa. <i>Demand-Driven Computation of Interprocedural Data Flow.</i> POPL 1995. <link href='https://doi.org/10.1145/199448.199461'>doi:10.1145/199448.199461</link>.",
        "[6] Y. Liu et al. <i>Towards Generality: Task-Adaptive Binary Analysis via Semantic Retrieval and Verifiable Reasoning.</i> 35th USENIX Security Symposium, 2026. USENIX open-access page.",
        "[7] Y. Hao et al. <i>ToolkenGPT: Augmenting Frozen Language Models with Massive Tools via Tool Embeddings.</i> NeurIPS 2023. <link href='https://arxiv.org/abs/2305.11554'>arxiv.org/abs/2305.11554</link>.",
        "[8] A. Kambhampati et al. <i>LLMs Can't Plan, But Can Help Planning in LLM-Modulo Frameworks.</i> arXiv:2402.01817, 2024. <link href='https://arxiv.org/abs/2402.01817'>arxiv.org/abs/2402.01817</link>.",
        "[9] Model Context Protocol. <i>Tools specification.</i> <link href='https://modelcontextprotocol.io/specification/draft/server/tools'>Model Context Protocol specification</link>. Accessed 2026-08-30.",
        "[10] T. Bao et al. <i>BYTEWEIGHT: Learning to Recognize Functions in Binary Code.</i> 23rd USENIX Security Symposium, 2014. USENIX open-access page.",
    ]
    ref_y_left = y
    for ref_text in refs[:5]:
        ref_y_left = para(c, ref_text, lx, ref_y_left, col_w, REF)
    ref_y_right = y
    for ref_text in refs[5:]:
        ref_y_right = para(c, ref_text, rx, ref_y_right, col_w, REF)
    y = min(ref_y_left, ref_y_right) - 3
    c.setStrokeColor(LINE_DARK)
    c.line(MARGIN, y, PAGE_W - MARGIN, y)
    c.setFillColor(FAINT)
    c.setFont("Arial", 8)
    c.drawCentredString(PAGE_W / 2, y - 15, "Final technical paper / 30 August 2026")
    end_page(c, y - 18, 10)


def build() -> None:
    register_fonts()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(
        str(OUTPUT),
        pagesize=letter,
        pageCompression=1,
        initialFontName="Arial",
        initialFontSize=10.75,
        initialLeading=15,
    )
    c.setTitle("The Interface Is the Model: Evidence-Carrying Continuations for Small-Model Static Binary Analysis")
    c.setAuthor("Demetrius Greses Jr., Husena LLC")
    c.setSubject("Windy v0.3.0 final technical paper on evidence-carrying continuations")
    c.setKeywords("agentic binary analysis, small language models, MCP, evidence provenance, continuation protocols")
    c.setCreator("Husena LLC with OpenAI Daybreak Blue assistance")

    cover(c)
    executive_summary(c)
    introduction(c)
    architecture(c)
    continuations(c)
    evaluation(c)
    results(c)
    runtime_and_interpretation(c)
    validity_and_next(c)
    conclusion_and_refs(c)
    c.save()
    print(OUTPUT)


if __name__ == "__main__":
    build()
