from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
MEDIA = ROOT / "media"
MEDIA.mkdir(exist_ok=True)

BG_TOP = (11, 16, 32)
BG_BOTTOM = (28, 37, 54)
CARD = (15, 23, 42)
CARD_ALT = (18, 27, 46)
TEXT = (248, 250, 252)
MUTED = (203, 213, 225)
ORANGE = (249, 115, 22)
AMBER = (245, 158, 11)
BLUE = (56, 189, 248)
GREEN = (34, 197, 94)
RED = (248, 113, 113)


def load_font(size: int, bold: bool = False):
    candidates = [
        "/System/Library/Fonts/Supplemental/Menlo.ttc",
        "/System/Library/Fonts/Supplemental/Courier New Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/Library/Fonts/Menlo-Regular.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


TITLE_FONT = load_font(74, bold=True)
SUBTITLE_FONT = load_font(22, bold=True)
BODY_FONT = load_font(20)
MONO_FONT = load_font(24)
MONO_SMALL = load_font(18)


def vertical_gradient(size):
    width, height = size
    image = Image.new("RGB", size, BG_TOP)
    draw = ImageDraw.Draw(image)
    for y in range(height):
        t = y / max(height - 1, 1)
        color = tuple(int(BG_TOP[i] * (1 - t) + BG_BOTTOM[i] * t) for i in range(3))
        draw.line([(0, y), (width, y)], fill=color)
    return image


def rounded_rect(draw, box, radius, fill, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def render_social_preview():
    image = vertical_gradient((1280, 640))
    draw = ImageDraw.Draw(image)

    rounded_rect(draw, (60, 60, 1220, 580), 28, fill=(15, 23, 42), outline=(71, 85, 105), width=2)
    rounded_rect(draw, (840, 130, 1160, 420), 22, fill=CARD, outline=(249, 115, 22, 160), width=2)
    rounded_rect(draw, (840, 438, 1160, 536), 18, fill=CARD_ALT, outline=(56, 189, 248, 160), width=2)

    draw.text((110, 110), "Kin", font=TITLE_FONT, fill=(255, 247, 237))
    draw.text((112, 196), "SEMANTIC VERSION CONTROL FOR AI-NATIVE TEAMS", font=SUBTITLE_FONT, fill=(253, 186, 116))
    draw.text((110, 288), "Git stores text history.", font=load_font(42, bold=True), fill=TEXT)
    draw.text((110, 344), "Kin understands code.", font=load_font(42, bold=True), fill=TEXT)
    draw.text(
        (110, 430),
        "Local-first graph core. Precise agent context. Semantic change, blame, review, and impact.",
        font=BODY_FONT,
        fill=MUTED,
    )

    draw.text((870, 165), "SOURCE OF TRUTH", font=MONO_SMALL, fill=(253, 186, 116))
    draw.text((870, 218), "Semantic Graph", font=load_font(30, bold=True), fill=TEXT)
    for idx, line in enumerate(["Entities", "Relationships", "Contracts", "SemanticChange"]):
        draw.text((870, 270 + idx * 34), line, font=BODY_FONT, fill=MUTED)

    draw.text((870, 468), "COMPATIBILITY SURFACE", font=MONO_SMALL, fill=(186, 230, 253))
    draw.text((870, 500), "Projected Files + MCP", font=load_font(22, bold=True), fill=TEXT)

    image.save(ROOT / "kin-social-preview.png", optimize=True)


def terminal_frame(title: str, lines, reveal_chars):
    width, height = 1120, 620
    image = vertical_gradient((width, height))
    draw = ImageDraw.Draw(image)

    rounded_rect(draw, (16, 16, 1104, 604), 22, fill=(9, 14, 28), outline=(255, 255, 255, 32), width=2)
    rounded_rect(draw, (16, 16, 1104, 72), 22, fill=(16, 24, 40))
    draw.ellipse((40, 35, 58, 53), fill=RED)
    draw.ellipse((68, 35, 86, 53), fill=AMBER)
    draw.ellipse((96, 35, 114, 53), fill=GREEN)
    draw.text((140, 29), title, font=MONO_SMALL, fill=MUTED)

    content_x = 48
    content_y = 106
    visible = reveal_chars
    for line, color in lines:
        draw.text((content_x, content_y), line[:visible], font=MONO_FONT, fill=color)
        visible = max(0, visible - len(line))
        content_y += 34

    footer = "graph-native context  |  semantic change  |  assistant-ready"
    draw.text((48, 560), footer, font=MONO_SMALL, fill=(148, 163, 184))
    return image


def build_terminal_gif(name: str, title: str, lines):
    total_chars = sum(len(line) for line, _ in lines)
    frames = []
    start = min(32, total_chars)
    reveal_steps = list(range(start, total_chars + 1, 12))
    if not reveal_steps or reveal_steps[-1] != total_chars:
        reveal_steps.append(total_chars)

    for step in reveal_steps:
        frames.append(terminal_frame(title, lines, step))
    for _ in range(8):
        frames.append(terminal_frame(title, lines, total_chars))

    output = MEDIA / name
    frames[0].save(
        output,
        save_all=True,
        append_images=frames[1:],
        duration=[70] * (len(frames) - 8) + [220] * 8,
        loop=0,
        optimize=False,
    )


def render_gifs():
    build_terminal_gif(
        "kin-demo-sovereign.gif",
        "kin sovereign workflow",
        [
            ("$ kin init .", ORANGE),
            ("initialized .kin/ + semantic graph + blob store", TEXT),
            ("$ kin status", ORANGE),
            ("branch: main  |  changes: 0  |  graph: ready", TEXT),
            ("$ kin branch create checkout-refactor", ORANGE),
            ("created branch checkout-refactor", TEXT),
            ("$ kin commit -m \"extract checkout flow\"", ORANGE),
            ("created SemanticChange 9f6c.. on checkout-refactor", BLUE),
        ],
    )
    build_terminal_gif(
        "kin-demo-semantic.gif",
        "kin semantic review",
        [
            ("$ kin diff", ORANGE),
            ("semantic delta: 2 functions, 1 relation, 1 contract edge", TEXT),
            ("$ kin review", ORANGE),
            ("risk: medium  |  impact: payments, ledger, retry policy", TEXT),
            ("$ kin blame src/payments.rs::charge_card", ORANGE),
            ("author: troy  |  survived 3 moves and 2 refactors", TEXT),
            ("$ kin history charge_card", ORANGE),
            ("tracked lineage across files, branches, and semantic changes", BLUE),
        ],
    )
    build_terminal_gif(
        "kin-demo-context.gif",
        "kin impact + context",
        [
            ("$ kin impact src/payments/charge_card.ts", ORANGE),
            ("impact: 3 entities, 2 contracts, 6 tests", TEXT),
            ("$ kin context --entity charge_card", ORANGE),
            ("pack: function + callers + tests + contract + risks", TEXT),
            ("$ kin search retry policy", ORANGE),
            ("2 matching specs  |  1 runtime evidence trail", TEXT),
            ("$ kin spec show stripe-checkout", ORANGE),
            ("linked work, proof, and implementation", BLUE),
        ],
    )
    build_terminal_gif(
        "kin-demo-agent.gif",
        "kin assistant coordination",
        [
            ("$ kin assistant install claude", ORANGE),
            ("installed local adapter + guidance pack", TEXT),
            ("$ kin mcp", ORANGE),
            ("server ready on stdio", TEXT),
            ("$ kin intent claim charge_card", ORANGE),
            ("lock: entity scope  |  downstream warnings attached", TEXT),
            ("$ kin traffic charge_card", ORANGE),
            ("active: claude(session-7)  |  risk: medium", BLUE),
        ],
    )
    build_terminal_gif(
        "kin-demo-interop.gif",
        "kin migration + git interop",
        [
            ("$ kin migrate scan", ORANGE),
            ("found 412 git commits  |  86 source files", TEXT),
            ("$ kin git import", ORANGE),
            ("imported Git history into SemanticChange graph", TEXT),
            ("$ kin git sync", ORANGE),
            ("imported external Git updates", TEXT),
            ("exported Kin state back into the active repo", TEXT),
            ("Git stays optional. The semantic graph stays primary.", BLUE),
        ],
    )


if __name__ == "__main__":
    render_social_preview()
    render_gifs()
