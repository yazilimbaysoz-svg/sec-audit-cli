"""Generate the sec-audit-cli Instagram carousel (1080x1350 dark cyber slides)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from pygments import lex
from pygments.lexers import BashLexer
from pygments.token import Token

WIDTH, HEIGHT = 1080, 1350
MARGIN = 72
OUTPUT = Path(__file__).resolve().parent
TOTAL = 4

BG_TOP = (9, 13, 19)
BG_BOTTOM = (16, 23, 33)
WHITE = "#EAF6FF"
MUTED = "#7E93A8"
GREEN = "#4ADE80"
CYAN = "#22D3EE"
PINK = "#F472B6"
RED = "#FB7185"
YELLOW = "#FBBF24"
VIOLET = "#C792EA"

FONT_REGULAR = Path("/usr/share/fonts/noto/NotoSansMono-Regular.ttf")
FONT_MONO_BOLD = Path("/usr/share/fonts/noto/NotoSansMono-Bold.ttf")
FONT_SANS_BOLD = Path("/usr/share/fonts/liberation/LiberationSans-Bold.ttf")
FONT_SANS = Path("/usr/share/fonts/liberation/LiberationSans-Regular.ttf")

CODE_COLORS = [
    (Token.Comment, "#64748B"),
    (Token.Keyword.Namespace, VIOLET),
    (Token.Keyword, VIOLET),
    (Token.Name.Builtin, "#F78C6C"),
    (Token.Name.Function, "#82AAFF"),
    (Token.String, "#C3E88D"),
    (Token.Number, "#F78C6C"),
    (Token.Operator, CYAN),
    (Token.Punctuation, "#94A3B8"),
    (Token.Name, WHITE),
    (Token.Text, WHITE),
]


@lru_cache(maxsize=64)
def font(size: int, *, mono: bool = True, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = []
    if mono:
        candidates = [FONT_MONO_BOLD, FONT_REGULAR] if bold else [FONT_REGULAR, FONT_MONO_BOLD]
    elif bold:
        candidates = [FONT_SANS_BOLD, FONT_MONO_BOLD]
    else:
        candidates = [FONT_SANS, FONT_REGULAR]
    for path in candidates:
        if path.exists():
            return ImageFont.truetype(str(path), size)
    return ImageFont.load_default(size=size)


def rgb(hex_color: str) -> tuple[int, int, int]:
    value = hex_color.lstrip("#")
    return tuple(int(value[index : index + 2], 16) for index in (0, 2, 4))


def token_color(ttype: object) -> str:
    name = str(ttype)
    for base, color in CODE_COLORS:
        if name.startswith(str(base)):
            return color
    return WHITE


def canvas(
    kicker: str, title: tuple[str, ...], accent: str, slide: int
) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG_TOP)
    draw = ImageDraw.Draw(image, "RGBA")

    for y in range(HEIGHT):
        ratio = y / HEIGHT
        color = tuple(int(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * ratio) for i in range(3))
        draw.line([(0, y), (WIDTH, y)], fill=(*color, 255))

    for x in range(0, WIDTH, 60):
        draw.line([(x, 0), (x, HEIGHT)], fill=(255, 255, 255, 6))
    for y in range(0, HEIGHT, 60):
        draw.line([(0, y), (WIDTH, y)], fill=(255, 255, 255, 6))

    glow = rgb(accent)
    for radius in range(300, 0, -10):
        alpha = int((1 - radius / 300) ** 2 * 20)
        draw.ellipse(
            [WIDTH - 90 - radius, -110 - radius, WIDTH - 90 + radius, -110 + radius],
            fill=(*glow, alpha),
        )

    draw.text(
        (MARGIN, 52),
        "BAYSOZ YAZILIM // OPEN SOURCE",
        font=font(21, mono=False, bold=True),
        fill=MUTED,
    )
    draw.text(
        (WIDTH - MARGIN, 52),
        "sec-audit // v0.1.0",
        font=font(20),
        fill=accent,
        anchor="ra",
    )
    draw.line([(MARGIN, 98), (WIDTH - MARGIN, 98)], fill=(*glow, 80), width=2)

    draw.text((MARGIN, 132), kicker, font=font(20), fill=accent)
    y = 176
    for line in title:
        draw.text((MARGIN, y), line, font=font(60, mono=False, bold=True), fill=WHITE)
        y += 74

    draw.line([(MARGIN, 1222), (WIDTH - MARGIN, 1222)], fill=(255, 255, 255, 28))
    draw.text((MARGIN, 1252), "@yazilimbaysoz", font=font(20), fill=MUTED)
    draw.text(
        (WIDTH - MARGIN, 1252),
        f"{slide:02d}/{TOTAL:02d}",
        font=font(20, bold=True),
        fill=accent,
        anchor="ra",
    )
    return image, draw


def terminal(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    width: int,
    height: int,
    label: str,
    accent: str,
) -> None:
    glow = rgb(accent)
    draw.rounded_rectangle(
        [x, y, x + width, y + height],
        radius=18,
        fill=(7, 11, 17, 250),
        outline=(*glow, 110),
        width=2,
    )
    draw.rounded_rectangle([x, y, x + width, y + 54], radius=18, fill=(24, 33, 45, 255))
    draw.rectangle([x, y + 30, x + width, y + 54], fill=(24, 33, 45, 255))
    for index, color in enumerate(((248, 113, 113), (250, 204, 21), (74, 222, 128))):
        cx = x + 28 + index * 26
        draw.ellipse([cx - 7, y + 20, cx + 7, y + 34], fill=(*color, 255))
    draw.text((x + 124, y + 17), label, font=font(18), fill=MUTED)


def code(
    draw: ImageDraw.ImageDraw,
    source: str,
    x: int,
    y: int,
    lexer: object,
    *,
    size: int = 20,
    leading: int = 32,
) -> int:
    text_font = font(size)
    for line in source.splitlines():
        cursor = x
        for ttype, value in lex(line, lexer):
            value = value.replace("\n", "").replace("\r", "").expandtabs(4)
            if not value:
                continue
            draw.text((cursor, y), value, font=text_font, fill=token_color(ttype))
            cursor += draw.textlength(value, font=text_font)
        y += leading
    return y


def pill(draw: ImageDraw.ImageDraw, x: int, y: int, text: str, color: str) -> int:
    text_font = font(18, bold=True)
    width = int(draw.textlength(text, font=text_font)) + 34
    draw.rounded_rectangle(
        [x, y, x + width, y + 44], radius=22, outline=(*rgb(color), 170), width=2
    )
    draw.text((x + 17, y + 9), text, font=text_font, fill=color)
    return x + width + 16


def slide_one() -> Image.Image:
    image, draw = canvas(
        "BÖLÜM 01 / PROBLEM",
        ("Klonladın,", "ya sonra?"),
        RED,
        1,
    )
    draw.text(
        (MARGIN, 344),
        "Gizli anahtar mı var? Bilinen CVE mi? Kodda eval( ) mi?",
        font=font(21, mono=False),
        fill=MUTED,
    )

    rows = (
        (RED, "SIZDIRILAN KEY", ".env içinde API anahtarı commit'lenmiş"),
        (YELLOW, "ZAFIYETLİ PAKET", "requirements.txt bilinen CVE taşıyor"),
        (PINK, "RİSKLİ KOD", "eval( ), SQLi veya zayıf hash var"),
    )
    top = 414
    for color, label, detail in rows:
        draw.rounded_rectangle(
            [MARGIN, top, WIDTH - MARGIN, top + 96],
            radius=14,
            fill=(18, 26, 37, 235),
            outline=(*rgb(color), 60),
            width=1,
        )
        draw.rounded_rectangle(
            [MARGIN, top, MARGIN + 6, top + 96], radius=3, fill=(*rgb(color), 255)
        )
        draw.text((MARGIN + 28, top + 17), label, font=font(23, bold=True), fill=color)
        draw.text((MARGIN + 28, top + 54), detail, font=font(18, mono=False), fill=WHITE)
        top += 110

    terminal(draw, MARGIN, 770, WIDTH - 2 * MARGIN, 380, "sec-audit -- terminal", RED)
    code(
        draw,
        "$ sec-audit .\n"
        "CRITICAL  SEC-OAI-001  OpenAI API key  config.py:12\n"
        "HIGH      DEP-CVE-2023-32681  requests 2.30.0  req.txt:4\n"
        "MEDIUM    OWASP-A02-HASH  Weak hashing  auth.py:31\n"
        "4 finding(s)  //  38 ms",
        MARGIN + 28,
        846,
        BashLexer(),
        size=19,
        leading=50,
    )
    draw.text(
        (MARGIN, 1172),
        "Üç soru, tek komut, saniyeler içinde cevap.",
        font=font(19),
        fill=GREEN,
    )
    return image


def slide_two() -> Image.Image:
    image, draw = canvas(
        "BÖLÜM 02 / YETENEKLER",
        ("Üç tarayıcı,", "tek komut."),
        CYAN,
        2,
    )
    draw.text(
        (MARGIN, 344),
        "Secret, dependency ve OWASP denetimi tek bir çalıştırmada.",
        font=font(21, mono=False),
        fill=MUTED,
    )

    cards = (
        (RED, "01", "SECRET TARAMASI", "AWS, GitHub, OpenAI, Stripe, JWT, PEM + Shannon entropisi"),
        (CYAN, "02", "BAĞIMLILIK DENETİMİ", "9 format, gömülü CVE DB, opsiyonel OSV API"),
        (VIOLET, "03", "OWASP DENETİMİ", "Injection, XSS, SSRF, path traversal, weak crypto, XXE"),
    )
    top = 410
    for color, number, label, detail in cards:
        draw.rounded_rectangle(
            [MARGIN, top, WIDTH - MARGIN, top + 118],
            radius=14,
            fill=(18, 26, 37, 235),
            outline=(*rgb(color), 90),
            width=1,
        )
        draw.rounded_rectangle(
            [MARGIN, top, MARGIN + 6, top + 118], radius=3, fill=(*rgb(color), 255)
        )
        draw.text((MARGIN + 26, top + 20), number, font=font(30, bold=True), fill=color)
        draw.text((MARGIN + 96, top + 22), label, font=font(23, bold=True), fill=WHITE)
        draw.text((MARGIN + 96, top + 64), detail, font=font(17, mono=False), fill=MUTED)
        top += 134

    terminal(draw, MARGIN, 836, WIDTH - 2 * MARGIN, 324, "sec-audit . --json --fail-on high", CYAN)
    code(
        draw,
        "$ sec-audit . --json --fail-on high\n"
        '{ "rule_id": "SEC-GIT-001", "severity": "CRITICAL" }\n'
        '{ "cwe": "CWE-798", "source": "regex+entropy" }\n'
        "exit 1  //  CI pipeline bloklandı",
        MARGIN + 28,
        912,
        BashLexer(),
        size=19,
        leading=52,
    )
    return image


def slide_three() -> Image.Image:
    image, draw = canvas(
        "BÖLÜM 03 / GÜVENLİ ÇIKTI",
        ("Şifreler asla", "açık çıkmaz."),
        VIOLET,
        3,
    )
    draw.text(
        (MARGIN, 344),
        "Bulgu maskelenir, SHA-256 parmak izi eklenir; ham değer yazdırılmaz.",
        font=font(21, mono=False),
        fill=MUTED,
    )

    draw.rounded_rectangle(
        [MARGIN, 414, WIDTH - MARGIN, 566],
        radius=16,
        fill=(*rgb(VIOLET), 16),
        outline=(*rgb(VIOLET), 130),
        width=2,
    )
    draw.text((MARGIN + 26, 436), "ÖRNEK KANIT / MASKELİ", font=font(17, bold=True), fill=VIOLET)
    draw.text(
        (MARGIN + 26, 482),
        "ghp_********************cDeF",
        font=font(26),
        fill=GREEN,
    )
    draw.text(
        (MARGIN + 26, 524),
        "sha256:1a2b3c4d...  //  CWE-798",
        font=font(18),
        fill=MUTED,
    )

    draw.text((MARGIN, 600), "PIPELINE", font=font(19, bold=True), fill=CYAN)
    boxes = (
        ("DOSYA BULUCU", "glob + budama", VIOLET),
        ("PARALEL ANALİZ", "ThreadPool", CYAN),
        ("BİRLEŞTİRME", "sıralama", GREEN),
        ("RAPOR", "terminal + json", YELLOW),
    )
    box_x = MARGIN
    for label, detail, color in boxes:
        draw.rounded_rectangle(
            [box_x, 642, box_x + 216, 760],
            radius=14,
            fill=(18, 26, 37, 235),
            outline=(*rgb(color), 120),
            width=2,
        )
        draw.text((box_x + 16, 664), label, font=font(17, bold=True), fill=color)
        draw.text((box_x + 16, 708), detail, font=font(16, mono=False), fill=MUTED)
        box_x += 240
        if box_x < WIDTH - MARGIN:
            draw.text((box_x - 20, 688), ">", font=font(26, bold=True), fill=MUTED)

    draw.rounded_rectangle(
        [MARGIN, 800, WIDTH - MARGIN, 916],
        radius=14,
        fill=(18, 26, 37, 220),
        outline=(*rgb(GREEN), 70),
        width=1,
    )
    draw.text((MARGIN + 24, 822), "CI ÇIKIŞ KODLARI", font=font(19, bold=True), fill=GREEN)
    draw.text(
        (MARGIN + 24, 864),
        "0  TEMİZ      1  EŞİK AŞILDI      2  GEÇERSİZ YOL",
        font=font(19),
        fill=WHITE,
    )

    for index, line in enumerate(
        (
            "Paralel dosya analizi ve ikili dosya atlama",
            "Boyut sınırı + dizin budama ile hızlı tarama",
            "Deterministik JSON ve anlamlı çıkış kodları",
        )
    ):
        draw.text((MARGIN, 972 + index * 48), f"✓  {line}", font=font(19, mono=False), fill=WHITE)

    draw.text(
        (MARGIN, 1140),
        "sec-audit  //  tek komutla güvenlik denetimi",
        font=font(20),
        fill=VIOLET,
    )
    return image


def slide_four() -> Image.Image:
    image, draw = canvas(
        "BÖLÜM 04 / KURULUM",
        ("Taramayı başlat,", "yıldızı bırak."),
        GREEN,
        4,
    )
    draw.text(
        (MARGIN, 344),
        "Python 3.11+, sıfır runtime bağımlılığı, tamamen çevrimdışı testler.",
        font=font(21, mono=False),
        fill=MUTED,
    )

    terminal(draw, MARGIN, 400, WIDTH - 2 * MARGIN, 340, "kurulum", GREEN)
    commands = (
        "$ git clone https://github.com/yazilimbaysoz-svg/sec-audit-cli.git\n"
        "$ cd sec-audit-cli && uv venv\n"
        "$ uv pip install -e .\n"
        "$ sec-audit . --fail-on high"
    )
    code(draw, commands, MARGIN + 28, 474, BashLexer(), size=19, leading=52)

    draw.rounded_rectangle(
        [MARGIN, 780, WIDTH - MARGIN, 890],
        radius=16,
        fill=(*rgb(GREEN), 18),
        outline=(*rgb(GREEN), 140),
        width=2,
    )
    draw.text(
        (MARGIN + 26, 806),
        "github.com/yazilimbaysoz-svg/sec-audit-cli",
        font=font(22),
        fill=GREEN,
    )
    draw.text(
        (MARGIN + 26, 846),
        "MIT lisans  /  katkı ve issue'ler açık",
        font=font(17, mono=False),
        fill=MUTED,
    )

    x = MARGIN
    for label, color in (("ZERO DEPS", CYAN), ("OFFLINE", YELLOW), ("OPEN SOURCE", PINK)):
        x = pill(draw, x, 930, label, color)

    draw.text(
        (MARGIN, 1030),
        "Bir yıldız, bir sonraki sızıntıyı erken yakalamamızı sağlar.",
        font=font(23, mono=False, bold=True),
        fill=WHITE,
    )
    draw.text(
        (MARGIN, 1082),
        "Star + fork + paylaş. #DevSecOps #Python #AçıkKaynak",
        font=font(18),
        fill=MUTED,
    )
    draw.text(
        (MARGIN, 1140),
        "sec-audit  //  güvenlik denetimi, saniyeler içinde",
        font=font(20),
        fill=GREEN,
    )
    return image


def main() -> None:
    names = ("kapak", "yetenekler", "guvenli-cikti", "kurulum")
    for index, builder in enumerate((slide_one, slide_two, slide_three, slide_four), start=1):
        image = builder()
        target = OUTPUT / f"{index:02d}_sec_audit_{names[index - 1]}.png"
        image.save(target, format="PNG", optimize=True)
        print(f"Wrote {target.name} ({image.width}x{image.height})")


if __name__ == "__main__":
    main()
