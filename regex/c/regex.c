/* Copyright (c) 2026 Jurjen Stellingwerff
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * The regex library's native part, in C99: a backtracking matcher over UTF-8 with the
 * leftmost-first semantics of the Rust `regex` crate it replaces — alternation, groups
 * (capturing, `(?:…)`, `(?<name>…)` / `(?P<name>…)`), the quantifiers `* + ? {m} {m,} {m,n}`
 * and their lazy forms, classes with ranges, negation and the escapes `\d \w \s` (Unicode:
 * a letter is a letter in any script) and `\p{L}` / `\p{N}`, the anchors `^ $ \A \z \b \B`,
 * `.`, and the inline flags `(?i)` `(?s)` `(?m)`.  Every offset is a byte offset on a
 * code-point boundary.  Compiled patterns are cached; a pattern that does not compile
 * matches nothing and its message is handed out once (`rx_error`).  Built by loft itself
 * (`[c] shim`, with `cc`); bound by the `#c` declarations in src/regex.loft.
 *
 * Bounded: a match attempt gives up (no match) after RX_STEP_LIMIT steps, so a pathological
 * pattern ends instead of running the process out of time. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── UTF-8 ──────────────────────────────────────────────────────────────────────────────── */

/* The code point at `p` (before `end`), its byte length in `*len`; a malformed sequence is
 * one byte, U+FFFD. */
static uint32_t rx_decode(const unsigned char *p, const unsigned char *end, int *len) {
    unsigned char c = p[0];
    uint32_t cp;
    int n, i;
    if (c < 0x80) { *len = 1; return c; }
    if (c >= 0xC2 && c <= 0xDF) { n = 2; cp = c & 0x1F; }
    else if (c >= 0xE0 && c <= 0xEF) { n = 3; cp = c & 0x0F; }
    else if (c >= 0xF0 && c <= 0xF4) { n = 4; cp = c & 0x07; }
    else { *len = 1; return 0xFFFD; }
    if (p + n > end) { *len = 1; return 0xFFFD; }
    for (i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80) { *len = 1; return 0xFFFD; }
        cp = (cp << 6) | (p[i] & 0x3F);
    }
    *len = n;
    return cp;
}

static int rx_is_cont(unsigned char c) { return (c & 0xC0) == 0x80; }

/* ── Character classes ──────────────────────────────────────────────────────────────────── */

/* Letters (`\p{L}`): the ranges of the General Category L in the Basic Multilingual Plane
 * and the main supplementary blocks, compact enough to live here; a script this table does
 * not know is not a letter to this engine. */
static const uint32_t rx_letters[][2] = {
    {0x41,0x5A},{0x61,0x7A},{0xAA,0xAA},{0xB5,0xB5},{0xBA,0xBA},{0xC0,0xD6},{0xD8,0xF6},{0xF8,0x2C1},
    {0x2C6,0x2D1},{0x2E0,0x2E4},{0x2EC,0x2EC},{0x2EE,0x2EE},{0x370,0x374},{0x376,0x377},{0x37A,0x37D},
    {0x37F,0x37F},{0x386,0x386},{0x388,0x38A},{0x38C,0x38C},{0x38E,0x3A1},{0x3A3,0x3F5},{0x3F7,0x481},
    {0x48A,0x52F},{0x531,0x556},{0x559,0x559},{0x560,0x588},{0x5D0,0x5EA},{0x5EF,0x5F2},{0x620,0x64A},
    {0x66E,0x66F},{0x671,0x6D3},{0x6D5,0x6D5},{0x6E5,0x6E6},{0x6EE,0x6EF},{0x6FA,0x6FC},{0x6FF,0x6FF},
    {0x710,0x710},{0x712,0x72F},{0x74D,0x7A5},{0x7B1,0x7B1},{0x7CA,0x7EA},{0x7F4,0x7F5},{0x7FA,0x7FA},
    {0x800,0x815},{0x81A,0x81A},{0x824,0x824},{0x828,0x828},{0x840,0x858},{0x860,0x86A},{0x8A0,0x8C9},
    {0x904,0x939},{0x93D,0x93D},{0x950,0x950},{0x958,0x961},{0x971,0x980},{0x985,0x98C},{0x98F,0x990},
    {0x993,0x9A8},{0x9AA,0x9B0},{0x9B2,0x9B2},{0x9B6,0x9B9},{0x9BD,0x9BD},{0x9CE,0x9CE},{0x9DC,0x9DD},
    {0x9DF,0x9E1},{0x9F0,0x9F1},{0xA05,0xA0A},{0xA0F,0xA10},{0xA13,0xA28},{0xA2A,0xA30},{0xA32,0xA33},
    {0xA35,0xA36},{0xA38,0xA39},{0xA59,0xA5C},{0xA5E,0xA5E},{0xA72,0xA74},{0xA85,0xA8D},{0xA8F,0xA91},
    {0xA93,0xAA8},{0xAAA,0xAB0},{0xAB2,0xAB3},{0xAB5,0xAB9},{0xABD,0xABD},{0xAD0,0xAD0},{0xAE0,0xAE1},
    {0xB05,0xB0C},{0xB0F,0xB10},{0xB13,0xB28},{0xB2A,0xB30},{0xB32,0xB33},{0xB35,0xB39},{0xB3D,0xB3D},
    {0xB5C,0xB5D},{0xB5F,0xB61},{0xB71,0xB71},{0xB83,0xB83},{0xB85,0xB8A},{0xB8E,0xB90},{0xB92,0xB95},
    {0xB99,0xB9A},{0xB9C,0xB9C},{0xB9E,0xB9F},{0xBA3,0xBA4},{0xBA8,0xBAA},{0xBAE,0xBB9},{0xBD0,0xBD0},
    {0xC05,0xC0C},{0xC0E,0xC10},{0xC12,0xC28},{0xC2A,0xC39},{0xC3D,0xC3D},{0xC58,0xC5A},{0xC60,0xC61},
    {0xC80,0xC80},{0xC85,0xC8C},{0xC8E,0xC90},{0xC92,0xCA8},{0xCAA,0xCB3},{0xCB5,0xCB9},{0xCBD,0xCBD},
    {0xCDE,0xCDE},{0xCE0,0xCE1},{0xCF1,0xCF2},{0xD04,0xD0C},{0xD0E,0xD10},{0xD12,0xD3A},{0xD3D,0xD3D},
    {0xD4E,0xD4E},{0xD54,0xD56},{0xD5F,0xD61},{0xD7A,0xD7F},{0xD85,0xD96},{0xD9A,0xDB1},{0xDB3,0xDBB},
    {0xDBD,0xDBD},{0xDC0,0xDC6},{0xE01,0xE30},{0xE32,0xE33},{0xE40,0xE46},{0xE81,0xE82},{0xE84,0xE84},
    {0xE86,0xE8A},{0xE8C,0xEA3},{0xEA5,0xEA5},{0xEA7,0xEB0},{0xEB2,0xEB3},{0xEBD,0xEBD},{0xEC0,0xEC4},
    {0xEC6,0xEC6},{0xEDC,0xEDF},{0xF00,0xF00},{0xF40,0xF47},{0xF49,0xF6C},{0xF88,0xF8C},{0x1000,0x102A},
    {0x103F,0x103F},{0x1050,0x1055},{0x105A,0x105D},{0x1061,0x1061},{0x1065,0x1066},{0x106E,0x1070},
    {0x1075,0x1081},{0x108E,0x108E},{0x10A0,0x10C5},{0x10C7,0x10C7},{0x10CD,0x10CD},{0x10D0,0x10FA},
    {0x10FC,0x1248},{0x124A,0x124D},{0x1250,0x1256},{0x1258,0x1258},{0x125A,0x125D},{0x1260,0x1288},
    {0x128A,0x128D},{0x1290,0x12B0},{0x12B2,0x12B5},{0x12B8,0x12BE},{0x12C0,0x12C0},{0x12C2,0x12C5},
    {0x12C8,0x12D6},{0x12D8,0x1310},{0x1312,0x1315},{0x1318,0x135A},{0x1380,0x138F},{0x13A0,0x13F5},
    {0x13F8,0x13FD},{0x1401,0x166C},{0x166F,0x167F},{0x1681,0x169A},{0x16A0,0x16EA},{0x16F1,0x16F8},
    {0x1700,0x1711},{0x171F,0x1731},{0x1740,0x1751},{0x1760,0x176C},{0x176E,0x1770},{0x1780,0x17B3},
    {0x17D7,0x17D7},{0x17DC,0x17DC},{0x1820,0x1878},{0x1880,0x1884},{0x1887,0x18A8},{0x18AA,0x18AA},
    {0x18B0,0x18F5},{0x1900,0x191E},{0x1950,0x196D},{0x1970,0x1974},{0x1980,0x19AB},{0x19B0,0x19C9},
    {0x1A00,0x1A16},{0x1A20,0x1A54},{0x1AA7,0x1AA7},{0x1B05,0x1B33},{0x1B45,0x1B4C},{0x1B83,0x1BA0},
    {0x1BAE,0x1BAF},{0x1BBA,0x1BE5},{0x1C00,0x1C23},{0x1C4D,0x1C4F},{0x1C5A,0x1C7D},{0x1C80,0x1C88},
    {0x1C90,0x1CBA},{0x1CBD,0x1CBF},{0x1CE9,0x1CEC},{0x1CEE,0x1CF3},{0x1CF5,0x1CF6},{0x1CFA,0x1CFA},
    {0x1D00,0x1DBF},{0x1E00,0x1F15},{0x1F18,0x1F1D},{0x1F20,0x1F45},{0x1F48,0x1F4D},{0x1F50,0x1F57},
    {0x1F59,0x1F59},{0x1F5B,0x1F5B},{0x1F5D,0x1F5D},{0x1F5F,0x1F7D},{0x1F80,0x1FB4},{0x1FB6,0x1FBC},
    {0x1FBE,0x1FBE},{0x1FC2,0x1FC4},{0x1FC6,0x1FCC},{0x1FD0,0x1FD3},{0x1FD6,0x1FDB},{0x1FE0,0x1FEC},
    {0x1FF2,0x1FF4},{0x1FF6,0x1FFC},{0x2071,0x2071},{0x207F,0x207F},{0x2090,0x209C},{0x2102,0x2102},
    {0x2107,0x2107},{0x210A,0x2113},{0x2115,0x2115},{0x2119,0x211D},{0x2124,0x2124},{0x2126,0x2126},
    {0x2128,0x2128},{0x212A,0x212D},{0x212F,0x2139},{0x213C,0x213F},{0x2145,0x2149},{0x214E,0x214E},
    {0x2183,0x2184},{0x2C00,0x2CE4},{0x2CEB,0x2CEE},{0x2CF2,0x2CF3},{0x2D00,0x2D25},{0x2D27,0x2D27},
    {0x2D2D,0x2D2D},{0x2D30,0x2D67},{0x2D6F,0x2D6F},{0x2D80,0x2D96},{0x2DA0,0x2DDE},{0x2E2F,0x2E2F},
    {0x3005,0x3006},{0x3031,0x3035},{0x303B,0x303C},{0x3041,0x3096},{0x309D,0x309F},{0x30A1,0x30FA},
    {0x30FC,0x30FF},{0x3105,0x312F},{0x3131,0x318E},{0x31A0,0x31BF},{0x31F0,0x31FF},{0x3400,0x4DBF},
    {0x4E00,0xA48C},{0xA4D0,0xA4FD},{0xA500,0xA60C},{0xA610,0xA61F},{0xA62A,0xA62B},{0xA640,0xA66E},
    {0xA67F,0xA69D},{0xA6A0,0xA6E5},{0xA717,0xA71F},{0xA722,0xA788},{0xA78B,0xA7CA},{0xA7D0,0xA7D1},
    {0xA7D3,0xA7D3},{0xA7D5,0xA7D9},{0xA7F2,0xA801},{0xA803,0xA805},{0xA807,0xA80A},{0xA80C,0xA822},
    {0xA840,0xA873},{0xA882,0xA8B3},{0xA8F2,0xA8F7},{0xA8FB,0xA8FB},{0xA8FD,0xA8FE},{0xA90A,0xA925},
    {0xA930,0xA946},{0xA960,0xA97C},{0xA984,0xA9B2},{0xA9CF,0xA9CF},{0xA9E0,0xA9E4},{0xA9E6,0xA9EF},
    {0xA9FA,0xA9FE},{0xAA00,0xAA28},{0xAA40,0xAA42},{0xAA44,0xAA4B},{0xAA60,0xAA76},{0xAA7A,0xAA7A},
    {0xAA7E,0xAAAF},{0xAAB1,0xAAB1},{0xAAB5,0xAAB6},{0xAAB9,0xAABD},{0xAAC0,0xAAC0},{0xAAC2,0xAAC2},
    {0xAADB,0xAADD},{0xAAE0,0xAAEA},{0xAAF2,0xAAF4},{0xAB01,0xAB06},{0xAB09,0xAB0E},{0xAB11,0xAB16},
    {0xAB20,0xAB26},{0xAB28,0xAB2E},{0xAB30,0xAB5A},{0xAB5C,0xAB69},{0xAB70,0xABE2},{0xAC00,0xD7A3},
    {0xD7B0,0xD7C6},{0xD7CB,0xD7FB},{0xF900,0xFA6D},{0xFA70,0xFAD9},{0xFB00,0xFB06},{0xFB13,0xFB17},
    {0xFB1D,0xFB1D},{0xFB1F,0xFB28},{0xFB2A,0xFB36},{0xFB38,0xFB3C},{0xFB3E,0xFB3E},{0xFB40,0xFB41},
    {0xFB43,0xFB44},{0xFB46,0xFBB1},{0xFBD3,0xFD3D},{0xFD50,0xFD8F},{0xFD92,0xFDC7},{0xFDF0,0xFDFB},
    {0xFE70,0xFE74},{0xFE76,0xFEFC},{0xFF21,0xFF3A},{0xFF41,0xFF5A},{0xFF66,0xFFBE},{0xFFC2,0xFFC7},
    {0xFFCA,0xFFCF},{0xFFD2,0xFFD7},{0xFFDA,0xFFDC},{0x10000,0x1000B},{0x1000D,0x10026},{0x10028,0x1003A},
    {0x1003C,0x1003D},{0x1003F,0x1004D},{0x10050,0x1005D},{0x10080,0x100FA},{0x10280,0x1029C},
    {0x102A0,0x102D0},{0x10300,0x1031F},{0x1032D,0x10340},{0x10342,0x10349},{0x10350,0x10375},
    {0x10380,0x1039D},{0x103A0,0x103C3},{0x103C8,0x103CF},{0x10400,0x1049D},{0x104B0,0x104D3},
    {0x104D8,0x104FB},{0x10500,0x10527},{0x10530,0x10563},{0x10600,0x10736},{0x10800,0x10855},
    {0x10900,0x10915},{0x10920,0x10939},{0x10980,0x109B7},{0x10A00,0x10A00},{0x10A10,0x10A35},
    {0x10A60,0x10A7C},{0x10A80,0x10A9C},{0x10AC0,0x10AE4},{0x10B00,0x10B35},{0x10B40,0x10B55},
    {0x10B60,0x10B72},{0x10B80,0x10B91},{0x10C00,0x10C48},{0x10C80,0x10CB2},{0x10CC0,0x10CF2},
    {0x10D00,0x10D23},{0x11003,0x11037},{0x11083,0x110AF},{0x110D0,0x110E8},{0x11103,0x11126},
    {0x11150,0x11172},{0x11183,0x111B2},{0x11200,0x1122B},{0x11280,0x112A8},{0x112B0,0x112DE},
    {0x11305,0x11339},{0x11400,0x11434},{0x11480,0x114AF},{0x11580,0x115AE},{0x11600,0x1162F},
    {0x11680,0x116AA},{0x11700,0x1171A},{0x11800,0x1182B},{0x118A0,0x118DF},{0x11A0B,0x11A32},
    {0x11AC0,0x11AF8},{0x11C00,0x11C2E},{0x11D00,0x11D30},{0x12000,0x12399},{0x12480,0x12543},
    {0x13000,0x1342E},{0x14400,0x14646},{0x16800,0x16A38},{0x16A40,0x16A5E},{0x16B00,0x16B2F},
    {0x16E40,0x16E7F},{0x16F00,0x16F4A},{0x17000,0x187F7},{0x18800,0x18CD5},{0x1B000,0x1B122},
    {0x1BC00,0x1BC6A},{0x1D400,0x1D6A5},{0x1D6A8,0x1D7CB},{0x1E100,0x1E12C},{0x1E2C0,0x1E2EB},
    {0x1E800,0x1E8C4},{0x1E900,0x1E943},{0x1EE00,0x1EEBB},{0x20000,0x2A6DF},{0x2A700,0x2B739},
    {0x2B740,0x2B81D},{0x2B820,0x2CEA1},{0x2CEB0,0x2EBE0},{0x2F800,0x2FA1D},{0x30000,0x3134A},
};

/* Decimal digits (`\d`, General Category Nd): every block of ten. */
static const uint32_t rx_digits[] = {
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66, 0xDE6,
    0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50,
    0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x16A60, 0x16AC0, 0x16B50,
    0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E950, 0x1FBF0,
};

static int rx_in_ranges(const uint32_t (*r)[2], size_t n, uint32_t c) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (c < r[mid][0]) hi = mid;
        else if (c > r[mid][1]) lo = mid + 1;
        else return 1;
    }
    return 0;
}

static int rx_is_letter(uint32_t c) {
    return rx_in_ranges(rx_letters, sizeof rx_letters / sizeof rx_letters[0], c);
}

static int rx_is_digit(uint32_t c) {
    size_t i;
    for (i = 0; i < sizeof rx_digits / sizeof rx_digits[0]; i++)
        if (c >= rx_digits[i] && c < rx_digits[i] + 10) return 1;
    return 0;
}

/* `\s`: Unicode White_Space. */
static int rx_is_space(uint32_t c) {
    return (c >= 9 && c <= 13) || c == 0x20 || c == 0x85 || c == 0xA0 || c == 0x1680
        || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 || c == 0x202F
        || c == 0x205F || c == 0x3000;
}

/* `\w`: a letter, a digit, a mark-free approximation of the crate's `\w` (Alphabetic,
 * Join_Control, Decimal_Number, Mark, Connector_Punctuation): letters, digits and `_`. */
static int rx_is_word(uint32_t c) {
    return c == '_' || rx_is_letter(c) || rx_is_digit(c) || (c >= 0x300 && c <= 0x36F);
}

/* Simple case folding: ASCII, Latin-1, Latin Extended-A (the pairwise blocks), Greek and
 * Cyrillic basic blocks. */
static uint32_t rx_fold(uint32_t c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    if (c < 0x80) return c;
    if ((c >= 0xC0 && c <= 0xDE && c != 0xD7)) return c + 32;
    if (c >= 0x100 && c <= 0x17F) {
        if ((c >= 0x139 && c <= 0x148) || (c >= 0x179 && c <= 0x17E)) return (c & 1) ? c + 1 : c;
        if (c == 0x130 || c == 0x131 || c == 0x138 || c == 0x149 || c == 0x17F) return c;
        return (c & 1) ? c : c + 1;
    }
    if (c >= 0x391 && c <= 0x3AB && c != 0x3A2) return c + 32;
    if (c >= 0x410 && c <= 0x42F) return c + 32;
    if (c >= 0x400 && c <= 0x40F) return c + 80;
    return c;
}

/* ── The compiled program ───────────────────────────────────────────────────────────────── */

enum {
    RX_CHAR,      /* a: the code point */
    RX_ANY,       /* `.`: a: 1 when it takes '\n' ((?s)) */
    RX_CLASS,     /* a: class index */
    RX_SPLIT,     /* x, y: try x first, then y */
    RX_JMP,       /* x */
    RX_SAVE,      /* a: capture slot */
    RX_BOL, RX_EOL, RX_BOT, RX_EOT, RX_WORDB, RX_NWORDB,
    RX_REPSTART,  /* a: counter index — x: min, y: max (-1 unbounded) — followed by the body */
    RX_REPEND,    /* a: counter index, x: body start, y: greedy */
    RX_MATCH
};

typedef struct { int op, a, x, y; } rx_inst;

typedef struct {
    uint32_t lo, hi;
} rx_range;

typedef struct {
    rx_range *ranges;
    int nranges, cap;
    int negate;
    /* The named sets folded in: bit 0 \d, 1 \w, 2 \s, 3 \p{L}, 4 \p{N}; bits 8.. their negations. */
    unsigned sets;
    int fold;
} rx_class;

typedef struct {
    rx_inst *code;
    int ncode, cap;
    rx_class *classes;
    int nclasses, ccap;
    int ngroups;         /* capturing groups, not counting group 0 */
    int ncounters;
    char **names;        /* ngroups entries, "" for an unnamed group */
    char *error;         /* NULL when the pattern compiled */
    int reported;
    char *pattern;
} rx_prog;

static int rx_emit(rx_prog *p, int op, int a, int x, int y) {
    if (p->ncode == p->cap) {
        int cap = p->cap ? p->cap * 2 : 64;
        rx_inst *n = (rx_inst *) realloc(p->code, sizeof(rx_inst) * (size_t) cap);
        if (!n) return -1;
        p->code = n;
        p->cap = cap;
    }
    p->code[p->ncode].op = op;
    p->code[p->ncode].a = a;
    p->code[p->ncode].x = x;
    p->code[p->ncode].y = y;
    return p->ncode++;
}

/* ── The parser: pattern → program, by recursive descent ───────────────────────────────── */

typedef struct {
    const unsigned char *s, *end;
    rx_prog *p;
    int fold, dotall, multiline;
    char err[200];
    int failed;
    int depth;
} rx_parser;

static void rx_fail(rx_parser *ps, const char *msg) {
    if (!ps->failed) {
        ps->failed = 1;
        snprintf(ps->err, sizeof ps->err, "%s", msg);
    }
}

static int rx_class_add(rx_class *c, uint32_t lo, uint32_t hi) {
    if (c->nranges == c->cap) {
        int cap = c->cap ? c->cap * 2 : 8;
        rx_range *n = (rx_range *) realloc(c->ranges, sizeof(rx_range) * (size_t) cap);
        if (!n) return 0;
        c->ranges = n;
        c->cap = cap;
    }
    c->ranges[c->nranges].lo = lo;
    c->ranges[c->nranges].hi = hi;
    c->nranges++;
    return 1;
}

static int rx_new_class(rx_prog *p) {
    if (p->nclasses == p->ccap) {
        int cap = p->ccap ? p->ccap * 2 : 8;
        rx_class *n = (rx_class *) realloc(p->classes, sizeof(rx_class) * (size_t) cap);
        if (!n) return -1;
        p->classes = n;
        p->ccap = cap;
    }
    memset(&p->classes[p->nclasses], 0, sizeof(rx_class));
    return p->nclasses++;
}

static int rx_peek(rx_parser *ps) { return ps->s < ps->end ? *ps->s : -1; }

static uint32_t rx_next_cp(rx_parser *ps) {
    int len;
    uint32_t c;
    if (ps->s >= ps->end) return 0;
    c = rx_decode(ps->s, ps->end, &len);
    ps->s += len;
    return c;
}

static int rx_hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* After a backslash: a code point in `*cp` (return 1), a named set in `*set` (return 2), an
 * assertion/other handled by the caller (return 0 with `*cp` the letter). */
static int rx_escape(rx_parser *ps, uint32_t *cp, unsigned *set, int in_class) {
    int c = rx_peek(ps);
    if (c < 0) { rx_fail(ps, "incomplete escape sequence, reached end of pattern prematurely"); return 0; }
    ps->s++;
    switch (c) {
    case 'n': *cp = '\n'; return 1;
    case 't': *cp = '\t'; return 1;
    case 'r': *cp = '\r'; return 1;
    case 'f': *cp = '\f'; return 1;
    case 'v': *cp = '\v'; return 1;
    case 'a': *cp = 7; return 1;
    case '0': *cp = 0; return 1;
    case 'd': *set = 1u; return 2;
    case 'D': *set = 1u << 8; return 2;
    case 'w': *set = 2u; return 2;
    case 'W': *set = 2u << 8; return 2;
    case 's': *set = 4u; return 2;
    case 'S': *set = 4u << 8; return 2;
    case 'p': case 'P': {
        int neg = c == 'P';
        char name[16];
        size_t n = 0;
        if (rx_peek(ps) == '{') {
            ps->s++;
            while (rx_peek(ps) >= 0 && rx_peek(ps) != '}' && n + 1 < sizeof name) name[n++] = (char) *ps->s++;
            if (rx_peek(ps) != '}') { rx_fail(ps, "unclosed Unicode class name"); return 0; }
            ps->s++;
        } else if (rx_peek(ps) >= 0) {
            name[n++] = (char) *ps->s++;
        }
        name[n] = 0;
        if (strcmp(name, "L") == 0 || strcmp(name, "Letter") == 0 || strcmp(name, "Alphabetic") == 0) *set = 8u;
        else if (strcmp(name, "N") == 0 || strcmp(name, "Nd") == 0 || strcmp(name, "Number") == 0) *set = 16u;
        else { rx_fail(ps, "unrecognized Unicode class name"); return 0; }
        if (neg) *set <<= 8;
        return 2;
    }
    case 'x': {
        uint32_t v = 0;
        int k;
        if (rx_peek(ps) == '{') {
            ps->s++;
            while (rx_hexval(rx_peek(ps)) >= 0) v = v * 16 + (uint32_t) rx_hexval(*ps->s++);
            if (rx_peek(ps) != '}') { rx_fail(ps, "invalid hexadecimal escape"); return 0; }
            ps->s++;
        } else {
            for (k = 0; k < 2; k++) {
                if (rx_hexval(rx_peek(ps)) < 0) { rx_fail(ps, "invalid hexadecimal escape"); return 0; }
                v = v * 16 + (uint32_t) rx_hexval(*ps->s++);
            }
        }
        if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) { rx_fail(ps, "invalid Unicode scalar value"); return 0; }
        *cp = v;
        return 1;
    }
    case 'u': case 'U': {
        uint32_t v = 0;
        int k, digits = c == 'u' ? 4 : 8;
        if (rx_peek(ps) == '{') {
            ps->s++;
            while (rx_hexval(rx_peek(ps)) >= 0) v = v * 16 + (uint32_t) rx_hexval(*ps->s++);
            if (rx_peek(ps) != '}') { rx_fail(ps, "invalid hexadecimal escape"); return 0; }
            ps->s++;
        } else {
            for (k = 0; k < digits; k++) {
                if (rx_hexval(rx_peek(ps)) < 0) { rx_fail(ps, "invalid hexadecimal escape"); return 0; }
                v = v * 16 + (uint32_t) rx_hexval(*ps->s++);
            }
        }
        if (v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF)) { rx_fail(ps, "invalid Unicode scalar value"); return 0; }
        *cp = v;
        return 1;
    }
    default:
        if (c == 'b' || c == 'B' || c == 'A' || c == 'z') {
            if (in_class) {
                if (c == 'b') { *cp = 8; return 1; }
                rx_fail(ps, "unrecognized escape sequence in class");
                return 0;
            }
            *cp = (uint32_t) c;
            return 0;
        }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            rx_fail(ps, "unrecognized escape sequence");
            return 0;
        }
        /* An escaped punctuation character stands for itself. */
        ps->s--;
        *cp = rx_next_cp(ps);
        return 1;
    }
}

static int rx_parse_alt(rx_parser *ps);

/* `[...]` after the opening bracket. */
static int rx_parse_class(rx_parser *ps) {
    int ci = rx_new_class(ps->p);
    rx_class *c;
    int first = 1;
    if (ci < 0) { rx_fail(ps, "out of memory"); return -1; }
    c = &ps->p->classes[ci];
    c->fold = ps->fold;
    if (rx_peek(ps) == '^') { c->negate = 1; ps->s++; }
    for (;;) {
        uint32_t lo, hi;
        unsigned set = 0;
        int kind;
        int ch = rx_peek(ps);
        if (ch < 0) { rx_fail(ps, "unclosed character class"); return -1; }
        if (ch == ']' && !first) { ps->s++; break; }
        first = 0;
        if (ch == '[' && ps->s + 1 < ps->end && ps->s[1] == ':') {
            /* a POSIX class */
            const unsigned char *q = ps->s + 2;
            char name[16];
            size_t n = 0;
            while (q < ps->end && *q != ':' && n + 1 < sizeof name) name[n++] = (char) *q++;
            name[n] = 0;
            if (q + 1 < ps->end && q[0] == ':' && q[1] == ']') {
                ps->s = q + 2;
                if (strcmp(name, "alpha") == 0) { rx_class_add(c, 'a', 'z'); rx_class_add(c, 'A', 'Z'); }
                else if (strcmp(name, "digit") == 0) rx_class_add(c, '0', '9');
                else if (strcmp(name, "alnum") == 0) { rx_class_add(c, 'a', 'z'); rx_class_add(c, 'A', 'Z'); rx_class_add(c, '0', '9'); }
                else if (strcmp(name, "space") == 0) { rx_class_add(c, 9, 13); rx_class_add(c, ' ', ' '); }
                else if (strcmp(name, "upper") == 0) rx_class_add(c, 'A', 'Z');
                else if (strcmp(name, "lower") == 0) rx_class_add(c, 'a', 'z');
                else if (strcmp(name, "punct") == 0) { rx_class_add(c, '!', '/'); rx_class_add(c, ':', '@'); rx_class_add(c, '[', '`'); rx_class_add(c, '{', '~'); }
                else if (strcmp(name, "xdigit") == 0) { rx_class_add(c, '0', '9'); rx_class_add(c, 'a', 'f'); rx_class_add(c, 'A', 'F'); }
                else if (strcmp(name, "word") == 0) c->sets |= 2u;
                else { rx_fail(ps, "unrecognized POSIX class name"); return -1; }
                c = &ps->p->classes[ci];
                continue;
            }
        }
        if (ch == '[') {
            /* a nested class: its ranges join this one */
            int inner;
            rx_class *ic;
            int k;
            ps->s++;
            inner = rx_parse_class(ps);
            if (inner < 0) return -1;
            c = &ps->p->classes[ci];
            ic = &ps->p->classes[inner];
            if (ic->negate) { rx_fail(ps, "a negated nested class is not supported"); return -1; }
            for (k = 0; k < ic->nranges; k++) rx_class_add(c, ic->ranges[k].lo, ic->ranges[k].hi);
            c->sets |= ic->sets;
            continue;
        }
        if (ch == '\\') {
            ps->s++;
            kind = rx_escape(ps, &lo, &set, 1);
            if (ps->failed) return -1;
            if (kind == 2) { c->sets |= set; continue; }
        } else {
            lo = rx_next_cp(ps);
        }
        hi = lo;
        if (rx_peek(ps) == '-' && ps->s + 1 < ps->end && ps->s[1] != ']') {
            ps->s++;
            if (rx_peek(ps) == '\\') {
                ps->s++;
                kind = rx_escape(ps, &hi, &set, 1);
                if (ps->failed) return -1;
                if (kind == 2) { rx_fail(ps, "invalid character class range: a class cannot end a range"); return -1; }
            } else {
                hi = rx_next_cp(ps);
            }
            if (hi < lo) { rx_fail(ps, "invalid character class range, the start must be <= the end"); return -1; }
        }
        if (!rx_class_add(c, lo, hi)) { rx_fail(ps, "out of memory"); return -1; }
    }
    if (c->nranges == 0 && c->sets == 0) { rx_fail(ps, "unclosed character class"); return -1; }
    return ci;
}

/* A number; -1 when none. */
static int rx_number(rx_parser *ps) {
    int v = -1;
    while (rx_peek(ps) >= '0' && rx_peek(ps) <= '9') {
        if (v < 0) v = 0;
        v = v * 10 + (*ps->s - '0');
        if (v > 100000) { rx_fail(ps, "repetition quantifier expects a valid decimal"); return -1; }
        ps->s++;
    }
    return v;
}

/* One atom with its quantifier. Returns 0 when the pattern failed. */
static int rx_parse_piece(rx_parser *ps) {
    int start = ps->p->ncode;
    int ch = rx_peek(ps);
    int min = 1, max = 1, greedy = 1, quantified = 0;
    if (ch == '(') {
        int capture = 1, saved_fold = ps->fold, saved_dotall = ps->dotall, saved_ml = ps->multiline;
        char *name = NULL;
        int gi = 0;
        ps->s++;
        if (rx_peek(ps) == '?') {
            ps->s++;
            if (rx_peek(ps) == ':') { capture = 0; ps->s++; }
            else if (rx_peek(ps) == 'P' || rx_peek(ps) == '<') {
                const unsigned char *q;
                size_t n;
                if (rx_peek(ps) == 'P') ps->s++;
                if (rx_peek(ps) != '<') { rx_fail(ps, "invalid capture group name"); return 0; }
                ps->s++;
                q = ps->s;
                while (q < ps->end && *q != '>') q++;
                if (q >= ps->end) { rx_fail(ps, "unclosed capture group name"); return 0; }
                n = (size_t) (q - ps->s);
                if (n == 0) { rx_fail(ps, "empty capture group name"); return 0; }
                {
                    size_t k;
                    for (k = 0; k < n; k++) {
                        unsigned char cc = ps->s[k];
                        if (!((cc >= 'a' && cc <= 'z') || (cc >= 'A' && cc <= 'Z') || cc == '_' || (k > 0 && ((cc >= '0' && cc <= '9') || cc == '.' || cc == '[' || cc == ']')))) {
                            rx_fail(ps, "invalid capture group character");
                            return 0;
                        }
                    }
                }
                name = (char *) malloc(n + 1);
                if (!name) { rx_fail(ps, "out of memory"); return 0; }
                memcpy(name, ps->s, n);
                name[n] = 0;
                ps->s = q + 1;
            } else {
                /* flags: (?i) (?s) (?m) (?-u) (?i:...) */
                int neg = 0, any = 0;
                for (;;) {
                    int f = rx_peek(ps);
                    if (f == '-') { neg = 1; ps->s++; continue; }
                    if (f == 'i') { ps->fold = !neg; any = 1; ps->s++; continue; }
                    if (f == 's') { ps->dotall = !neg; any = 1; ps->s++; continue; }
                    if (f == 'm') { ps->multiline = !neg; any = 1; ps->s++; continue; }
                    if (f == 'u') {
                        if (neg) { rx_fail(ps, "pattern can match invalid UTF-8 — Unicode mode cannot be disabled on a text"); return 0; }
                        any = 1; ps->s++; continue;
                    }
                    if (f == 'x' || f == 'U' || f == 'R') { any = 1; ps->s++; continue; }
                    break;
                }
                if (!any && rx_peek(ps) != ')' && rx_peek(ps) != ':') { rx_fail(ps, "unrecognized flag"); return 0; }
                if (rx_peek(ps) == ')') {
                    /* the flags apply to the rest of the enclosing group */
                    ps->s++;
                    return 1;
                }
                if (rx_peek(ps) != ':') { rx_fail(ps, "expected flag or `:` after flags"); return 0; }
                ps->s++;
                capture = 0;
            }
        }
        if (capture) {
            char **names;
            gi = ++ps->p->ngroups;
            names = (char **) realloc(ps->p->names, sizeof(char *) * (size_t) gi);
            if (!names) { free(name); rx_fail(ps, "out of memory"); return 0; }
            ps->p->names = names;
            if (!name) {
                name = (char *) malloc(1);
                if (!name) { rx_fail(ps, "out of memory"); return 0; }
                name[0] = 0;
            } else {
                int k;
                for (k = 0; k < gi - 1; k++)
                    if (strcmp(names[k], name) == 0) { free(name); rx_fail(ps, "duplicate capture group name"); return 0; }
            }
            names[gi - 1] = name;
            rx_emit(ps->p, RX_SAVE, 2 * gi, 0, 0);
        }
        if (++ps->depth > 200) { rx_fail(ps, "nesting too deep"); return 0; }
        if (!rx_parse_alt(ps)) return 0;
        ps->depth--;
        if (rx_peek(ps) != ')') { rx_fail(ps, "unclosed group"); return 0; }
        ps->s++;
        if (capture) rx_emit(ps->p, RX_SAVE, 2 * gi + 1, 0, 0);
        ps->fold = saved_fold;
        ps->dotall = saved_dotall;
        ps->multiline = saved_ml;
    } else if (ch == '[') {
        int ci;
        ps->s++;
        ci = rx_parse_class(ps);
        if (ci < 0) return 0;
        rx_emit(ps->p, RX_CLASS, ci, 0, 0);
    } else if (ch == '.') {
        ps->s++;
        rx_emit(ps->p, RX_ANY, ps->dotall, 0, 0);
    } else if (ch == '^') {
        ps->s++;
        rx_emit(ps->p, ps->multiline ? RX_BOL : RX_BOT, 0, 0, 0);
    } else if (ch == '$') {
        ps->s++;
        rx_emit(ps->p, ps->multiline ? RX_EOL : RX_EOT, 0, 0, 0);
    } else if (ch == '\\') {
        uint32_t cp;
        unsigned set = 0;
        int kind;
        ps->s++;
        kind = rx_escape(ps, &cp, &set, 0);
        if (ps->failed) return 0;
        if (kind == 1) {
            rx_emit(ps->p, RX_CHAR, (int) (ps->fold ? rx_fold(cp) : cp), ps->fold, 0);
        } else if (kind == 2) {
            int ci = rx_new_class(ps->p);
            if (ci < 0) { rx_fail(ps, "out of memory"); return 0; }
            ps->p->classes[ci].sets = set;
            rx_emit(ps->p, RX_CLASS, ci, 0, 0);
        } else {
            switch (cp) {
            case 'b': rx_emit(ps->p, RX_WORDB, 0, 0, 0); break;
            case 'B': rx_emit(ps->p, RX_NWORDB, 0, 0, 0); break;
            case 'A': rx_emit(ps->p, RX_BOT, 0, 0, 0); break;
            default: rx_emit(ps->p, RX_EOT, 0, 0, 0); break;
            }
        }
    } else if (ch == '*' || ch == '+' || ch == '?') {
        rx_fail(ps, "repetition operator missing expression");
        return 0;
    } else if (ch == '{') {
        /* a `{` that does not open a valid quantifier is a literal; one at the start of a piece
         * is never a quantifier */
        ps->s++;
        rx_emit(ps->p, RX_CHAR, '{', 0, 0);
    } else if (ch == ')') {
        rx_fail(ps, "unopened group");
        return 0;
    } else {
        uint32_t cp = rx_next_cp(ps);
        rx_emit(ps->p, RX_CHAR, (int) (ps->fold ? rx_fold(cp) : cp), ps->fold, 0);
    }
    /* the quantifier */
    ch = rx_peek(ps);
    if (ch == '*') { min = 0; max = -1; quantified = 1; ps->s++; }
    else if (ch == '+') { min = 1; max = -1; quantified = 1; ps->s++; }
    else if (ch == '?') { min = 0; max = 1; quantified = 1; ps->s++; }
    else if (ch == '{') {
        const unsigned char *save = ps->s;
        int a, b;
        ps->s++;
        a = rx_number(ps);
        if (ps->failed) return 0;
        if (a < 0) { ps->s = save; }
        else {
            if (rx_peek(ps) == ',') {
                ps->s++;
                b = rx_number(ps);
                if (ps->failed) return 0;
                if (b >= 0 && b < a) { rx_fail(ps, "invalid repetition count range, the start must be <= the end"); return 0; }
            } else {
                b = a;
            }
            if (rx_peek(ps) != '}') { ps->s = save; }
            else { ps->s++; min = a; max = b; quantified = 1; }
        }
    }
    if (quantified) {
        if (rx_peek(ps) == '?') { greedy = 0; ps->s++; }
        if (rx_peek(ps) == '*' || rx_peek(ps) == '+' || rx_peek(ps) == '?') { rx_fail(ps, "repetition operator missing expression"); return 0; }
        if (ps->p->ncode == start) { rx_fail(ps, "repetition operator missing expression"); return 0; }
        {
            /* wrap [start, ncode) in a counted repetition: REPSTART; body; REPEND */
            int body_len = ps->p->ncode - start;
            int counter = ps->p->ncounters++;
            int k;
            if (rx_emit(ps->p, RX_REPEND, 0, 0, 0) < 0) { rx_fail(ps, "out of memory"); return 0; }
            if (rx_emit(ps->p, RX_REPEND, 0, 0, 0) < 0) { rx_fail(ps, "out of memory"); return 0; }
            /* shift the body up by one to make room for REPSTART */
            for (k = ps->p->ncode - 2; k > start; k--) {
                ps->p->code[k] = ps->p->code[k - 1];
                if (ps->p->code[k].op == RX_SPLIT || ps->p->code[k].op == RX_JMP) {
                    if (ps->p->code[k].x >= start) ps->p->code[k].x++;
                    if (ps->p->code[k].op == RX_SPLIT && ps->p->code[k].y >= start) ps->p->code[k].y++;
                } else if (ps->p->code[k].op == RX_REPEND) {
                    if (ps->p->code[k].x >= start) ps->p->code[k].x++;
                }
            }
            ps->p->code[start].op = RX_REPSTART;
            ps->p->code[start].a = counter;
            ps->p->code[start].x = min;
            ps->p->code[start].y = max;
            ps->p->code[start + body_len + 1].op = RX_REPEND;
            ps->p->code[start + body_len + 1].a = counter;
            ps->p->code[start + body_len + 1].x = start + 1;
            ps->p->code[start + body_len + 1].y = greedy;
            ps->p->ncode = start + body_len + 2;
        }
    }
    return 1;
}

static int rx_parse_concat(rx_parser *ps) {
    for (;;) {
        int ch = rx_peek(ps);
        if (ch < 0 || ch == '|' || ch == ')') return 1;
        if (!rx_parse_piece(ps)) return 0;
    }
}

/* alt := concat ('|' concat)* — each branch wrapped as SPLIT L1, L2; L1: branch JMP end; L2: … */
static int rx_parse_alt(rx_parser *ps) {
    int start = ps->p->ncode;
    int jumps[256];
    int njumps = 0, k;
    if (!rx_parse_concat(ps)) return 0;
    while (rx_peek(ps) == '|') {
        /* turn [start, ncode) into: SPLIT start+1, L2 ; branch ; JMP end */
        int branch_len = ps->p->ncode - start;
        int j;
        ps->s++;
        if (njumps >= 256) { rx_fail(ps, "too many alternatives"); return 0; }
        if (rx_emit(ps->p, RX_JMP, 0, 0, 0) < 0 || rx_emit(ps->p, RX_JMP, 0, 0, 0) < 0) { rx_fail(ps, "out of memory"); return 0; }
        for (j = ps->p->ncode - 2; j > start; j--) {
            ps->p->code[j] = ps->p->code[j - 1];
            if (ps->p->code[j].op == RX_SPLIT || ps->p->code[j].op == RX_JMP) {
                if (ps->p->code[j].x >= start) ps->p->code[j].x++;
                if (ps->p->code[j].op == RX_SPLIT && ps->p->code[j].y >= start) ps->p->code[j].y++;
            } else if (ps->p->code[j].op == RX_REPEND) {
                if (ps->p->code[j].x >= start) ps->p->code[j].x++;
            }
        }
        for (k = 0; k < njumps; k++) jumps[k]++;
        ps->p->code[start].op = RX_SPLIT;
        ps->p->code[start].x = start + 1;
        ps->p->code[start].y = start + branch_len + 2;
        ps->p->code[start + branch_len + 1].op = RX_JMP;
        jumps[njumps++] = start + branch_len + 1;
        ps->p->ncode = start + branch_len + 2;
        start = ps->p->ncode;
        if (!rx_parse_concat(ps)) return 0;
    }
    for (k = 0; k < njumps; k++) ps->p->code[jumps[k]].x = ps->p->ncode;
    return 1;
}

static void rx_free_prog(rx_prog *p) {
    int k;
    if (!p) return;
    free(p->code);
    for (k = 0; k < p->nclasses; k++) free(p->classes[k].ranges);
    free(p->classes);
    for (k = 0; k < p->ngroups; k++) free(p->names[k]);
    free(p->names);
    free(p->error);
    free(p->pattern);
    free(p);
}

static rx_prog *rx_compile(const char *pattern) {
    rx_prog *p = (rx_prog *) calloc(1, sizeof(rx_prog));
    rx_parser ps;
    if (!p) return NULL;
    p->pattern = (char *) malloc(strlen(pattern) + 1);
    if (!p->pattern) { free(p); return NULL; }
    strcpy(p->pattern, pattern);
    memset(&ps, 0, sizeof ps);
    ps.s = (const unsigned char *) pattern;
    ps.end = ps.s + strlen(pattern);
    ps.p = p;
    rx_emit(p, RX_SAVE, 0, 0, 0);
    if (rx_parse_alt(&ps) && !ps.failed) {
        if (ps.s < ps.end) rx_fail(&ps, "unopened group");
    }
    if (ps.failed) {
        p->error = (char *) malloc(strlen(ps.err) + 1);
        if (p->error) strcpy(p->error, ps.err);
        return p;
    }
    rx_emit(p, RX_SAVE, 1, 0, 0);
    rx_emit(p, RX_MATCH, 0, 0, 0);
    return p;
}

/* ── The matcher: recursive backtracking with capture restore ───────────────────────────── */

#define RX_STEP_LIMIT 20000000L

typedef struct {
    const rx_prog *p;
    const unsigned char *in, *end;
    long *caps;       /* 2 * (ngroups + 1) */
    int *counters;
    long *lastpos;    /* per counter: where the current iteration began */
    long steps;
    int gave_up;
} rx_run;

static int rx_class_has(const rx_class *c, uint32_t ch) {
    int k, hit = 0;
    uint32_t f = c->fold ? rx_fold(ch) : ch;
    for (k = 0; k < c->nranges && !hit; k++) {
        uint32_t lo = c->ranges[k].lo, hi = c->ranges[k].hi;
        if (ch >= lo && ch <= hi) hit = 1;
        else if (c->fold) {
            /* the folded character against the folded range ends, for the one-case blocks */
            if (f >= rx_fold(lo) && f <= rx_fold(hi)) hit = 1;
            else if (ch >= 'a' && ch <= 'z' && ch - 32 >= lo && ch - 32 <= hi) hit = 1;
        }
    }
    if (!hit && c->sets) {
        unsigned s = c->sets;
        if ((s & 1u) && rx_is_digit(ch)) hit = 1;
        if ((s & 2u) && rx_is_word(ch)) hit = 1;
        if ((s & 4u) && rx_is_space(ch)) hit = 1;
        if ((s & 8u) && rx_is_letter(ch)) hit = 1;
        if ((s & 16u) && rx_is_digit(ch)) hit = 1;
        if ((s & (1u << 8)) && !rx_is_digit(ch)) hit = 1;
        if ((s & (2u << 8)) && !rx_is_word(ch)) hit = 1;
        if ((s & (4u << 8)) && !rx_is_space(ch)) hit = 1;
        if ((s & (8u << 8)) && !rx_is_letter(ch)) hit = 1;
        if ((s & (16u << 8)) && !rx_is_digit(ch)) hit = 1;
    }
    return c->negate ? !hit : hit;
}

static int rx_word_at(rx_run *r, const unsigned char *pos) {
    int len;
    if (pos >= r->end) return 0;
    return rx_is_word(rx_decode(pos, r->end, &len));
}

static int rx_word_before(rx_run *r, const unsigned char *pos) {
    const unsigned char *q = pos;
    int len;
    if (q <= r->in) return 0;
    q--;
    while (q > r->in && rx_is_cont(*q)) q--;
    return rx_is_word(rx_decode(q, r->end, &len));
}

static int rx_step(rx_run *r, int pc, const unsigned char *pos);

static int rx_step(rx_run *r, int pc, const unsigned char *pos) {
    for (;;) {
        const rx_inst *i;
        if (++r->steps > RX_STEP_LIMIT) { r->gave_up = 1; return 0; }
        i = &r->p->code[pc];
        switch (i->op) {
        case RX_CHAR: {
            int len;
            uint32_t c;
            if (pos >= r->end) return 0;
            c = rx_decode(pos, r->end, &len);
            if (i->x) c = rx_fold(c);
            if (c != (uint32_t) i->a) return 0;
            pos += len;
            pc++;
            break;
        }
        case RX_ANY: {
            int len;
            uint32_t c;
            if (pos >= r->end) return 0;
            c = rx_decode(pos, r->end, &len);
            if (c == '\n' && !i->a) return 0;
            pos += len;
            pc++;
            break;
        }
        case RX_CLASS: {
            int len;
            uint32_t c;
            if (pos >= r->end) return 0;
            c = rx_decode(pos, r->end, &len);
            if (!rx_class_has(&r->p->classes[i->a], c)) return 0;
            pos += len;
            pc++;
            break;
        }
        case RX_SPLIT:
            if (rx_step(r, i->x, pos)) return 1;
            if (r->gave_up) return 0;
            pc = i->y;
            break;
        case RX_JMP:
            pc = i->x;
            break;
        case RX_SAVE: {
            long old = r->caps[i->a];
            r->caps[i->a] = (long) (pos - r->in);
            if (rx_step(r, pc + 1, pos)) return 1;
            r->caps[i->a] = old;
            return 0;
        }
        case RX_BOL:
            if (pos != r->in && pos[-1] != '\n') return 0;
            pc++;
            break;
        case RX_EOL:
            if (pos != r->end && *pos != '\n') return 0;
            pc++;
            break;
        case RX_BOT:
            if (pos != r->in) return 0;
            pc++;
            break;
        case RX_EOT:
            if (pos != r->end) return 0;
            pc++;
            break;
        case RX_WORDB:
            if (rx_word_before(r, pos) == rx_word_at(r, pos)) return 0;
            pc++;
            break;
        case RX_NWORDB:
            if (rx_word_before(r, pos) != rx_word_at(r, pos)) return 0;
            pc++;
            break;
        case RX_REPSTART: {
            /* enter the repetition: no iteration yet, no position to compare; the REPEND past
             * the body decides whether to iterate */
            int old = r->counters[i->a];
            long oldpos = r->lastpos[i->a];
            int ok;
            int k = pc + 1, depth = 1;
            while (depth) {
                if (r->p->code[k].op == RX_REPSTART) depth++;
                else if (r->p->code[k].op == RX_REPEND) depth--;
                if (depth) k++;
            }
            r->counters[i->a] = 0;
            r->lastpos[i->a] = -1;
            ok = rx_step(r, k, pos);
            r->counters[i->a] = old;
            r->lastpos[i->a] = oldpos;
            return ok;
        }
        case RX_REPEND: {
            /* `count` iterations of the body are behind us: another one is allowed below the
             * maximum and only when the last one consumed something (an empty iteration ends
             * the loop, as the crate ends it); stopping is allowed from the minimum on.
             * Greedy tries the next iteration first, lazy tries stopping first. */
            const rx_inst *st = &r->p->code[i->x - 1];
            int count = r->counters[i->a];
            int min = st->x, max = st->y;
            long here = (long) (pos - r->in);
            int can_stop = count >= min;
            int can_go = (max < 0 || count < max) && (count == 0 || r->lastpos[i->a] != here);
            int ok;
            if (!can_go) {
                if (!can_stop) return 0;
                pc++;
                break;
            }
            if (i->y) {
                r->counters[i->a] = count + 1;
                r->lastpos[i->a] = here;
                ok = rx_step(r, i->x, pos);
                r->counters[i->a] = count;
                if (ok) return 1;
                if (r->gave_up || !can_stop) return 0;
                pc++;
                break;
            }
            if (can_stop && rx_step(r, pc + 1, pos)) return 1;
            if (r->gave_up) return 0;
            r->counters[i->a] = count + 1;
            r->lastpos[i->a] = here;
            ok = rx_step(r, i->x, pos);
            r->counters[i->a] = count;
            return ok;
        }
        case RX_MATCH:
            return 1;
        default:
            return 0;
        }
    }
}

/* ── Running a program ──────────────────────────────────────────────────────────────────── */

/* The leftmost match at or after byte `from`: `caps` filled (2 * (ngroups + 1) entries, -1
 * for a group that took no part); 1 on a match. */
static int rx_search(const rx_prog *p, const unsigned char *in, size_t n, size_t from, long *caps) {
    rx_run r;
    size_t start;
    int ncaps = 2 * (p->ngroups + 1);
    r.p = p;
    r.in = in;
    r.end = in + n;
    r.caps = caps;
    r.counters = (int *) calloc((size_t) p->ncounters + 1, sizeof(int));
    r.lastpos = (long *) calloc((size_t) p->ncounters + 1, sizeof(long));
    r.steps = 0;
    r.gave_up = 0;
    if (!r.counters || !r.lastpos) { free(r.counters); free(r.lastpos); return 0; }
    for (start = from; start <= n; ) {
        int k, len;
        for (k = 0; k < ncaps; k++) caps[k] = -1;
        if (rx_step(&r, 0, in + start)) { free(r.counters); free(r.lastpos); return 1; }
        if (r.gave_up) break;
        if (start >= n) break;
        rx_decode(in + start, in + n, &len);
        start += (size_t) len;
    }
    free(r.counters);
    free(r.lastpos);
    return 0;
}

/* ── The cache of compiled patterns ─────────────────────────────────────────────────────── */

#define RX_CACHE 64
static rx_prog *rx_cache[RX_CACHE];
static unsigned rx_cache_next = 0;

static rx_prog *rx_get(const char *pattern) {
    unsigned k;
    rx_prog *p;
    if (!pattern) pattern = "";
    for (k = 0; k < RX_CACHE; k++)
        if (rx_cache[k] && strcmp(rx_cache[k]->pattern, pattern) == 0) return rx_cache[k];
    p = rx_compile(pattern);
    if (!p) return NULL;
    k = rx_cache_next++ % RX_CACHE;
    rx_free_prog(rx_cache[k]);
    rx_cache[k] = p;
    return p;
}

/* `from` rounded up to a character boundary, as the Rust part rounded it. */
static size_t rx_start_at(const unsigned char *in, size_t n, int64_t from) {
    size_t at = from < 0 ? 0 : (uint64_t) from > n ? n : (size_t) from;
    while (at < n && rx_is_cont(in[at])) at++;
    return at;
}

int64_t rx_group_count(const char *pattern);
int64_t rx_spans(const char *pattern, const char *input, int64_t from, int64_t *out, int64_t cap);
int64_t rx_is_match(const char *pattern, const char *input);
int64_t rx_match_start_at(const char *pattern, const char *input, int64_t from);
int64_t rx_match_end_at(const char *pattern, const char *input, int64_t from);
const char *rx_group_names(const char *pattern);
const char *rx_error(const char *pattern);

/* The number of capturing groups; -1 for a pattern that does not compile. */
int64_t rx_group_count(const char *pattern) {
    rx_prog *p = rx_get(pattern);
    return !p || p->error ? -1 : p->ngroups;
}

/* The spans of the first match at or after `from` into `out` (at most `cap` integers):
 * `s0 e0 s1 e1 …`, -1 -1 for a group that took no part; the count written, 0 when nothing
 * matched or the pattern does not compile. */
int64_t rx_spans(const char *pattern, const char *input, int64_t from, int64_t *out, int64_t cap) {
    rx_prog *p = rx_get(pattern);
    size_t n;
    long *caps;
    int ncaps, k;
    if (!p || p->error || !input) return 0;
    n = strlen(input);
    ncaps = 2 * (p->ngroups + 1);
    caps = (long *) malloc(sizeof(long) * (size_t) ncaps);
    if (!caps) return 0;
    if (!rx_search(p, (const unsigned char *) input, n, rx_start_at((const unsigned char *) input, n, from), caps)) {
        free(caps);
        return 0;
    }
    for (k = 0; k < ncaps && k < cap; k++) out[k] = caps[k];
    free(caps);
    return k;
}

int64_t rx_is_match(const char *pattern, const char *input) {
    rx_prog *p = rx_get(pattern);
    long caps[2];
    size_t n;
    if (!p || p->error || !input) return 0;
    n = strlen(input);
    if (p->ngroups == 0) return rx_search(p, (const unsigned char *) input, n, 0, caps) ? 1 : 0;
    {
        long *c = (long *) malloc(sizeof(long) * 2 * ((size_t) p->ngroups + 1));
        int ok;
        if (!c) return 0;
        ok = rx_search(p, (const unsigned char *) input, n, 0, c);
        free(c);
        return ok ? 1 : 0;
    }
}

static int64_t rx_match_edge(const char *pattern, const char *input, int64_t from, int which) {
    rx_prog *p = rx_get(pattern);
    long *c;
    size_t n;
    int64_t r = INT64_MIN;
    if (!p || p->error || !input) return INT64_MIN;
    n = strlen(input);
    c = (long *) malloc(sizeof(long) * 2 * ((size_t) p->ngroups + 1));
    if (!c) return INT64_MIN;
    if (rx_search(p, (const unsigned char *) input, n, rx_start_at((const unsigned char *) input, n, from), c)) r = c[which];
    free(c);
    return r;
}

/* The start of the first match at or after `from`, null (INT64_MIN) when none. */
int64_t rx_match_start_at(const char *pattern, const char *input, int64_t from) {
    return rx_match_edge(pattern, input, from, 0);
}

/* The end of that match. */
int64_t rx_match_end_at(const char *pattern, const char *input, int64_t from) {
    return rx_match_edge(pattern, input, from, 1);
}

static char rx_text_buf[4096];

/* The group names, each preceded by a newline ("" for an unnamed group); "" for no group or
 * a pattern that does not compile.  The buffer is reused by the next call. */
const char *rx_group_names(const char *pattern) {
    rx_prog *p = rx_get(pattern);
    size_t n = 0;
    int k;
    rx_text_buf[0] = 0;
    if (!p || p->error) return rx_text_buf;
    for (k = 0; k < p->ngroups; k++) {
        size_t l = strlen(p->names[k]);
        if (n + 1 + l + 1 > sizeof rx_text_buf) break;
        rx_text_buf[n++] = '\n';
        memcpy(rx_text_buf + n, p->names[k], l);
        n += l;
    }
    rx_text_buf[n] = 0;
    return rx_text_buf;
}

/* The message of a pattern that does not compile, handed out ONCE per pattern; "" for a
 * valid or an already reported one. */
const char *rx_error(const char *pattern) {
    rx_prog *p = rx_get(pattern);
    if (!p || !p->error || p->reported) return "";
    p->reported = 1;
    snprintf(rx_text_buf, sizeof rx_text_buf, "%s", p->error);
    return rx_text_buf;
}
