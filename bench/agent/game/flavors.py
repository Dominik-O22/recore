#!/usr/bin/env python3
"""Prints the potion colors of a Brogue CE game seed, as game.exe deals them, for checking key.md
by a second route: Brogue's random generator (src/brogue/Math.c) and the draws initializeRogue
(src/brogue/RogueMain.c) makes before shuffleFlavors shuffles the colors, for a seed below 2^32.

Usage: flavors.py <seed> [src], with src the source build.sh fetched.
"""
import re, sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[3] / "target/agent/game/src"
DEEPEST_LEVEL = 40  # src/variants/GlobalsBrogue.c
DCOLS, DROWS = 79, 29  # src/brogue/Rogue.h: COLS - STAT_BAR_WIDTH - 1, ROWS - MESSAGE_LINES - 2
MASK = 0xFFFFFFFF


class Generator:
    """Bob Jenkins' small generator, seeded as raninit seeds it."""

    def __init__(self, seed: int):
        self.a, self.b = 0xF1EA5EED, seed & MASK
        self.c = (seed & MASK) ^ (seed >> 32)
        self.d = seed & MASK
        for _ in range(20):
            self.next()

    def next(self) -> int:
        rot = lambda x, k: ((x << k) | (x >> (32 - k))) & MASK
        e = (self.a - rot(self.b, 27)) & MASK
        self.a = self.b ^ rot(self.c, 17)
        self.b = (self.c + self.d) & MASK
        self.c = (self.d + e) & MASK
        self.d = (e + self.a) & MASK
        return self.d

    def range(self, lower: int, upper: int) -> int:
        if upper <= lower:
            return lower
        n = upper - lower + 1
        div = MASK // n
        while (r := self.next() // div) >= n:
            pass
        return lower + r


def colors(seed: int, src: Path) -> list[str]:
    rng = Generator(seed)
    up = ((DCOLS - 1) // 2 - 1, DROWS - 2)
    for _ in range(DEEPEST_LEVEL + 1):
        rng.range(0, 9999), rng.range(0, 9999)  # the level's seed
        while True:
            down = (rng.range(1, DCOLS - 2), rng.range(1, DROWS - 2))
            if max(abs(up[0] - down[0]), abs(up[1] - down[1])) >= DCOLS // 3:
                break
        up = down
    globals_c = (src / "brogue/Globals.c").read_text()
    names = re.findall(r'"([^"]+)"', re.search(r"itemColorsRef\[NUMBER_ITEM_COLORS\]\[30\] = \{(.*?)\};", globals_c, re.S).group(1))
    for i in range(len(names)):
        j = rng.range(0, len(names) - 1)
        names[i], names[j] = names[j], names[i]
    return names


def main() -> None:
    src = Path(sys.argv[2]) if len(sys.argv) > 2 else SRC
    shuffled = colors(int(sys.argv[1]), src)
    table = (src / "variants/GlobalsBrogue.c").read_text()
    potions = re.search(r"itemTable potionTable_Brogue\[\] = \{(.*?)\n\};", table, re.S).group(1)
    for name, slot in re.findall(r'\{"([^"]+)",\s*itemColors\[(\d+)\]', potions):
        print(f"{name}\titemColors[{slot}]\t{shuffled[int(slot)]}")


if __name__ == "__main__":
    main()
