# Answer key: game.exe

One point per item. An item passes when the report states it, and a report that asserts something this key calls false fails the item that covers it. Addresses are as `game.exe` loads, at its preferred base 0x400000. They hold for the build whose `.text` and `.data` hash to `0ff97853`, which `build.sh` checks; another compiler gives other addresses and this key does not apply to it.

The game is Brogue CE 1.15.1. Names below come from `game.pdb` and the source, for whoever checks the key. The agent sees neither. Each task ends with how its key was derived, so it can be checked again: `pdb.py`, `stores.py` and `flavors.py` are in this directory, and source paths are under `target/agent/game/src`.

## Task A: the field at 0xfa

- **A1.** The 16-bit field at 0xfa is the creature's weakness: how many points of strength it has lost to weakening. Each weakening adds one, up to 10. For the player it comes off strength when weapons, armor and throws check it; for a monster it lowers accuracy, damage and defense.
- **A2.** The record type is the game's creature, monster or player, 0x214 bytes. The record at 0x5a9884 is the player's. Saying "monster" or "unit" record passes; the size is not needed.
- **A3.** Three functions write it through a pointer to any creature: 0x441d50 adds one while it is below 10 (store at 0x441d67), 0x441e80 sets it to 0 when a full cure removes ailments (0x44200c), and 0x45b230 sets it to 0 when the creature's weakened status, the word at +0x190, counts down to zero (0x45b4c9). All three are needed.
- **A4.** Two functions write the player's copy at 0x5a997e directly: 0x446f00 sets it to 0 when the player drinks a potion of strength (0x44734d), and 0x47e780 sets it to 0 when the player's weakened status wears off in the per-turn status update (0x47f8cc). Both are needed. The status update is not a function of its own in the binary: it sits inside 0x47e780.
- **A5.** No other function writes it. Five functions store four bytes at offset 0xfa of a different record, a 0x138-byte item: 0x434a00, 0x434bf0, 0x436bb0, 0x43f460 and 0x449a50. A report that names any of them as a writer of the creature's field fails this item. Copies and clears of a whole creature, such as the `memset` of the player's record at game start (src/brogue/RogueMain.c:363), are excluded by the task and count neither way.

Derivation. `pdb.py struct creature` gives `0x0fa weaknessAmount` and sizeof 0x214, and `pdb.py globals` puts `player` at 0x5a9884. `stores.py 0xfa 2 0x5a9884` lists every store over the field: the eight above, the five item stores (`pdb.py struct item` puts the 0xfa bytes inside `keyLoc`), and stores relative to esp, which are locals. The writes in the source are `weaken` (src/brogue/Items.c:3829), `heal` with `panacea` (Items.c:3950), `drinkPotion`, `POTION_STRENGTH` (Items.c:7306), `decrementMonsterStatus`, `STATUS_WEAKENED` (src/brogue/Monsters.c:1857), and `decrementPlayerStatus` (src/brogue/Time.c:2030), which is static and inlined into `playerTurnEnded`. The uses are in src/brogue/Combat.c:61-99 and Items.c:3209-3218.

## Task B: potion colors for seed 2026

- **B1.** The potion of detect magic is brown.
- **B2.** The potion of descent is gray.
- **B3.** How the colors are dealt: the game start, 0x473050, seeds the generator (0x455cd0) and draws each of 41 levels' seed and stairs before the shuffle function 0x449de0 shuffles the 21 color names into 30-byte slots at 0x5f335c. Each potion's record in the table at 0x506010, with records 0x61c bytes apart, points at the slot that names its color: detect magic's record at 0x507880 points at slot 5, 0x5f33f2, and descent's record at 0x50b598 points at slot 15, 0x5f351e. Naming the shuffle or the game start and the slot each potion points at passes. A color guessed without running or reproducing the draws fails B1 and B2, whatever it is.

Derivation. Two routes agree. `flavors.py 2026` reproduces the generator of src/brogue/Math.c and the draws of `initializeRogue` (src/brogue/RogueMain.c), parsing the color list from src/brogue/Globals.c and the table from src/variants/GlobalsBrogue.c, and prints `detect magic itemColors[5] brown` and `descent itemColors[15] gray`. recore's emulator runs the binary itself:

```
recore-mcp run game.exe --function 0x473050 --args 2026 --args 0 --before 0x473030 --skip 0x44bd00:0 --dump 0x5f33f2:30 --dump 0x5f351e:30
```

It stops in 0x42e110 after the shuffle, at a `pshuflw` the emulator does not run, and the dumps read `brown` and `gray`. Two things are needed for that run, and they are what make the task hard. The `memset` at 0x44bd00 starts with SSE2 the emulator stops on, so it must be skipped; it clears memory that reads as zero in the emulator anyway. And 0x473030 must run first: it sets the variant's tables, among them the pointer at 0x5ab3a0 that gives the number of levels. Without it the run reads zeros there, finishes without complaint and deals other colors: detect magic comes out crimson.

## Task C: the record the pack is made of

- **C1.** A record is 0x138 bytes (312).
- **C2.** The category is the 16-bit field at +0x0, one bit per category: food 1, weapon 2, armor 4, potion 8, scroll 0x10 and so on. The kind within the category is the 16-bit field at +0x2. Both offsets are needed; the bit values are not.
- **C3.** The stack count is the 16-bit field at +0x2c, and the letter it is listed under is the byte at +0x2e.
- **C4.** The enchantment is the 16-bit field at +0x12, and the charges the 16-bit field at +0x10.
- **C5.** The map position is two 16-bit coordinates at +0x7e (x) and +0x80 (y), and the next record is the pointer at +0x134. The record that 0x5ab3b4 points at is a placeholder whose link leads to the first carried thing; the report need not say so.

Derivation. `pdb.py struct item` gives sizeof 0x138 and `category 0x000`, `kind 0x002`, `charges 0x010`, `enchant1 0x012`, `quantity 0x02c`, `inventoryLetter 0x02e`, `loc 0x07e`, `nextItem 0x134`; `pdb.py globals` puts `packItems` at 0x5ab3b4. In the binary, `malloc` at 0x44ba80 is called for 0x138 bytes in item creation at 0x434a01, and at game start at 0x473ba5, whose result goes to 0x5ab3b4 and is cleared with a `memset` of 0x138 bytes: the chain's placeholder (src/brogue/RogueMain.c, `packItems = (item *) malloc(sizeof(item))`). The category bits are `enum itemCategory` in src/brogue/Rogue.h.

## Task D: where 0x46d810 goes

- **D1.** 0x46d810 is a single `jmp` through the pointer at 0x5fd7f4. That slot is entry 3, at offset 0xc, of a table of nine function pointers, 36 bytes at 0x5fd7e8, in data that is zero in the file.
- **D2.** `main`, 0x454d20, fills the table by copying the 36 bytes at 0x55c6d8: a 16-byte move to 0x5fd7e8, which covers the slot, a 16-byte move to 0x5fd7f8 and a 4-byte move to 0x5fd808, at 0x454d2f to 0x454d4e. It does the same again at 0x4550e9 to 0x455108 on another path. Naming `main` and the source table at 0x55c6d8 passes.
- **D3.** The slot therefore holds 0x46d7f0, a lone `ret`: the call draws nothing. A report that says the pointer is never set, is null, or cannot be known fails D2 and D3.

Derivation. `pdb.py functions` names 0x46d810 `plotChar`, 0x46d7f0 both `null_plotChar` and `null_nextKeyOrMouseEvent`, which the linker folded into one, and `pdb.py globals` names 0x5fd7e8 `currentConsole` and 0x55c6d8 `nullConsole`. `pdb.py struct brogueConsole` gives nine pointers with `plotChar` at 0xc. The source is src/platform/platformdependent.c:224 for the jump, src/platform/main.c for `currentConsole = nullConsole`, and src/platform/null-platform.c for the table. `recore-mcp bytes game.exe --addr 0x55c6d8 --len 36` shows 0x46d7f0 in its fourth entry. This is the hard one to find: `recore-mcp xrefs` of 0x5fd7f4 lists only the read in 0x46d810, since the store that fills it starts at 0x5fd7e8.

## Task E: the scroll of teleportation

- **E1.** Reading a scroll is 0x447b60. It switches on the scroll's kind, the 16-bit field at +2 of its item record, through the jump table at 0x4f2e58: 14 entries for kinds 0 to 13, bounds checked at 0x447cd3, jump at 0x447cdc.
- **E2.** Teleportation is kind 2, the third record of the scroll table at 0x50c1d0, whose records are 0x61c bytes apart; the record at 0x50ce08 names "teleportation". Entry 2 of the jump table, at 0x4f2e60, holds 0x447f95. A report that gives 0x447f2d, the third address of the address-sorted `switch to` list recore prints, which is the recharging case, fails this item.
- **E3.** 0x447f95 calls 0x459150, the teleport function, with the player's record 0x5a9884, -1 as the destination, which is x and y of -1 and means no destination, so the function picks a random spot, and 1. The meaning of the 1, that the move respects the creature's terrain preferences, is not needed.

Derivation. `pdb.py functions` names 0x447b60 `readScroll` and 0x459150 `teleport`; `pdb.py globals` names 0x50c1d0 `scrollTable_Brogue`, and `pdb.py struct itemTable` gives sizeof 0x61c. `enum scrollKind` in src/brogue/Rogue.h puts `SCROLL_TELEPORT` at 2, and src/brogue/Items.c, `readScroll`, has `case SCROLL_TELEPORT: teleport(&player, INVALID_POS, true)`. `recore-mcp bytes game.exe --addr 0x4f2e58 --len 56` gives the entries: 0x447ce3, 0x448055, 0x447f95, 0x447fc0, 0x447f2d, and on.

## Task F: poison

- **F1.** Once a turn, the player's status update in 0x47e780 and the monsters' in 0x45b230 take one from the creature's poison duration, the 16-bit field at +0x1a2 (the player's at 0x5a9a26), and inflict damage equal to its poison amount, the 16-bit field at +0xfc (the player's at 0x5a9980), through 0x416a70 with protective shields ignored. When the duration reaches zero they set the amount to 0. Both functions are needed.
- **F2.** Each poisoning adds its concentration to the amount, which is at least 1, and its duration to the duration: 0x418330, inlined into the attack function 0x416f40 at 0x417d9a. A hit from a creature with ability bit 0x80 at +0xe8 deals 1 damage directly, and its rolled damage becomes the poison's duration with concentration 1, at 0x417658 to 0x417670.
- **F3.** Two hits rolling 7 and 4 cost 24 hit points over 11 turns: 1 each directly, then 2 a turn for 11 turns, 22 from poison. The amount is 2 because each hit added 1. A report of 11 from poison, one a turn, fails. This holds outside the game's easy mode, which cuts damage to the player to a fifth.

Derivation. `pdb.py functions` names 0x47e780 `playerTurnEnded`, 0x45b230 `decrementMonsterStatus`, 0x416a70 `inflictDamage`, 0x418330 `addPoison` and 0x416f40 `attack`. `pdb.py struct creature` gives `poisonAmount 0x0fc` and `status 0x18c`, and `STATUS_POISONED` is 11 in `enum statusEffects` (src/brogue/Rogue.h), so the duration is at 0x18c + 2 × 11 = 0x1a2. The source is src/brogue/Time.c:2329-2337 for the player, src/brogue/Monsters.c:1907-1922 for monsters, src/brogue/Combat.c:1615 for `addPoison`, and `attack` in Combat.c for `poisonDamage = damage; damage = 1;` and `specialHit`'s `addPoison(defender, damage, 1)`. `stores.py 0xfc 2 0x5a9884` lists the amount's writers: 0x417daa in `attack`, 0x418381 in `addPoison`, the clears in `heal`, `decrementMonsterStatus` and `playerTurnEnded`, and the item stores again.

## What to expect

- **Hard: B.** It needs a run of the game start, and the run fails twice before it works: the emulator stops on the first `memset`, and without the variant's setup the run finishes and deals the wrong colors. Reproducing the draws by hand means reading 41 iterations of a loop with a retry inside it.
- **Hard: D.** Nothing the tool lists writes the slot. The agent has to see that a copy of a whole table in `main` covers it.
- **Hard: A.** The field query mixes in five item functions, the player's two writers address the player's record directly and show up only among 33 "reads or writes it" rows for 0x5a997e, and one of them sits inside an 8 KB function.
- **Medium: E.** The jump table is plain, but recore's `switch to` list is sorted by address, so its third entry is not case 2.
- **Medium: F.** Strings such as "Died from poison" lead to the right code. The stacking of the amount is where a careless answer goes wrong.
- **Medium: C.** Many functions use the fields; the work is in naming each one from its use.
