"""Moves Ghidra's analysis of kernel modules to the addresses recore and the truth use.

A `.ko` is a relocatable ELF file whose sections all sit at 0. Ghidra lays them out by a rule of
its own, from 0x100000. recore's `relocatable::link` places each allocated section in the order of
the section headers, aligned, from where Linux loads modules, and the truth names those addresses.
ExportRef.java writes the memory blocks Ghidra made, each named for its section, so each address
moves to the same section and offset in recore's layout.

  kmod.py translate <bin-dir> <in-dir> <out-dir>
      Rewrites every <name>.json of <in-dir>, ExportRef.java's or ExportSignatures.java's, into
      <out-dir>. Addresses outside every section, such as Ghidra's EXTERNAL block, are dropped.
  kmod.py names <truth-dir> <out-dir> [names...]
      Counts the functions Ghidra named for a symbol that the truth has at the same address, and
      those it has at another, which would mean the translation is wrong.
  kmod.py sample <recore-signatures-dir> <in-dir> <out-dir>
      Keeps of each translated signature report only the functions recore's report has, so that
      `recore-decompile params` scores both decompilers on the same sample.
  kmod.py diff <bin-dir> <truth-dir> <recore-dir> <ghidra-dir> [<recore-dir-without-kcfi>]
      Lists by kind the function starts and noreturn calls one tool gets right and the other
      wrong, each kind with a count and an example.
"""
import bisect
import json
import os
import struct
import sys

SHF_ALLOC = 2
SHF_EXECINSTR = 4
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_NOBITS = 8
R_AARCH64_JUMP26 = 282
R_AARCH64_CALL26 = 283
BASES = {183: 0xFFFF_8000_0000_0000, 62: 0xFFFF_FFFF_C000_0000}


class Module:
    """A `.ko`'s sections, symbols and relocations, at the addresses recore gives them."""

    def __init__(self, path):
        self.data = data = open(path, 'rb').read()
        machine, = struct.unpack_from('<H', data, 18)
        shoff, = struct.unpack_from('<Q', data, 0x28)
        shnum, shstrndx = struct.unpack_from('<HH', data, 0x3C)
        self.headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + 64 * i) for i in range(shnum)]
        names = self.headers[shstrndx][4]
        self.names = [self.string(names, h[0]) for h in self.headers]
        self.addrs, self.layout, at = {}, {}, BASES[machine]
        for index, (_, _, flags, _, _, size, _, _, align, _) in enumerate(self.headers):
            if not flags & SHF_ALLOC:
                continue
            name = self.names[index]
            if name in self.layout:
                sys.exit(f'{path}: two allocated sections are named {name}')
            align = max(align, 1)
            self.addrs[index] = self.layout[name] = at = (at + align - 1) // align * align
            at += size

    def string(self, table, offset):
        return self.data[table + offset:self.data.index(b'\0', table + offset)].decode(errors='replace')

    def symbols(self):
        """Each symbol as (name, section index, value)."""
        symtab = next(h for h in self.headers if h[1] == SHT_SYMTAB)
        strings = self.headers[symtab[6]][4]
        return [(self.string(strings, name), shndx, value)
                for name, _, _, shndx, value, _ in struct.iter_unpack('<IBBHQQ', self.data[symtab[4]:symtab[4] + symtab[5]])]

    def relocations(self):
        """Each relocation of an allocated section as (place, kind, symbol name, target), where
        the target is None for a symbol the module does not define."""
        symbols = self.symbols()
        for header in self.headers:
            if header[1] != SHT_RELA or header[7] not in self.addrs:
                continue
            base = self.addrs[header[7]]
            for offset, info, addend in struct.iter_unpack('<QQq', self.data[header[4]:header[4] + header[5]]):
                name, shndx, value = symbols[info >> 32]
                target = self.addrs[shndx] + value + addend if shndx in self.addrs else None
                yield base + offset, info & 0xFFFFFFFF, name, target

    def section_of(self, addr):
        return next((i for i, a in self.addrs.items() if a <= addr < a + self.headers[i][5]), None)

    def word(self, addr):
        index = self.section_of(addr)
        offset = self.headers[index][4] + addr - self.addrs[index]
        return struct.unpack_from('<I', self.data, offset)[0]

    def data_in_code(self):
        """The ranges that `$d` mapping symbols mark as data inside code: clang's kCFI hashes."""
        marks = {}
        for name, shndx, value in self.symbols():
            if shndx in self.addrs and self.headers[shndx][2] & SHF_EXECINSTR and name[:2] in ('$d', '$x') and name[2:3] in ('', '.'):
                marks.setdefault(shndx, []).append((value, name[:2] == '$d'))
        ranges = []
        for shndx, marks in marks.items():
            marks.sort()
            for i, (value, is_data) in enumerate(marks):
                if is_data:
                    end = next((v for v, d in marks[i + 1:] if not d), self.headers[shndx][5])
                    ranges.append((self.addrs[shndx] + value, self.addrs[shndx] + end))
        return sorted(ranges)

    def adr_targets(self, relocated):
        """Where each `adr` without a relocation points: `_THIS_IP_`, an address in its own code."""
        targets = set()
        for index, addr in self.addrs.items():
            header = self.headers[index]
            if not header[2] & SHF_EXECINSTR or header[1] == SHT_NOBITS:
                continue
            for i, (insn,) in enumerate(struct.iter_unpack('<I', self.data[header[4]:header[4] + header[5] // 4 * 4])):
                place = addr + 4 * i
                if insn & 0x9F000000 == 0x10000000 and place not in relocated:
                    imm = (insn >> 3 & 0x1FFFFC) | (insn >> 29 & 3)
                    targets.add(place + imm - (imm & 0x100000) * 2)
        return targets


def recore_layout(path):
    """Each allocated section's name and address, as relocatable::link places it."""
    return Module(path).layout


def mover(path, blocks, shift):
    """A function from Ghidra's address less `shift` to recore's, None outside every section."""
    layout = recore_layout(path)
    loaded = sorted((b['start'], b['start'] + max(b['size'], 1), layout[b['name']])
                    for b in blocks if b['name'] in layout and not b['comment'].endswith('[not-loaded]'))
    starts = [start for start, _, _ in loaded]

    def move(addr):
        addr += shift
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0 or addr >= loaded[i][1]:
            return None
        return addr - loaded[i][0] + loaded[i][2]
    return move


def translate(bin_dir, in_dir, out_dir, blocks_dir=None):
    os.makedirs(out_dir, exist_ok=True)
    for file in sorted(os.listdir(in_dir)):
        if not file.endswith('.json'):
            continue
        report = json.load(open(os.path.join(in_dir, file)))
        name = file[:-5]
        # A signature report has no blocks of its own, so it takes those of the analysis.
        blocks = report.pop('blocks', None) or json.load(open(os.path.join(blocks_dir, file)))['blocks']
        # ExportRef.java takes Ghidra's image base off every address it writes.
        move = mover(os.path.join(bin_dir, name), blocks, report.get('shift', 0))
        functions = []
        for f in report['functions']:
            addr = move(f['addr'])
            if addr is None:
                continue
            f['addr'] = addr
            if 'ranges' in f:
                f['ranges'] = [[move(s), move(s) + e - s] for s, e in f['ranges'] if move(s) is not None]
            functions.append(f)
        report['functions'] = functions
        report['name'] = name
        if 'noreturn_calls' in report:
            report['noreturn_calls'] = [a for a in map(move, report['noreturn_calls']) if a is not None]
            report['jump_tables'] = [{'jump': move(t['jump']), 'targets': sorted(a for a in map(move, t['targets']) if a is not None)}
                                     for t in report['jump_tables'] if move(t['jump']) is not None]
        else:
            report.setdefault('fragments_skipped', 0)
        json.dump(report, open(os.path.join(out_dir, file), 'w'))


def names(truth_dir, out_dir, only):
    right = wrong = 0
    examples = []
    for file in sorted(os.listdir(out_dir)):
        if not file.endswith('.json') or only and file[:-5] not in only:
            continue
        truth_path = os.path.join(truth_dir, file)
        if not os.path.exists(truth_path):
            continue
        truth = {}
        for f in json.load(open(truth_path))['functions']:
            truth.setdefault(f['name'], set()).add(f['addr'])
        for f in json.load(open(os.path.join(out_dir, file)))['functions']:
            where = truth.get(f.get('name'))
            if not where:
                continue
            if f['addr'] in where:
                right += 1
            else:
                wrong += 1
                examples.append(f"{file[:-5]} {f['name']} ghidra {f['addr']:#x} truth {min(where):#x}")
    print(f'named functions at the truth address: {right}, elsewhere: {wrong}')
    for line in examples[:10]:
        print('  ' + line)


def sample(recore_dir, in_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for file in sorted(os.listdir(recore_dir)):
        theirs = os.path.join(in_dir, file)
        if not file.endswith('.json') or file == 'summary.json' or not os.path.exists(theirs):
            continue
        wanted = {f['addr'] for f in json.load(open(os.path.join(recore_dir, file)))['functions']}
        report = json.load(open(theirs))
        report['functions'] = [f for f in report['functions'] if f['addr'] in wanted]
        json.dump(report, open(os.path.join(out_dir, file), 'w'))


def diff(bin_dir, truth_dir, recore_dir, ghidra_dir, blanked_dir=None):
    """Sorts each false start and each wrong noreturn call by kind, for the starts and calls
    where one tool is right and the other wrong. `blanked_dir` is recore's analysis of the same
    modules with the kCFI hashes zeroed, which names what the hashes cause."""
    from collections import Counter, defaultdict
    counts = defaultdict(Counter)
    examples = {}
    for file in sorted(os.listdir(truth_dir)):
        name = file[:-5]
        try:
            ours, theirs = (json.load(open(os.path.join(d, file))) for d in (recore_dir, ghidra_dir))
        except FileNotFoundError:
            continue
        truth = json.load(open(os.path.join(truth_dir, file)))
        module = Module(os.path.join(bin_dir, name))
        functions = sorted((f['addr'], f['addr'] + f['size'], f['name']) for f in truth['functions'])
        starts = [f[0] for f in functions]
        text = truth['text']

        def where(addr):
            i = bisect.bisect_right(starts, addr) - 1
            f = functions[i] if i >= 0 and addr < functions[i][1] else None
            return f'{name} {addr:#x} ' + (f'{f[2]}+{addr - f[0]:#x}' if f else 'outside every function')

        def note(table, kind, addr):
            counts[table][kind] += 1
            examples.setdefault((table, kind), where(addr))

        relocations = list(module.relocations())
        referrers = defaultdict(set)
        callees = {}
        for place, kind, symbol, target in relocations:
            if target is not None:
                referrers[target].add(module.names[module.section_of(place)])
            if kind in (R_AARCH64_CALL26, R_AARCH64_JUMP26):
                callees[place] = symbol if target is None else target
        data = module.data_in_code()
        adrs = module.adr_targets({place for place, _, _, _ in relocations})
        origin = {f['addr']: f.get('origin', '') for f in ours['functions']}
        blanked = json.load(open(os.path.join(blanked_dir, file))) if blanked_dir else None
        by_hashes = 'gone once the kCFI hashes are blanked'

        def kind_of_start(addr):
            i = bisect.bisect_right(data, (addr, float('inf'))) - 1
            if i >= 0 and addr < data[i][1]:
                return 'a kCFI type hash read as code'
            if blanked and addr not in blanked_starts:
                return by_hashes
            sources = referrers.get(addr, ())
            if '__jump_table' in sources:
                return 'a jump label target'
            if addr in adrs:
                return 'the address an adr takes of its own code (_THIS_IP_)'
            if any(module.headers[module.section_of(module.layout[s])][2] & SHF_EXECINSTR for s in sources):
                return 'an address code takes'
            if sources:
                return 'an address in ' + ' '.join(sorted(sources))
            return f'recore origin {origin[addr]}' if addr in origin else 'no reference'

        def callee(call):
            target = callees.get(call)
            if target is None:
                insn = module.word(call)
                if insn & 0x7C000000 != 0x14000000:
                    return 'not a branch'
                imm = insn & 0x3FFFFFF
                target = call + 4 * (imm - (imm & 0x2000000) * 2)
            if isinstance(target, str):
                return target
            i = bisect.bisect_right(starts, target) - 1
            return functions[i][2] if i >= 0 and target < functions[i][1] else f'{target:#x}'

        in_text = lambda addr: text[0] <= addr < text[1]
        true_starts = {a for a in starts if in_text(a)}
        false = [{f['addr'] for f in tool['functions'] if in_text(f['addr'])} - true_starts for tool in (ours, theirs)]
        blanked_starts = {f['addr'] for f in blanked['functions']} if blanked else set()
        for tool, starts_ in zip(('recore', 'Ghidra'), false):
            for addr in starts_:
                if addr % 4:
                    note('false starts at an address not a multiple of 4', tool, addr)
        for addr in false[0] - false[1]:
            note('false starts recore has and Ghidra not', kind_of_start(addr), addr)
        for addr in false[1] - false[0]:
            note('false starts Ghidra has and recore not', kind_of_start(addr), addr)
        found = [{f['addr'] for f in tool['functions']} for tool in (ours, theirs)]
        for addr in true_starts - found[1]:
            note('true starts Ghidra misses', f'recore origin {origin.get(addr, "none")}', addr)
        for addr in true_starts - found[0]:
            note('true starts recore misses', 'missed', addr)
        noreturn = set(truth['noreturn_calls'])
        calls = [{a for a in tool['noreturn_calls'] if in_text(a)} for tool in (ours, theirs)]
        for addr in calls[0] - calls[1] - noreturn:
            gone = blanked and addr not in blanked['noreturn_calls']
            note('wrong noreturn calls recore has and Ghidra not', f'{callee(addr)}' + (f', {by_hashes}' if gone else ''), addr)
        for addr in calls[1] - calls[0] - noreturn:
            note('wrong noreturn calls Ghidra has and recore not', callee(addr), addr)
        for addr in noreturn - calls[0] - calls[1]:
            note('noreturn calls both miss', callee(addr), addr)
        for addr in noreturn & calls[0] - calls[1]:
            note('noreturn calls Ghidra misses', callee(addr), addr)
        for addr in noreturn & calls[1] - calls[0]:
            note('noreturn calls recore misses', callee(addr), addr)
    for table, kinds in sorted(counts.items()):
        print(f'{table}: {sum(kinds.values())}')
        for kind, count in kinds.most_common(12):
            print(f'  {count:6}  {kind[:90]}  e.g. {examples[(table, kind)][:120]}')


if __name__ == '__main__':
    command, args = sys.argv[1], sys.argv[2:]
    if command == 'translate':
        translate(*args)
    elif command == 'names':
        names(args[0], args[1], set(args[2:]))
    elif command == 'sample':
        sample(*args)
    elif command == 'diff':
        diff(*args)
    else:
        sys.exit(__doc__)
