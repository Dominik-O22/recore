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
"""
import bisect
import json
import os
import struct
import sys

SHF_ALLOC = 2
BASES = {183: 0xFFFF_8000_0000_0000, 62: 0xFFFF_FFFF_C000_0000}


def recore_layout(path):
    """Each allocated section's name and address, as relocatable::link places it."""
    data = open(path, 'rb').read()
    machine, = struct.unpack_from('<H', data, 18)
    shoff, = struct.unpack_from('<Q', data, 0x28)
    shnum, shstrndx = struct.unpack_from('<HH', data, 0x3C)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + 64 * i) for i in range(shnum)]
    names = headers[shstrndx][4]
    layout, at = {}, BASES[machine]
    for name, _, flags, _, _, size, _, _, align, _ in headers:
        if not flags & SHF_ALLOC:
            continue
        name = data[names + name:data.index(b'\0', names + name)].decode()
        if name in layout:
            sys.exit(f'{path}: two allocated sections are named {name}')
        align = max(align, 1)
        layout[name] = at = (at + align - 1) // align * align
        at += size
    return layout


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


if __name__ == '__main__':
    command, args = sys.argv[1], sys.argv[2:]
    if command == 'translate':
        translate(*args)
    elif command == 'names':
        names(args[0], args[1], set(args[2:]))
    elif command == 'sample':
        sample(*args)
    else:
        sys.exit(__doc__)
