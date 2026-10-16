// C interface between recore and Ghidra's decompiler engine.
//
// One RdSession is one ghidra::Architecture: a program image, its symbol database and a
// SLEIGH translator. Sessions are independent of each other and may run on different
// threads, but a single session must only be used by one thread at a time. The two places
// where the engine touches process-wide state, session creation and C printing, take a lock.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "funcdata.hh"
#include "grammar.hh"
#include "sleigh_arch.hh"

using namespace ghidra;
using namespace std;

extern "C" {

struct RdSection {
  uint64_t addr;
  const uint8_t *data;
  size_t len;
  uint32_t readonly;
  uint32_t code;
};

struct RdParam {
  const char *type_name;
  const char *storage;  // register name, or "<space>:<offset>"
  uint32_t size;
};

// Bits of RdDecompiled::flags.
const uint32_t RD_BAD_DATA = 4;        // flow ran into bytes that do not decode
const uint32_t RD_UNIMPLEMENTED = 8;  // flow hit an instruction without p-code semantics
const uint32_t RD_RETURNS_VALUE = 16;

// Pointers stay valid until the next call on the same session.
struct RdDecompiled {
  const char *c_text;
  const char *return_type;
  const RdParam *params;
  size_t param_count;
  // Jump tables the decompiler ended up with: the indirect jump's address, and for table i
  // jump_counts[i] consecutive entries of jump_targets (in table order, duplicates kept).
  const uint64_t *jump_addrs;
  const size_t *jump_counts;
  size_t jump_table_count;
  const uint64_t *jump_targets;
  uint32_t flags;
  // The function's data flow after simplification, if rd_set_flow asked for it: see `dump_flow`.
  const char *flow;
  // The function's variables, a line each: the name, a tab, and the place rd_name_local takes.
  const char *locals;
};

// What struct recovery hands to recore and gets back: see `recover_structs`, and
// crates/decomp/src/ffi.rs for each field.
struct RdObject {
  int64_t low, high;
  uint8_t locked, global, number;
};
struct RdRoot {
  uint32_t object;
  const char *reg;
  uint64_t stack;
  int64_t offset;
};
struct RdAccess {
  uint32_t object;
  int64_t offset;
  uint32_t size;
  uint8_t kind;
};
struct RdLink {
  uint32_t object;
  int64_t offset;
  uint32_t child;
};
struct RdStride {
  uint32_t object;
  uint64_t stride;
};
struct RdPass {
  uint32_t object;
  uint64_t callee;
  const char *reg;
  uint64_t stack;
  int64_t offset;
};
struct RdEvidence {
  uint64_t function;
  uint32_t pointer;
  const RdObject *objects;
  size_t object_count;
  const RdRoot *roots;
  size_t root_count;
  const RdAccess *accesses;
  size_t access_count;
  const RdLink *links;
  size_t link_count;
  const RdStride *strides;
  size_t stride_count;
  const RdPass *passed;
  size_t pass_count;
};
struct RdPlan {
  const char *xml;
  const char *const *names;
  const char *const *recovered;
  const uint8_t *arrays;
  size_t recovered_count;
  const char *const *warnings;
  size_t warning_count;
};
typedef int (*RdPlanHook)(void *ctx, const RdEvidence *evidence, RdPlan *out);
typedef void (*RdWrappedHook)(void *ctx, uint64_t function, const char *name);

}  // extern "C"

namespace {

// Serves bytes straight from the sections handed over by recore; no file is parsed.
class SectionImage : public LoadImage {
  struct Section {
    uintb addr;
    vector<uint1> data;
    bool readonly;
    bool code;
    uintb end() const { return addr + data.size(); }
  };
  vector<Section> sections;  // sorted by address, non-overlapping

  const Section *find(uintb addr) const {
    auto iter = upper_bound(sections.begin(), sections.end(), addr,
                            [](uintb a, const Section &s) { return a < s.addr; });
    if (iter == sections.begin()) return nullptr;
    --iter;
    return addr < iter->end() ? &*iter : nullptr;
  }

 public:
  string language;             // SLEIGH language and compiler id, such as x86:LE:32:default:windows
  AddrSpace *space = nullptr;  // the space the code is in, known once the translator exists
  AddrSpace *constant = nullptr;
  VarnodeData assist_place;  // a temporary no instruction and no analysis uses, known with it
  // While a function is being decompiled, no other function's entry decodes: see `hidden`.
  unordered_set<uint64_t> entries;  // every declared function start
  set<pair<uint64_t, uint64_t>> allowed;  // (function, entry) pairs exempt from the above
  uint64_t current = ~(uint64_t)0;  // the function being decompiled, or none

  // A range of addresses that holds the bytes found elsewhere: `[start, end)` is the code from
  // `target` on, as each bank of banked code shows the code all banks share. Sorted by start.
  struct Mirror {
    uintb start, end, target;
  };
  vector<Mirror> mirrors;
  // Addresses a jump or call does not stay at: code there only passes control on to the other
  // address, as a trampoline into another bank does.
  unordered_map<uint64_t, uint64_t> redirects;
  // Calls that never return to the code after them, because the routine they call takes its
  // return address as the address of a table and jumps to an entry of it: each with the
  // register the routine picks the entry by.
  // A call that is a jump to one of several places, picked by `selector`. With `cases`, the
  // compiler spec's jump assist `assist` says where from `count` cases listed at `list`.
  struct SwitchCall {
    VarnodeData selector;
    bool cases;
    uintb assist, count, list;
  };
  unordered_map<uint64_t, SwitchCall> switch_calls;
  // Calls followed by data that the routine they call reads and returns past: each with the
  // number of bytes.
  unordered_map<uint64_t, int4> data_after;
  // Code runs from the end of one function into the start of the next on purpose, to share
  // that one's code: see rd_functions_run_on.
  bool functions_run_on = false;

  SectionImage(const string &lang, const RdSection *secs, size_t count)
      : LoadImage("recore"), language(lang) {
    for (size_t i = 0; i < count; ++i)
      sections.push_back({secs[i].addr, vector<uint1>(secs[i].data, secs[i].data + secs[i].len),
                          secs[i].readonly != 0, secs[i].code != 0});
    sort(sections.begin(), sections.end(),
         [](const Section &a, const Section &b) { return a.addr < b.addr; });
  }

  // Where the bytes at `addr` are kept, and in `room` how many lie there in a row.
  uintb kept(uintb addr, uintb &room) const {
    room = ~(uintb)0;
    auto iter = upper_bound(mirrors.begin(), mirrors.end(), addr,
                            [](uintb a, const Mirror &m) { return a < m.start; });
    if (iter != mirrors.end()) room = iter->start - addr;
    if (iter == mirrors.begin()) return addr;
    --iter;
    if (addr >= iter->end) return addr;
    room = iter->end - addr;
    return iter->target + (addr - iter->start);
  }

  // Where a jump or call to `addr` goes.
  uintb reached(uintb addr) const {
    uintb room;
    addr = kept(addr, room);
    auto found = redirects.find(addr);
    return found == redirects.end() ? addr : found->second;
  }

  // Whether the instruction at `addr` is kept from the function being decompiled, because it is
  // where another function starts. Flow that runs or jumps into another function is then cut
  // off with a "bad instruction" warning instead of being followed. That happens after a call
  // the engine does not know to be non-returning, and one such miss can chain through
  // thousands of functions. The engine's own flow bounds (FlowInfo::setRange) cannot do
  // this: a restart drops them, and a fall-through across the bound fails the function.
  bool hidden(uintb addr) const {
    if (current == ~(uint64_t)0) return false;
    uintb room;
    addr = kept(addr, room);
    if (addr == current || entries.count(addr) == 0 || allowed.count({current, addr}) != 0) return false;
    const Section *sec = find(addr);
    return sec != nullptr && sec->code;
  }

  // The instruction decoder reads a fixed window ahead, so a request may run past the end of a
  // section. Like Ghidra's own loaders, pad with zeros and fail only if the first byte is unmapped.
  // Only the code space has bytes: an address in another space is not one of a section.
  void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
    uintb cur = addr.getOffset();
    int4 done = 0;
    while (done < size && addr.getSpace() == space) {
      uintb room;
      uintb from = kept(cur, room);
      const Section *sec = find(from);
      if (sec == nullptr) break;
      int4 count = (int4)min<uintb>(min<uintb>(size - done, sec->end() - from), room);
      memcpy(ptr + done, sec->data.data() + (from - sec->addr), count);
      done += count;
      cur += count;
    }
    if (done == 0) {
      ostringstream msg;
      msg << "No bytes at 0x" << hex << addr.getOffset();
      throw DataUnavailError(msg.str());
    }
    memset(ptr + done, 0, size - done);
  }

  // The decompiler only trusts memory contents (jump tables, constants) inside these ranges.
  void getReadonly(RangeList &list) const override {
    for (const Section &sec : sections)
      if (sec.readonly && !sec.data.empty()) list.insertRange(space, sec.addr, sec.end() - 1);
  }

  string getArchType() const override { return language; }
  void adjustVma(long) override {}
};

// Hands on the p-code of one instruction with its jumps and calls going where the image says
// they go.
class Retargeted : public PcodeEmit {
  PcodeEmit &out;
  const SectionImage &image;
  const SectionImage::SwitchCall *selector;  // set for a call that is a jump through a table

 public:
  bool runs_on = true;  // whether control passes on to the next instruction

  Retargeted(PcodeEmit &o, const SectionImage &i, const SectionImage::SwitchCall *s) : out(o), image(i), selector(s) {}
  void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) override {
    runs_on = opc != CPUI_BRANCH && opc != CPUI_BRANCHIND && opc != CPUI_RETURN && selector == nullptr;
    if (selector != nullptr) {
      // All the instruction does is hand control to the routine, which jumps on. The return
      // address it pushes for the routine to find its table by is not left on the stack.
      if (opc != CPUI_CALL) return;
      VarnodeData input = selector->selector;
      if (selector->cases) {
        // Where the jump goes is what the assist makes of the selector. The engine works the
        // places and the value of each case out from that, and switches on the selector.
        uint4 wide = image.assist_place.size;
        VarnodeData place = image.assist_place;
        VarnodeData inputs[4] = {{image.constant, selector->assist, 4}, input, {image.constant, selector->count, wide}, {image.constant, selector->list, wide}};
        out.dump(addr, CPUI_CALLOTHER, &place, inputs, 4);
        input = place;
      }
      out.dump(addr, CPUI_BRANCHIND, nullptr, &input, 1);
      return;
    }
    bool direct = opc == CPUI_BRANCH || opc == CPUI_CBRANCH || opc == CPUI_CALL;
    if (direct && vars[0].space == image.space) vars[0].offset = image.reached(vars[0].offset);
    out.dump(addr, opc, outvar, vars, isize);
  }
};

// The translator, which decodes what the image lets the function being decompiled see.
class SectionSleigh : public Sleigh {
  const SectionImage &image;

 public:
  SectionSleigh(SectionImage *img, ContextDatabase *context) : Sleigh(img, context), image(*img) {}

  int4 oneInstruction(PcodeEmit &emit, const Address &addr) const override {
    uintb at = addr.getOffset();
    if (image.hidden(at)) throw BadDataError("The instruction is the entry of another function");
    if (image.mirrors.empty() && image.redirects.empty() && image.switch_calls.empty() && image.data_after.empty() &&
        !image.functions_run_on)
      return Sleigh::oneInstruction(emit, addr);
    auto jump = image.switch_calls.find(at);
    Retargeted retargeted(emit, image, jump == image.switch_calls.end() ? nullptr : &jump->second);
    int4 length = Sleigh::oneInstruction(retargeted, addr);
    auto data = image.data_after.find(at);
    if (data != image.data_after.end()) length += data->second;
    if (image.functions_run_on && retargeted.runs_on && image.hidden(at + length)) {
      // The function ends by running into the next one: it calls that one and returns, as the
      // engine has it for a jump that is a tail call.
      VarnodeData next = {image.space, at + length, 1};
      emit.dump(addr, CPUI_CALL, nullptr, &next, 1);
      VarnodeData nowhere = {getConstantSpace(), 0, 1};
      emit.dump(addr, CPUI_RETURN, nullptr, &nowhere, 1);
    }
    return length;
  }
};

class SectionArchitecture : public SleighArchitecture {
  SectionImage *image;  // owned by Architecture::loader once buildLoader has run

  void buildLoader(DocumentStorage &) override {
    collectSpecFiles(*errorstream);
    loader = image;
  }

  // SleighArchitecture keeps one translator per language in a static map and re-points it at
  // whichever Architecture was built last. A translator per session is what makes sessions
  // independent of each other.
  Translate *buildTranslator(DocumentStorage &) override { return new SectionSleigh(image, context); }

  void postSpecFile() override {
    Architecture::postSpecFile();
    image->space = getDefaultCodeSpace();
    image->constant = translate->getConstantSpace();
    image->assist_place = {translate->getUniqueSpace(), translate->getUniqueStart(Translate::RUNTIME_RETURN_LOCATION), image->space->getAddrSize()};
  }

 public:
  SectionArchitecture(SectionImage *img, ostream *errs)
      : SleighArchitecture("recore", img->language, errs), image(img) {}

  // ~SleighArchitecture forgets the translator instead of freeing it, so the session does.
  const Translate *translator() const { return translate; }

  // What the session does when the engine starts typing a function: see `recover_structs`.
  std::function<void(Funcdata &)> start_types;
  void startTypes(Funcdata &data) override {
    if (start_types) start_types(data);
  }
};

void fail(char *err, size_t errlen, const string &message) {
  if (errlen == 0) return;
  size_t count = min(errlen - 1, message.size());
  memcpy(err, message.data(), count);
  err[count] = 0;
}

// Runs `body`, turning any C++ exception into an error string. Nothing may unwind into Rust.
template <typename F>
bool guarded(char *err, size_t errlen, F body) {
  try {
    body();
    return true;
  } catch (const LowlevelError &e) {
    fail(err, errlen, e.explain);
  } catch (const DecoderError &e) {
    fail(err, errlen, e.explain);
  } catch (const std::exception &e) {
    fail(err, errlen, e.what());
  } catch (...) {
    fail(err, errlen, "unknown C++ exception");
  }
  return false;
}

}  // namespace

struct RdSession {
  ostringstream messages;  // warnings the engine prints while loading specs
  DocumentStorage store;   // parsed .pspec/.cspec; the architecture keeps pointers into it
  SectionImage *image = nullptr;  // owned by `arch`
  SectionArchitecture *arch = nullptr;
  const Translate *translator = nullptr;
  bool print_c = true;
  bool keep_prototypes = false;
  bool kept_are_lower_bounds = true;  // see rd_keep_prototypes_exact
  bool result_in_first_argument = false;  // see rd_result_in_first_argument
  bool stack_aggregates = false;  // see rd_stack_aggregates
  bool want_flow = false;
  bool want_addresses = false;
  set<uint64_t> kept;  // functions whose prototype this session locked
  // Functions rd_takes_variable_arguments named: those of the program that take a format and
  // the arguments it asks for.
  set<uint64_t> saves_arguments;
  // Calls whose arguments rd_format_call settled before their function was decompiled.
  set<pair<uint64_t, uint64_t>> format_calls;
  // Names given to variables, per function: the variable's place and its name.
  map<uint64_t, vector<pair<string, string>>> local_names;
  // Where and as what each function decompiled so far returns its value, if it returns one.
  map<uint64_t, ParameterPieces> outputs;
  // Functions whose result rd_returns_like settled, until they are next decompiled.
  set<uint64_t> returns_like;
  // The registers rd_keep_registers named for each function.
  map<uint64_t, vector<VarnodeData>> kept_registers;
  // recore's side of struct recovery, which plans the structs: see rd_set_struct_hooks.
  RdPlanHook plan = nullptr;
  RdWrappedHook wrapped = nullptr;
  void *structs = nullptr;
  // Every struct recovery defined, each with whether it is the element of an array.
  map<const Datatype *, bool> recovered;

  // Backing storage for the last RdDecompiled, listing and type layout.
  string c_text, return_type, flow, locals, text;
  vector<string> strings;
  vector<RdParam> params;
  vector<uint64_t> jump_addrs, jump_targets;
  vector<size_t> jump_counts;

  // Imported functions have no code in the image, so each gets a made-up address outside it.
  uint64_t next_external = 0;  // set once the address space is known
  map<string, uint64_t> externals;  // import name to its made-up address
  map<uint64_t, uint64_t> slots;    // GOT slot to the made-up address of its import

  ~RdSession() {
    delete arch;
    delete translator;
  }

  // Address spaces besides the one the code is in, each with the address recore gives its
  // first byte. Those addresses lie above every address of code.
  vector<pair<uint64_t, AddrSpace *>> spaces;

  // The engine's address for one of recore's.
  Address address(uint64_t offset) const {
    for (const pair<uint64_t, AddrSpace *> &mapped : spaces)
      if (offset >= mapped.first && offset - mapped.first <= mapped.second->getHighest())
        return Address(mapped.second, offset - mapped.first);
    return Address(arch->getDefaultCodeSpace(), offset);
  }

  // recore's address for one of the engine's.
  uint64_t offset(const Address &addr) const {
    for (const pair<uint64_t, AddrSpace *> &mapped : spaces)
      if (addr.getSpace() == mapped.second) return mapped.first + addr.getOffset();
    return addr.getOffset();
  }

  // The function at `offset`, created if it is new: under `name`, or a generated name if empty.
  Funcdata *function(uint64_t offset, string name = "") {
    Address addr = address(offset);
    Scope *global = arch->symboltab->getGlobalScope();
    Funcdata *fd = global->queryFunction(addr);
    if (fd != nullptr) return fd;
    if (name.empty()) arch->nameFunction(addr, name);
    image->entries.insert(offset);
    return global->addFunction(addr, name)->getFunction();
  }
};

// Whether a value goes nowhere except through copies and merges into storage that nothing reads
// directly. A read after a call that may have written the storage is not a read of the value.
static bool never_read(const Varnode *vn, set<const Varnode *> &seen) {
  if (!seen.insert(vn).second) return true;
  for (auto it = vn->beginDescend(); it != vn->endDescend(); ++it) {
    const PcodeOp *op = *it;
    switch (op->code()) {
      case CPUI_INDIRECT:
        break;
      case CPUI_COPY:
      case CPUI_CAST:
      case CPUI_MULTIEQUAL:
        if (!never_read(op->getOut(), seen)) return false;
        break;
      default:
        return false;
    }
  }
  return true;
}

// The parameters a function takes on the stack beyond those the engine recovered, as 8-byte
// slots from the first it reads to the last, or none. The System V convention for x86-64 puts a
// structure of more than 16 bytes on the stack whatever registers are free; the engine's rule
// that stack arguments come only after all six integer registers leaves such a structure out,
// reading its fields as `in_stack_...` and dropping it from every call.
static vector<ParameterPieces> stack_aggregate(Funcdata *fd) {
  vector<ParameterPieces> slots;
  AddrSpace *stack = fd->getArch()->getStackSpace();
  const FuncProto &proto = fd->getFuncProto();
  if (stack == nullptr) return slots;
  for (int4 i = 0; i < proto.numParams(); ++i)
    if (proto.getParam(i)->getAddress().getSpace() == stack) return slots;  // it already takes the stack
  const int4 word = 8;  // the return address, and the size of a slot
  intb end = -1;
  for (auto it = fd->beginDef(Varnode::input); it != fd->endDef(Varnode::input); ++it) {
    const Varnode *vn = *it;
    if (vn->getSpace() != stack) continue;
    intb offset = sign_extend((intb)vn->getOffset(), 8 * stack->getAddrSize() - 1);
    if (offset >= word) end = max(end, offset + vn->getSize());
  }
  if (end < 0 || end - word > 16 * word) return slots;
  for (intb at = word; at < end; at += word) {
    ParameterPieces piece;
    piece.addr = Address(stack, (uintb)at);
    piece.type = fd->getArch()->types->getBase(word, TYPE_UNKNOWN);
    piece.flags = 0;
    slots.push_back(piece);
  }
  return slots;
}

// Whether the function's one register parameter exists only because the register is pushed.
// MSVC reserves four bytes of stack with `push ecx`; when the address of that slot is passed on,
// the engine cannot tell that the pushed value is never used, and reports ECX as a parameter.
static bool only_spills_register_param(Funcdata *fd) {
  const FuncProto &proto = fd->getFuncProto();
  // Only where the default convention is the stack-only alternative to the one recovered.
  if (proto.isModelLocked() || proto.getModelName() == fd->getArch()->defaultfp->getName()) return false;
  const ProtoParameter *spilled = nullptr;
  for (int4 i = 0; i < proto.numParams(); ++i) {
    ProtoParameter *param = proto.getParam(i);
    if (param->getAddress().getSpace()->getType() == IPTR_SPACEBASE) continue;
    if (spilled != nullptr) return false;
    spilled = param;
  }
  if (spilled == nullptr) return false;
  const Varnode *vn = fd->findVarnodeInput(spilled->getSize(), spilled->getAddress());
  set<const Varnode *> seen;
  return vn != nullptr && !vn->hasNoDescend() && never_read(vn, seen);
}

// Whether a register parameter exists only because the function stores the register and never
// reads the value: a variadic function saves every argument register so that va_arg can find
// them, and unoptimized code saves them all whether it has that many parameters or not. How many
// of them are parameters cannot be told, so the prototype says too much to pass on to callers.
static bool spills_a_register_param(Funcdata *fd) {
  // 32-bit conventions pass on the stack; the one register that is pushed there is
  // `only_spills_register_param`'s to tell.
  if (fd->getArch()->getDefaultCodeSpace()->getAddrSize() < 8) return false;
  const FuncProto &proto = fd->getFuncProto();
  for (int4 i = 0; i < proto.numParams(); ++i) {
    ProtoParameter *param = proto.getParam(i);
    if (param->getAddress().getSpace()->getType() == IPTR_SPACEBASE) continue;
    const Varnode *vn = fd->findVarnodeInput(param->getSize(), param->getAddress());
    set<const Varnode *> seen;
    if (vn != nullptr && !vn->hasNoDescend() && never_read(vn, seen)) return true;
  }
  return false;
}

// The address a varnode holds, when it is a constant or the address of a global.
static bool constant_address(const Varnode *vn, uint64_t &addr, int depth = 0) {
  if (vn->isConstant()) {
    addr = vn->getOffset();
    return true;
  }
  if (!vn->isWritten() || depth > 3) return false;
  const PcodeOp *def = vn->getDef();
  switch (def->code()) {
    case CPUI_COPY:
    case CPUI_CAST:
      return constant_address(def->getIn(0), addr, depth + 1);
    case CPUI_PTRSUB:
      if (!def->getIn(1)->isConstant()) return false;
      addr = def->getIn(1)->getOffset();
      return true;
    default:
      return false;
  }
}

// What a format takes after it: for each argument, whether it is a floating-point number.
// Empty for text that is no format, and for one whose conversions cannot be read. A printf
// format takes an argument for each `*`, where a scanf format, which `scans` says it is,
// reads and stores nothing for a conversion marked with one.
static vector<bool> format_arguments(const string &format, bool scans) {
  vector<bool> floats;
  for (size_t i = 0; i < format.size(); ++i) {
    if (format[i] != '%') continue;
    size_t j = i + 1;
    if (j < format.size() && format[j] == '%') {
      i = j;
      continue;
    }
    size_t stars = 0;
    while (j < format.size() && strchr("-+ #0'", format[j]) != nullptr) ++j;
    for (; j < format.size() && (isdigit((unsigned char)format[j]) || format[j] == '*' || format[j] == '.'); ++j)
      stars += format[j] == '*';
    // Length: hh h l ll z j t L, and Microsoft's I, I32, I64 and w.
    if (format.compare(j, 3, "I64") == 0 || format.compare(j, 3, "I32") == 0) j += 3;
    while (j < format.size() && strchr("hlzjtLIwq", format[j]) != nullptr) ++j;
    if (j >= format.size()) return {};
    if (scans && format[j] == '[') {
      // A set of characters, which may open with the bracket that would close it.
      j = format.find(']', j + 2);
      if (j == string::npos) return {};
    } else if (strchr("diouxXeEfFgGaAcCsSpn", format[j]) == nullptr) {
      return {};
    }
    if (scans) {
      // Every argument of a scan is a pointer, whatever it points to.
      if (stars == 0) floats.push_back(false);
    } else {
      floats.insert(floats.end(), stars, false);
      floats.push_back(strchr("eEfFgGaA", format[j]) != nullptr);
    }
    i = j;
  }
  return floats;
}

// Gives each call that passes a printf format to a function taking a variable number of
// arguments the arguments its format asks for, where the call was recovered with another
// number. The engine decides what a call passes from the registers and stack around it, and
// leaves out a register that the caller also reads, and takes in one it merely happens to
// have written. The format says how many there are. Returns whether any call was changed,
// which shows once the function is decompiled again.
static bool follow_formats(RdSession *session, Funcdata *fd) {
  /// A format asking for more than this is not believed.
  const size_t most = 12;
  Architecture *arch = session->arch;
  int4 word = arch->getDefaultCodeSpace()->getAddrSize();
  bool changed = false;
  for (int4 i = 0; i < fd->numCalls(); ++i) {
    FuncCallSpecs *call = fd->getCallSpecs(i);
    PcodeOp *op = call->getOp();
    uint64_t callee = call->getEntryAddress().isInvalid() ? ~(uint64_t)0 : call->getEntryAddress().getOffset();
    // Declared with `...`, or seen to save its argument registers as such a function does.
    if (session->format_calls.count({fd->getAddress().getOffset(), op->getAddr().getOffset()}) != 0) continue;
    bool declared = call->isInputLocked() && call->isDotdotdot() && session->kept.count(callee) == 0;
    if (!declared && session->saves_arguments.count(callee) == 0) continue;
    int4 passed = op->numInput() - 1;
    for (int4 at = 1; at <= passed; ++at) {
      uint64_t addr;
      if (!constant_address(op->getIn(at), addr)) continue;
      uint1 bytes[256];
      try {
        session->image->loadFill(bytes, sizeof(bytes), session->address(addr));
      } catch (LowlevelError &) {
        continue;
      }
      const uint1 *end = (const uint1 *)memchr(bytes, 0, sizeof(bytes));
      if (end == nullptr) continue;
      vector<bool> floats = format_arguments(string((const char *)bytes, end - bytes), call->getName().find("scanf") != string::npos);
      if (floats.empty()) continue;
      // The first argument that is a format settles it, whatever the later ones are. A
      // floating-point argument travels in a register of its own, and a call of unknown
      // prototype may list it before the format: with one in play, where the format stands
      // does not say how many parameters come before it, and the call is left as it is.
      if (at + floats.size() == (size_t)passed || floats.size() > most || count(floats.begin(), floats.end(), true) > 0) break;
      size_t fixed = at - 1;
      PrototypePieces pieces;
      pieces.model = arch->getModel(call->getModelName());
      pieces.name = call->getName();
      pieces.outtype = call->getOutputType();
      // As a function of exactly these parameters: marked as taking more, the call would
      // again collect whatever else the registers around it hold.
      pieces.firstVarArgSlot = -1;
      pieces.intypes.assign(fixed + 1, arch->types->getBase(word, TYPE_UNKNOWN));
      for (bool is_float : floats)
        pieces.intypes.push_back(is_float ? arch->types->getBase(8, TYPE_FLOAT) : arch->types->getBase(word, TYPE_UNKNOWN));
      pieces.innames.assign(pieces.intypes.size(), "");
      FuncProto *proto = new FuncProto();
      proto->setInternal(pieces.model, arch->types->getTypeVoid());
      proto->setPieces(pieces);
      proto->setOutputLock(false);
      proto->setNoReturn(call->isNoReturn());
      fd->getOverride().insertProtoOverride(op->getAddr(), proto);
      changed = true;
      break;
    }
  }
  return changed;
}

// Whether the function reads a register that its recovered prototype does not account for. Such
// a prototype is incomplete, and Ghidra's parameter analysis does not pass it on to callers either.
static bool reads_unexplained_register(Funcdata *fd) {
  ScopeLocal *scope = fd->getScopeLocal();
  for (MapIterator it = scope->begin(); it != scope->end(); ++it) {
    const SymbolEntry *entry = *it;
    const string &name = entry->getSymbol()->getName();
    if (name.compare(0, 3, "in_") != 0 || name == "in_FS_OFFSET") continue;
    if (entry->isDynamic()) continue;
    const Address &addr = static_cast<const MapEntry *>(entry)->getAddr();
    if (addr.getSpace()->getType() != IPTR_SPACEBASE) return true;
  }
  return false;
}

// One operand of raw p-code, written the way Ghidra's listing shows it.
static void print_operand(ostream &s, const Translate *translate, const VarnodeData &vn) {
  if (vn.space->getType() == IPTR_CONSTANT) {
    s << "0x" << hex << vn.offset << dec;
    return;
  }
  string reg = translate->getRegisterName(vn.space, vn.offset, vn.size);
  if (!reg.empty()) {
    s << reg;
    return;
  }
  if (vn.space->getType() == IPTR_INTERNAL)
    s << "$U" << hex << vn.offset << dec;
  else
    s << vn.space->getName() << "[0x" << hex << vn.offset << dec << "]";
  s << ":" << vn.size;
}

class ListingAssembly : public AssemblyEmit {
 public:
  string text;
  void dump(const Address &, const string &mnem, const string &body) override {
    text = body.empty() ? mnem : mnem + " " + body;
  }
};

class ListingPcode : public PcodeEmit {
  const Translate *translate;
  ostream &out;

 public:
  ListingPcode(const Translate *t, ostream &o) : translate(t), out(o) {}
  void dump(const Address &, OpCode opc, VarnodeData *outvar, VarnodeData *vars, int4 isize) override {
    out << "\t";
    if (outvar != nullptr) {
      print_operand(out, translate, *outvar);
      out << " = ";
    }
    out << get_opname(opc);
    for (int4 i = 0; i < isize; ++i) {
      out << (i == 0 ? " " : ", ");
      // The first input of a load or store names the address space, not a value.
      if (i == 0 && (opc == CPUI_LOAD || opc == CPUI_STORE))
        out << ((AddrSpace *)(uintp)vars[i].offset)->getName();
      else
        print_operand(out, translate, vars[i]);
    }
    out << "\n";
  }
};

// Prints C as the engine's plain emitter does, and notes for each line the address of the first
// operation a token on it was printed for: the instruction that line of C came from.
class EmitAddressed : public EmitNoMarkup {
  ostringstream line;  // the line being printed, which the base class writes to
  ostream *out = nullptr;
  vector<pair<uint8, string>> lines;  // finished lines, each with its address or ~0 for none
  uint8 at = ~(uint8)0;

  void note(const PcodeOp *op) {
    if (op != nullptr && at == ~(uint8)0) at = op->getAddr().getOffset();
  }
  void finish() {
    lines.push_back({at, line.str()});
    line.str("");
    at = ~(uint8)0;
  }

 public:
  EmitAddressed() { EmitNoMarkup::setOutputStream(&line); }
  virtual void setOutputStream(ostream *t) { out = t; }
  virtual ostream *getOutputStream(void) const { return out; }
  virtual void tagLine(void) {
    finish();
    EmitNoMarkup::tagLine();
  }
  virtual void tagLine(int4 indent) {
    finish();
    EmitNoMarkup::tagLine(indent);
  }
  virtual void tagVariable(const string &name, syntax_highlight hl, const Varnode *vn, const PcodeOp *op) {
    note(op);
    EmitNoMarkup::tagVariable(name, hl, vn, op);
  }
  virtual void tagOp(const string &name, syntax_highlight hl, const PcodeOp *op) {
    note(op);
    EmitNoMarkup::tagOp(name, hl, op);
  }
  virtual void tagFuncName(const string &name, syntax_highlight hl, const Funcdata *fd, const PcodeOp *op) {
    note(op);
    EmitNoMarkup::tagFuncName(name, hl, fd, op);
  }
  // Writes the lines out, each after its address in a column as wide as the longest.
  void flush() {
    finish();
    size_t width = 0;
    for (const auto &entry : lines) {
      if (entry.first == ~(uint8)0) continue;
      ostringstream digits;
      digits << hex << entry.first;
      width = max(width, digits.str().size());
    }
    for (const auto &entry : lines) {
      // The base class starts each line with a line feed, which stays in front of the column.
      size_t start = entry.second.find_first_not_of('\n');
      if (start == string::npos) start = entry.second.size();
      // An empty line stays empty.
      if (start == entry.second.size()) {
        *out << entry.second;
        continue;
      }
      ostringstream digits;
      if (entry.first != ~(uint8)0) digits << hex << entry.first;
      *out << entry.second.substr(0, start) << string(width - digits.str().size(), ' ') << digits.str() << "| "
           << entry.second.substr(start);
    }
    lines.clear();
  }
};

// Whether a symbol of a function's own scope is one of its variables, not a label or a constant.
static bool is_variable(const Symbol *symbol) {
  return symbol->getCategory() <= Symbol::function_parameter &&
         dynamic_cast<const LabSymbol *>(symbol) == nullptr &&
         dynamic_cast<const FunctionSymbol *>(symbol) == nullptr;
}

// Where a variable lives, in a form that names the same variable when the function is
// decompiled again: `<space>:<offset>:<size>`, and for a variable that holds its storage only
// from one instruction on, `@` and that instruction's address. All numbers are hexadecimal.
static string local_place(const MapEntry *entry) {
  ostringstream s;
  s << entry->getAddr().getSpace()->getName() << ':' << hex << entry->getAddr().getOffset() << ':'
    << entry->getSize();
  Address use = entry->getFirstUseAddress();
  if (!use.isInvalid()) s << '@' << use.getOffset();
  return s.str();
}

// The variable at a place written by `local_place`, or null if the function has none there now.
static Symbol *local_at(Funcdata *fd, const string &place) {
  char space_name[64];
  unsigned long long offset = 0, use_offset = 0;
  unsigned size = 0;
  int fields = sscanf(place.c_str(), "%63[^:]:%llx:%x@%llx", space_name, &offset, &size, &use_offset);
  if (fields < 3) return nullptr;
  AddrSpace *space = fd->getArch()->getSpaceByName(space_name);
  if (space == nullptr) return nullptr;
  Address addr(space, offset);
  Address use = fields == 4 ? Address(fd->getArch()->getDefaultCodeSpace(), use_offset) : Address();
  ScopeLocal *scope = fd->getScopeLocal();
  MapEntry *entry = scope->findAddr(addr, use);
  if (entry != nullptr && entry->getSize() == (int4)size) return entry->getSymbol();
  // The variable may be recorded from another of its assignments this time.
  Varnode *vn = fields == 4 ? fd->findVarnodeWritten(size, addr, use) : nullptr;
  if (vn == nullptr || vn->getHigh()->getSymbolOffset() > 0) return nullptr;
  Symbol *symbol = vn->getHigh()->getSymbol();
  return symbol != nullptr && symbol->getScope() == scope ? symbol : nullptr;
}

// Gives the variables of a decompiled function the names rd_name_local recorded, then lists
// every variable under the name it now has.
static string name_locals(RdSession *session, uint64_t addr, Funcdata *fd) {
  ScopeLocal *scope = fd->getScopeLocal();
  auto named = session->local_names.find(addr);
  if (named != session->local_names.end()) {
    for (const pair<string, string> &local : named->second) {
      Symbol *symbol = local_at(fd, local.first);
      if (symbol != nullptr && is_variable(symbol)) scope->renameSymbol(symbol, local.second);
    }
  }
  ostringstream out;
  for (MapIterator it = scope->begin(); it != scope->end(); ++it) {
    const MapEntry *entry = *it;
    const Symbol *symbol = entry->getSymbol();
    if (is_variable(symbol) && symbol->getFirstWholeMap() == entry)
      out << symbol->getName() << '\t' << local_place(entry) << '\n';
  }
  return out.str();
}

// The name of a data type as C spells it. getName() is empty for pointers and arrays.
static string type_name(const Datatype *type) {
  ostringstream s;
  type->printRaw(s);
  return s.str();
}

// The decompiler's name for an operation. The two that only exist after analysis share their
// numbers with operations of the processor specs, whose names get_opname gives.
static const char *flow_opname(OpCode code) {
  if (code == CPUI_MULTIEQUAL) return "MULTIEQUAL";
  if (code == CPUI_INDIRECT) return "INDIRECT";
  return get_opname(code);
}

// Writes the function's simplified p-code as lines of tab-separated fields:
//   B <index> <start> <stop> <successor indices, comma-separated>
//   V <id> <size> <kind> <text>     kind: const, param, global, local or temp
//   O <address> <block> <opcode> <output id or -> <input ids, comma-separated> <callee address and name, or ->
// A value is one SSA varnode, defined by at most one operation. A parameter's text is its
// position and name; a constant's is its value; a global's is its address.
static void dump_flow(const RdSession *session, Funcdata *fd, ostream &out) {
  const BlockGraph &blocks = fd->getBasicBlocks();
  out << hex;
  for (int4 i = 0; i < blocks.getSize(); ++i) {
    const FlowBlock *block = blocks.getBlock(i);
    out << "B\t" << i << "\t" << block->getStart().getOffset() << "\t" << block->getStop().getOffset() << "\t";
    for (int4 j = 0; j < block->sizeOut(); ++j) out << (j == 0 ? "" : ",") << block->getOut(j)->getIndex();
    out << "\n";
  }
  set<uint4> seen;
  auto value = [&](const Varnode *vn) {
    uint4 id = vn->getCreateIndex();
    if (!seen.insert(id).second) return id;
    out << "V\t" << id << "\t" << vn->getSize() << "\t";
    Symbol *symbol = nullptr;
    try {
      symbol = vn->getHigh()->getSymbol();
    } catch (const LowlevelError &) {
    }
    if (vn->isConstant())
      out << "const\t" << vn->getOffset();
    else if (symbol != nullptr && symbol->getCategory() == Symbol::function_parameter)
      out << "param\t" << symbol->getCategoryIndex() << " " << symbol->getName();
    else if (vn->isPersist() && vn->getSpace()->getType() == IPTR_PROCESSOR)
      out << "global\t" << session->offset(vn->getAddr()) << (symbol != nullptr ? " " + symbol->getName() : "");
    else if (symbol != nullptr)
      out << "local\t" << symbol->getName();
    else {
      out << "temp\t";
      vn->printRawNoMarkup(out);
    }
    out << "\n";
    return id;
  };
  for (int4 index = 0; index < blocks.getSize(); ++index) {
    const BlockBasic *block = static_cast<const BlockBasic *>(blocks.getBlock(index));
    for (auto it = block->beginOp(); it != block->endOp(); ++it) {
    const PcodeOp *op = *it;
    uint4 output = op->getOut() != nullptr ? value(op->getOut()) : 0;
    vector<uint4> inputs;
    // The first input of a call is its target, of a load or store the address space, and of a
    // return the place the return address was read from: none of them is a value passed on.
    bool skip_first = op->isCall() || op->code() == CPUI_LOAD || op->code() == CPUI_STORE || op->code() == CPUI_RETURN;
    for (int4 i = skip_first ? 1 : 0; i < op->numInput(); ++i)
      if (!op->getIn(i)->isAnnotation()) inputs.push_back(value(op->getIn(i)));
    out << "O\t" << op->getAddr().getOffset() << "\t" << index << "\t" << flow_opname(op->code()) << "\t";
    if (op->getOut() != nullptr) out << output; else out << "-";
    out << "\t";
    for (size_t i = 0; i < inputs.size(); ++i) out << (i == 0 ? "" : ",") << inputs[i];
    out << "\t";
    FuncCallSpecs *call = op->code() == CPUI_CALL ? fd->getCallSpecs(op) : nullptr;
    if (call != nullptr && !call->getEntryAddress().isInvalid())
      out << call->getEntryAddress().getOffset() << " " << call->getName();
    else
      out << "-";
    out << "\n";
    }
  }
}

// The engine allocates and frees small objects by the million: tree nodes for every varnode and
// operation. These replace the C++ allocation functions for the whole program with mimalloc,
// which the Rust side links.
extern "C" {
void *mi_malloc(size_t size);
void mi_free(void *block);
}

void *operator new(size_t size) {
  void *block = mi_malloc(size);
  if (block == nullptr) throw std::bad_alloc();
  return block;
}
void *operator new[](size_t size) { return operator new(size); }
void *operator new(size_t size, const std::nothrow_t &) noexcept { return mi_malloc(size); }
void *operator new[](size_t size, const std::nothrow_t &) noexcept { return mi_malloc(size); }
void operator delete(void *block) noexcept { mi_free(block); }
void operator delete[](void *block) noexcept { mi_free(block); }
void operator delete(void *block, size_t) noexcept { mi_free(block); }
void operator delete[](void *block, size_t) noexcept { mi_free(block); }

// The engine's XML parser keeps its state in globals. Sessions are created under this lock,
// since that parses the language files, and so is every other document parsed.
static mutex xml_lock;

extern "C" {

static void recover_structs(RdSession *session, Funcdata &fd);

// `spec_dir` holds the .ldefs/.pspec/.cspec/.sla files. The first session fixes it for the
// whole process, because the engine caches its language list in static storage.
RdSession *rd_session_new(const char *spec_dir, const char *language, const RdSection *sections,
                          size_t count, char *err, size_t errlen) {
  // Spec loading goes through bison parsers with global state and fills static tables.
  static bool started = false;
  lock_guard<mutex> guard(xml_lock);

  RdSession *session = new RdSession;
  bool ok = guarded(err, errlen, [&] {
    if (!started) {
      AttributeId::initialize();
      ElementId::initialize();
      CapabilityPoint::initializeAll();
      ArchitectureCapability::sortCapabilities();
      SleighArchitecture::specpaths.addDir2Path(spec_dir);
      started = true;
    }
    session->image = new SectionImage(language, sections, count);
    session->arch = new SectionArchitecture(session->image, &session->messages);
    session->arch->init(session->store);
    session->arch->start_types = [session](Funcdata &fd) { recover_structs(session, fd); };
    // Use the contents of read-only memory as constants, as Ghidra does by default. This is
    // what turns a call through a pointer table into a call to a known function.
    session->arch->readonlypropagate = true;
    // Every cut at another function's entry counts as a bad instruction, and a function with
    // several conditional tail calls has several. The engine's default gives up at four.
    session->arch->max_baddata = 32;
    // The top megabyte of the address space, which no image occupies, or of a space narrower
    // than 24 bits its top sixteenth.
    uintb highest = session->arch->getDefaultCodeSpace()->getHighest();
    session->next_external = highest & ~min<uintb>(0xfffff, highest >> 4);
  });
  if (session->arch != nullptr) session->translator = session->arch->translator();
  if (ok) return session;
  delete session;
  return nullptr;
}

void rd_session_free(RdSession *session) { delete session; }

// Says that recore's addresses from `base` on are those of the engine's address space `name`,
// from its first. Every address handed over afterwards is read so: without this each one is an
// address of code.
int rd_map_space(RdSession *session, uint64_t base, const char *name, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    AddrSpace *space = session->arch->getSpaceByName(name);
    if (space == nullptr) throw LowlevelError(string("no address space named ") + name);
    session->spaces.push_back({base, space});
  });
}

// Says that the byte of memory at `addr` belongs to the function that runs, as a register does,
// and is no global variable: what a function keeps there, a called function leaves there.
int rd_register_at(RdSession *session, uint64_t addr, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Address at = session->address(addr);
    Database *symbols = session->arch->symboltab;
    symbols->removeRange(symbols->getGlobalScope(), at.getSpace(), at.getOffset(), at.getOffset());
    VarnodeData byte = {at.getSpace(), at.getOffset(), 1};
    session->arch->defaultfp->addEffect(EffectRecord(byte, EffectRecord::unaffected));
    // And in the convention that carries a function's own list of registers.
    ProtoModel *carrier = session->arch->getModel("__registers");
    if (carrier != nullptr) carrier->addEffect(EffectRecord(byte, EffectRecord::unaffected));
  });
}

// Says that the `len` bytes of code at `addr` are those at `target`: reading them reads those,
// and a jump or call into them goes to the code at `target`.
void rd_mirror(RdSession *session, uint64_t addr, uint64_t len, uint64_t target) {
  vector<SectionImage::Mirror> &mirrors = session->image->mirrors;
  mirrors.push_back({addr, addr + len, target});
  sort(mirrors.begin(), mirrors.end(),
       [](const SectionImage::Mirror &a, const SectionImage::Mirror &b) { return a.start < b.start; });
}

// Says that a jump or call to `from` goes to `to`: the code at `from` only passes control on.
void rd_redirect(RdSession *session, uint64_t from, uint64_t to) { session->image->redirects[from] = to; }

// Says that the call at `call` does not come back: the routine it calls jumps on, to one of the
// places rd_override_jump_table gives for `call`, which it picks by the register `selector`.
// With `assist`, the places are not given: the jump assist of that name in the compiler spec
// finds them and the value of each case, from `count` cases listed at `list`.
int rd_call_switches(RdSession *session, uint64_t call, const char *selector, const char *assist, uint64_t count, uint64_t list, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    SectionImage::SwitchCall jump = {arch->translate->getRegister(selector), assist != nullptr, 0, count, list};
    if (assist != nullptr) {
      UserPcodeOp *op = arch->userops.getOp(assist);
      if (op == nullptr || op->getType() != UserPcodeOp::jumpassist) throw LowlevelError(string("no jump assist ") + assist);
      jump.assist = op->getIndex();
    }
    session->image->switch_calls[call] = jump;
  });
}

// Says that code which runs from the end of one function into the start of the next is meant
// to: the first function then ends in a call to the second and a return. Without this such
// flow is cut off, as what follows a call that was not known to never return.
void rd_functions_run_on(RdSession *session, int on) { session->image->functions_run_on = on != 0; }

// Says that the convention returns a result in the register it passes the first argument in.
void rd_result_in_first_argument(RdSession *session, int shared) { session->result_in_first_argument = shared != 0; }

// Says that `len` bytes of data follow the call at `call`, and that it returns past them.
void rd_call_skips(RdSession *session, uint64_t call, uint64_t len) { session->image->data_after[call] = (int4)len; }

// Declares a function start. Calls to it become calls to a known symbol, and with `noreturn`
// flow stops after every call to it. A non-empty `name` is used if the function is new; the
// engine keeps a function's name in more places than a rename reaches.
int rd_add_function(RdSession *session, uint64_t addr, const char *name, int noreturn, char *err,
                    size_t errlen) {
  return guarded(err, errlen, [&] {
    Funcdata *fd = session->function(addr, name);
    if (noreturn) fd->getFuncProto().setNoReturn(true);
  });
}

// Declares that the pointer stored at `slot` (a GOT entry) refers to the imported function
// `name`. An indirect call through the slot then becomes a direct call to `name`; if it is
// `noreturn` the engine restarts flow analysis with that call ending the path.
int rd_add_import(RdSession *session, uint64_t slot, const char *name, int noreturn, char *err,
                  size_t errlen) {
  return guarded(err, errlen, [&] {
    Scope *global = session->arch->symboltab->getGlobalScope();
    auto found = session->externals.find(name);
    if (found == session->externals.end()) {
      found = session->externals.emplace(name, session->next_external).first;
      session->next_external += 16;
      Funcdata *fd = global->addFunction(session->address(found->second), name)->getFunction();
      fd->setNoCode(true);
      if (noreturn) fd->getFuncProto().setNoReturn(true);
    }
    global->addExternalRef(session->address(slot), session->address(found->second), "");
    session->slots[slot] = found->second;
  });
}

// Declares that the code at `addr` only forwards to the import behind `slot`: a PLT stub or an
// import thunk. It gets the import's name and, if one was declared, its prototype, so calls
// to it read like calls to the import.
int rd_alias_import(RdSession *session, uint64_t addr, uint64_t slot, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    auto found = session->slots.find(slot);
    if (found == session->slots.end()) throw LowlevelError("no import declared at this slot");
    Funcdata *import = session->function(found->second);
    Funcdata *alias = session->function(addr, import->getName());
    const FuncProto &proto = import->getFuncProto();
    if (proto.isInputLocked()) {
      PrototypePieces pieces;
      proto.getPieces(pieces);
      pieces.name = alias->getName();
      alias->getFuncProto().setPieces(pieces);
    }
    if (proto.isNoReturn()) alias->getFuncProto().setNoReturn(true);
  });
}

// Tells the engine up front that the indirect call at `call` inside `function` goes through the
// import slot `slot`. The engine finds this out by itself, but only after data-flow analysis,
// and for a non-returning callee it then throws the work away and restarts the function.
int rd_override_import_call(RdSession *session, uint64_t function, uint64_t call, uint64_t slot,
                            char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    auto found = session->slots.find(slot);
    if (found == session->slots.end()) throw LowlevelError("no import declared at this slot");
    session->function(function)->getOverride().insertDeindirect(session->address(call),
                                                                session->address(found->second));
  });
}

// Fixes the destinations of the indirect jump at `jump` inside `function`, so the decompiler
// does not try to recover the table itself. Survives repeated decompilation.
int rd_override_jump_table(RdSession *session, uint64_t function, uint64_t jump,
                           const uint64_t *targets, size_t count, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Funcdata *fd = session->function(function);
    vector<Address> table;
    for (size_t i = 0; i < count; ++i) table.push_back(session->address(targets[i]));
    // No normalized switch variable is supplied (invalid address, hash 0), so the output
    // labels cases by table position starting at 0.
    fd->installJumpTable(session->address(jump))->setOverride(table, Address(), 0, 0);
  });
}

// Lets flow from `function` pass through the entry of the declared function `entry`, which lies
// inside one of `function`'s own ranges.
int rd_allow_entry(RdSession *session, uint64_t function, uint64_t entry, char *err, size_t errlen) {
  return guarded(err, errlen, [&] { session->image->allowed.insert({function, entry}); });
}

// Tells the engine up front that the indirect call at `call` inside `function` reaches the
// local function `target`, as when it goes through a relocated pointer slot.
int rd_override_call(RdSession *session, uint64_t function, uint64_t call, uint64_t target, char *err,
                     size_t errlen) {
  return guarded(err, errlen, [&] {
    session->function(function)->getOverride().insertDeindirect(session->address(call),
                                                                session->address(target));
  });
}

// Parses one C declaration with the engine's own parser. `extern` declarations set the prototype
// of the function of that name, which must exist; `typedef` and struct declarations add types.
int rd_declare(RdSession *session, const char *declaration, char *err, size_t errlen) {
  static mutex parser_lock;  // the bison parser keeps its state in globals
  lock_guard<mutex> guard(parser_lock);
  return guarded(err, errlen, [&] {
    istringstream text(declaration);
    parse_C(session->arch, text);
  });
}

// Declares a NUL-terminated string of `count` characters (terminator included) at `addr`, as a
// global of type char[count], or wchar2[count] if `wide`. A pointer to read-only data typed this
// way is printed as a string literal.
int rd_add_string(RdSession *session, uint64_t addr, const char *name, size_t count, int wide,
                  char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    Scope *global = arch->symboltab->getGlobalScope();
    Address where = session->address(addr);
    if (global->findAddr(where, Address()) != nullptr) return;  // already declared
    Datatype *element = arch->types->getTypeChar(wide ? 2 : 1);
    global->addSymbol(name, arch->types->getTypeArray(count, element), where, Address());
  });
}

// Declares the function at `addr` as a stub that sends one Objective-C message: it takes the
// receiver and `count - 1` arguments, each as wide as a pointer and of unknown type. What it
// returns is left for each call to show. A selector's colons count its arguments.
int rd_set_param_count(RdSession *session, uint64_t addr, size_t count, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    Funcdata *fd = session->function(addr);
    int4 size = arch->getDefaultCodeSpace()->getAddrSize();
    PrototypePieces pieces;
    pieces.model = arch->defaultfp;
    pieces.name = fd->getName();
    pieces.outtype = arch->types->getBase(size, TYPE_UNKNOWN);
    pieces.firstVarArgSlot = -1;
    // The convention's second register carries the selector, which the function at `addr`
    // loads itself. Laying out one parameter more and dropping the second leaves the
    // arguments in the registers the caller really uses.
    for (size_t i = 0; i < count + 1; ++i) {
      pieces.intypes.push_back(arch->types->getBase(size, TYPE_UNKNOWN));
      pieces.innames.push_back(i == 0 ? "self" : i == 1 ? "_cmd" : "arg" + to_string(i - 1));
    }
    fd->getFuncProto().setPieces(pieces);
    fd->getFuncProto().removeParam(1);
    fd->getFuncProto().setOutputLock(false);
  });
}

// Where a value is: a register by name, several joined with `:`, most significant first, or
// `<space>:<offset>/<size>` as a parameter's storage is reported, with its size.
static ParameterPieces stored_in(Architecture *arch, const string &place) {
  ParameterPieces piece;
  int4 size = 0;
  size_t sized = place.find('/');
  if (sized != string::npos) {
    size_t colon = place.find(':');
    AddrSpace *space = arch->getSpaceByName(place.substr(0, colon));
    if (colon == string::npos || space == nullptr) throw LowlevelError("no such storage: " + place);
    piece.addr = Address(space, stoull(place.substr(colon + 1, sized - colon - 1), nullptr, 16));
    size = stoi(place.substr(sized + 1));
  } else {
    vector<VarnodeData> registers;
    istringstream names(place);
    for (string name; getline(names, name, ':');) {
      registers.push_back(arch->translate->getRegister(name));
      size += registers.back().size;
    }
    piece.addr = registers.size() == 1 ? registers[0].getAddr() : arch->findAddJoin(registers, 0)->getUnified().getAddr();
  }
  piece.type = arch->types->getBase(size, TYPE_UNKNOWN);
  piece.flags = 0;
  return piece;
}

// Says where the function at `addr` takes its arguments and leaves its result, for one that
// keeps to no calling convention: `storage` is `ACC(R3:R2:R1,DPTR)` for a result in ACC and
// two arguments, `void(...)` for no result, and `?(...)` to leave the result to be found.
int rd_set_storage(RdSession *session, uint64_t addr, const char *storage, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    string text(storage);
    size_t open = text.find('('), close = text.rfind(')');
    if (open == string::npos || close == string::npos) throw LowlevelError("storage is `result(arguments)`: " + text);
    FuncProto &proto = session->function(addr)->getFuncProto();
    string result = text.substr(0, open);
    if (result != "void" && result != "?") proto.setOutput(stored_in(arch, result));
    istringstream arguments(text.substr(open + 1, close - open - 1));
    proto.clearInput();
    int4 count = 0;
    for (string place; getline(arguments, place, ',');) proto.setParam(count++, "", stored_in(arch, place));
    proto.setInputLock(true);
    // With `?` what is known of the result stays as it is.
    if (result != "?") proto.setOutputLock(true);
    proto.setModelLock(true);
  });
}

// Says that the function at `addr` leaves the registers named in `kept`, separated by commas,
// as they were, whatever the calling convention says a call does to them: a value one of them
// holds before a call to the function is the value it holds after. To be said before anything
// else about the function's prototype, which this sets afresh: the engine takes what a single
// function does to registers only as part of a stored prototype. R0 to R7 are listed in runs,
// the ones left alone and the ones a call changes, so that two or four of them read as one
// value have one answer where they are all alike.
int rd_keep_registers(RdSession *session, uint64_t addr, const char *kept, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    const VarnodeData first = arch->translate->getRegister("R0");
    vector<VarnodeData> unaffected;
    bool bank[8] = {};
    istringstream names(kept);
    for (string name; getline(names, name, ',');) {
      VarnodeData reg = arch->translate->getRegister(name);
      if (reg.space == first.space && reg.offset - first.offset < 8 && reg.size == 1)
        bank[reg.offset - first.offset] = true;
      else
        unaffected.push_back(reg);
    }
    vector<VarnodeData> killed;
    for (int4 start = 0; start < 8;) {
      int4 end = start + 1;
      while (end < 8 && bank[end] == bank[start]) ++end;
      (bank[start] ? unaffected : killed).push_back({first.space, first.offset + start, (uint4)(end - start)});
      start = end;
    }
    auto list = [](ostream &xml, const char *tag, const vector<VarnodeData> &ranges) {
      xml << "<" << tag << ">";
      for (const VarnodeData &range : ranges)
        xml << "<varnode space=\"" << range.space->getName() << "\" offset=\"0x" << hex << range.offset << "\" size=\"" << dec << range.size << "\"/>";
      xml << "</" << tag << ">";
    };
    ostringstream xml;
    xml << "<prototype model=\"__registers\"><returnsym><addr/><void/></returnsym>";
    list(xml, "unaffected", unaffected);
    list(xml, "killedbycall", killed);
    xml << "</prototype>";
    unique_ptr<Document> document;
    {
      lock_guard<mutex> guard(xml_lock);
      istringstream text(xml.str());
      document.reset(xml_tree(text));
    }
    XmlDecode decoder(arch, document->getRoot());
    session->function(addr)->getFuncProto().decode(decoder, arch);
    // The convention that carries the list is no part of the function's declaration.
    arch->getModel("__registers")->setPrintInDecl(false);
    session->kept_registers[addr] = unaffected;
  });
}

// Says what a call to the function at `addr` does to the registers rd_keep_registers named for
// it: leaves them as they were, or with `as_convention` what the calling convention says. The
// second is for while the function itself is decompiled: a register it only reads is then one
// it is passed a value in, and no register its caller keeps a value in across the call.
static void set_kept_registers(RdSession *session, uint64_t addr, bool as_convention) {
  auto kept = session->kept_registers.find(addr);
  if (kept == session->kept_registers.end()) return;
  const FuncProto &proto = session->function(addr)->getFuncProto();
  for (auto effect = proto.effectBegin(); effect != proto.effectEnd(); ++effect) {
    for (const VarnodeData &reg : kept->second) {
      if (effect->getAddress() != reg.getAddr() || effect->getSize() != (int4)reg.size) continue;
      uint4 type = as_convention ? (uint4)EffectRecord::killedbycall : (uint4)EffectRecord::unaffected;
      // The engine has no call that changes one record of a prototype's list.
      const_cast<EffectRecord &>(*effect) = EffectRecord(reg, type);
    }
  }
}

// Says that the function at `function` is read as part of `caller` wherever that one calls it:
// its instructions stand in place of the call. To be said for every function that calls it.
int rd_inline(RdSession *session, uint64_t caller, uint64_t function, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    session->function(function)->getFuncProto().setInline(true);
    session->image->allowed.insert({caller, function});
  });
}

// Says that the function at `addr` returns nothing, whatever its registers hold when it does.
int rd_returns_nothing(RdSession *session, uint64_t addr, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    FuncProto &proto = session->function(addr)->getFuncProto();
    // Locking the output locks the calling convention with it, which is still to be recovered.
    bool model_locked = proto.isModelLocked();
    proto.setOutputLock(true);
    proto.setModelLock(model_locked);
  });
}

// Replaces every call to the function at `addr` with the p-code of the compiler spec's call
// fixup `fixup`. Compiler helpers such as the stack-cookie check and `_alloca_probe` break the
// calling convention, and their fixup says what they really do to the caller.
int rd_set_call_fixup(RdSession *session, uint64_t addr, const char *fixup, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    int4 id = session->arch->pcodeinjectlib->getPayloadId(InjectPayload::CALLFIXUP_TYPE, fixup);
    if (id < 0) throw LowlevelError(string("no call fixup named ") + fixup);
    session->function(addr)->getFuncProto().setInjectId(id);
  });
}

// Declares a table of `count` code pointers at `addr`, such as a vtable, as a global named
// `name`. Its address then prints as the name, and reads through it resolve to functions.
int rd_add_pointer_table(RdSession *session, uint64_t addr, const char *name, size_t count,
                         char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    Scope *global = arch->symboltab->getGlobalScope();
    Address where = session->address(addr);
    if (global->findAddr(where, Address()) != nullptr) return;  // already declared
    AddrSpace *space = arch->getDefaultCodeSpace();
    Datatype *pointer = arch->types->getTypePointer(space->getAddrSize(), arch->types->getTypeCode(), space->getWordSize());
    global->addSymbol(name, arch->types->getTypeArray(count, pointer), where, Address());
  });
}

// Marks the jump at `jump` inside `function` as a tail call: a call followed by a return.
// Without this the engine follows the jump and decompiles the target's body as part of
// `function`. Only unconditional jumps can be overridden.
int rd_override_tail_call(RdSession *session, uint64_t function, uint64_t jump, char *err,
                          size_t errlen) {
  return guarded(err, errlen, [&] {
    session->function(function)->getOverride().insertFlowOverride(session->address(jump),
                                                                  "callreturn");
  });
}

// Marks the branch through a register at `jump` inside `function` as a return, which the engine
// cannot tell from the register alone when the code popped the return address into it.
int rd_override_return(RdSession *session, uint64_t function, uint64_t jump, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    session->function(function)->getOverride().insertFlowOverride(session->address(jump), "return");
  });
}

// Declares that the function at `function` returns what the function at `callee` returns, as it
// does when it ends by jumping there: the engine sees a call followed by a return and does not
// connect the two. `callee` must have been decompiled by this session, or be an import with a
// declared prototype if `import_slot` is set, in which case `callee` is the slot. Answers 1 if
// the callee returns a value, which `function` then returns too, and 0 if it does not.
int rd_returns_like(RdSession *session, uint64_t function, uint64_t callee, int import_slot, char *err,
                    size_t errlen) {
  bool returns = false;
  bool ok = guarded(err, errlen, [&] {
    ParameterPieces piece;
    if (import_slot) {
      auto found = session->slots.find(callee);
      if (found == session->slots.end()) return;
      const FuncProto &proto = session->function(found->second)->getFuncProto();
      if (!proto.isOutputLocked() || proto.getOutputType()->getMetatype() == TYPE_VOID) return;
      piece.addr = proto.getOutput()->getAddress();
      piece.type = proto.getOutputType();
      piece.flags = 0;
    } else {
      auto found = session->outputs.find(callee);
      if (found == session->outputs.end()) return;
      // A call fixup stands in for the callee, and what the function returns shows in that.
      if (session->function(callee)->getFuncProto().getInjectId() >= 0) return;
      piece = found->second;
    }
    Funcdata *fd = session->function(function);
    if (fd->getFuncProto().isOutputLocked()) return;  // the caller or an edit has said what it returns
    bool model_locked = fd->getFuncProto().isModelLocked();
    fd->getFuncProto().setOutput(piece);
    fd->getFuncProto().setOutputLock(true);
    // Locking the output locks the calling convention with it, which is still to be recovered.
    fd->getFuncProto().setModelLock(model_locked);
    session->returns_like.insert(function);
    returns = true;
  });
  return ok && returns;
}

// With `keep` set, the parameters recovered by each successful rd_decompile are locked into the
// function's symbol, so that later decompilations of its callers pass at least those parameters.
void rd_keep_prototypes(RdSession *session, int keep) { session->keep_prototypes = keep != 0; }

// Says that the convention puts a large structure on the stack whatever registers are free, as
// x86-64 System V does: stack slots a function reads beyond its parameters become parameters.
void rd_stack_aggregates(RdSession *session, int on) { session->stack_aggregates = on != 0; }

// Puts a note on an instruction of `function`. The C of the function prints it as a comment
// where that instruction's code is, if the instruction has any left after simplification.
int rd_add_comment(RdSession *session, uint64_t function, uint64_t addr, const char *text, char *err,
                   size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    arch->commentdb->addComment(Comment::user2, session->address(function), session->address(addr), text);
    arch->print->setInstructionComment(arch->print->getInstructionComment() | Comment::user2);
  });
}

// Drops the comments rd_add_comment entered for `function`.
void rd_forget_comments(RdSession *session, uint64_t function) {
  session->arch->commentdb->clearType(session->address(function), Comment::user2);
}

// Says that the function at `addr` takes a format and a variable number of arguments for it:
// a call that passes it a printf format then gets the arguments the format asks for.
void rd_takes_variable_arguments(RdSession *session, uint64_t addr) { session->saves_arguments.insert(addr); }

// Settles what the call at `call` in `function` passes, from the printf or scanf format at
// `format` that it passes as argument `position`, counted from zero: the parameters before the
// format, the format, and an argument for each conversion in it. Done before the function is
// decompiled, this costs nothing, where finding out afterwards costs decompiling it again.
// Nothing happens unless `callee`, a function's entry or with `import` an import's slot, takes a
// variable number of arguments, and unless the text is a format.
int rd_format_call(RdSession *session, uint64_t function, uint64_t call, uint64_t callee, int import,
                   size_t position, uint64_t format, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    int4 word = arch->getDefaultCodeSpace()->getAddrSize();
    Funcdata *target = nullptr;
    if (import != 0) {
      auto slot = session->slots.find(callee);
      if (slot == session->slots.end()) return;
      target = arch->symboltab->getGlobalScope()->queryFunction(session->address(slot->second));
      // An import is known to take a variable number of arguments only by its declaration,
      // which also says where its format stands.
      if (target == nullptr || !target->getFuncProto().isInputLocked() || !target->getFuncProto().isDotdotdot() ||
          (size_t)target->getFuncProto().numParams() != position + 1)
        return;
    } else {
      if (session->saves_arguments.count(callee) == 0) return;
      target = session->function(callee);
    }
    uint1 bytes[256];
    session->image->loadFill(bytes, sizeof(bytes), session->address(format));
    const uint1 *end = (const uint1 *)memchr(bytes, 0, sizeof(bytes));
    if (end == nullptr) return;
    string text((const char *)bytes, end - bytes);
    vector<bool> floats = format_arguments(text, target->getName().find("scanf") != string::npos);
    // recore: text without a `%` asks for nothing more, as firmware's linked `printf` is
    // called with it. Other text that asks for nothing is no format the parser read.
    if ((floats.empty() && text.find('%') != string::npos) || floats.size() > 12) return;

    const FuncProto &declared = target->getFuncProto();
    PrototypePieces pieces;
    pieces.model = arch->getModel(declared.getModelName());
    pieces.name = target->getName();
    pieces.outtype = declared.isOutputLocked() ? declared.getOutputType() : arch->types->getBase(word, TYPE_UNKNOWN);
    pieces.firstVarArgSlot = -1;
    for (size_t i = 0; i <= position; ++i)
      pieces.intypes.push_back(import != 0 ? declared.getParam(i)->getType() : arch->types->getBase(word, TYPE_UNKNOWN));
    for (bool is_float : floats)
      pieces.intypes.push_back(is_float ? arch->types->getBase(8, TYPE_FLOAT) : arch->types->getBase(word, TYPE_UNKNOWN));
    pieces.innames.assign(pieces.intypes.size(), "");
    FuncProto *proto = new FuncProto();
    proto->setInternal(pieces.model, arch->types->getTypeVoid());
    proto->setPieces(pieces);
    proto->setOutputLock(declared.isOutputLocked());
    // What stands in for the function's prototype at this call says, as that does, whether
    // the call comes back.
    proto->setNoReturn(declared.isNoReturn());
    session->function(function)->getOverride().insertProtoOverride(session->address(call), proto);
    session->format_calls.insert({function, call});
  });
}

// Whether a kept prototype says everything a call passes, or only the least: a call then also
// passes whatever else the call site shows.
void rd_keep_prototypes_exact(RdSession *session, int exact) { session->kept_are_lower_bounds = exact == 0; }

// Selects the engine's root action: "decompile" (everything), "normalize" (stops before type
// recovery and structuring; what Ghidra's switch analysis uses) or "paramid" (what Ghidra's
// parameter-ID analysis uses). Only "decompile" structures control flow, so only it prints C.
int rd_set_style(RdSession *session, const char *name, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    session->arch->allacts.setCurrent(name);
    session->print_c = strcmp(name, "decompile") == 0;
  });
}

// With `on`, each rd_decompile also fills RdDecompiled::flow.
void rd_set_flow(RdSession *session, int on) { session->want_flow = on != 0; }

// Whether rd_decompile prints, before each line of C, the address of the instruction the line
// came from, where it came from one.
void rd_set_addresses(RdSession *session, int on) { session->want_addresses = on != 0; }

// Names the variable of `function` at `place`, as RdDecompiled::locals gives places. The name
// shows in every later decompilation of the function in which the variable is still there.
void rd_name_local(RdSession *session, uint64_t function, const char *place, const char *name) {
  session->local_names[function].push_back({place, name});
}

// Drops the names rd_name_local recorded for `function`.
void rd_forget_local_names(RdSession *session, uint64_t function) { session->local_names.erase(function); }

// Gives the function at `addr` the name `name` in place of the one it has, which `*old` then
// holds until the next call on the session. What the session knows of the function stays,
// its prototype included.
int rd_rename_function(RdSession *session, uint64_t addr, const char *name, const char **old, char *err,
                       size_t errlen) {
  return guarded(err, errlen, [&] {
    Funcdata *fd = session->function(addr);
    session->text = fd->getName();
    fd->getSymbol()->getScope()->renameSymbol(fd->getSymbol(), name);
    fd->setName(name);
    *old = session->text.c_str();
  });
}

// Disassembles `[start, end)` into `*out`, one line per instruction: its address and length in
// hex and its text, tab-separated. Bytes that do not decode give a line with the text `(bad)`.
// With `pcode`, each instruction is followed by its raw p-code, one operation per line, each
// starting with a tab. The text stays valid until the next call on the session.
int rd_listing(RdSession *session, uint64_t start, uint64_t end, int pcode, const char **out,
               char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    const Translate *translate = session->arch->translate;
    ostringstream text;
    uint64_t step = max(1, translate->getAlignment());
    for (uint64_t addr = start; addr < end;) {
      ListingAssembly line;
      ostringstream ops;
      int4 length = 0;
      try {
        length = translate->printAssembly(line, session->address(addr));
        if (pcode) {
          ListingPcode emit(translate, ops);
          translate->oneInstruction(emit, session->address(addr));
        }
      } catch (const UnimplError &) {
        // Decoded, but the processor spec gives it no semantics.
      } catch (const LowlevelError &) {
        length = 0;
      }
      if (length <= 0) {
        text << hex << addr << "\t" << step << "\t(bad)\n";
        addr += step;
        continue;
      }
      text << hex << addr << "\t" << length << "\t" << line.text << "\n" << ops.str();
      addr += length;
    }
    session->text = text.str();
    *out = session->text.c_str();
  });
}

// Declares a global variable `name` at `addr`. `type` is a C type the session knows, such as
// `int4`, `char *` or a declared struct; empty for a label on data of unknown type.
int rd_add_global(RdSession *session, uint64_t addr, const char *name, const char *type, char *err,
                  size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    Scope *global = arch->symboltab->getGlobalScope();
    Address where = session->address(addr);
    Datatype *datatype = arch->types->getBase(1, TYPE_UNKNOWN);
    if (type[0] != 0) {
      static mutex parser_lock;
      lock_guard<mutex> guard(parser_lock);
      istringstream text(type);
      string unused;
      datatype = parse_type(text, unused, arch);
    }
    // A string or vtable declared here before gives way to what the caller says it is.
    SymbolEntry *old = global->findAddr(where, Address());
    if (old != nullptr) global->removeSymbol(old->getSymbol());
    global->addSymbol(name, datatype, where, Address());
  });
}

// The value of an attribute of an XML element, or the empty string if it has none.
static string attribute(const Element *element, const char *name) {
  for (int4 i = 0; i < element->getNumAttributes(); ++i)
    if (element->getAttributeName(i) == name) return element->getAttributeValue(i);
  return "";
}

// The data type an element describes in the engine's own format: `<type>`, `<typeref>`, `<def>`
// or `<void>`.
static Datatype *decode_type(Architecture *arch, const Element *element) {
  XmlDecode decoder(arch, element);
  return arch->types->decodeType(decoder);
}

// Reads a prototype from the `<p>` children of `element`, each holding one type: the first is
// what the function returns, the others are its parameters, by `name`. A `dotdotdot`
// attribute makes it variadic and `model` names its calling convention.
static void decode_prototype(Architecture *arch, const Element *element, PrototypePieces &pieces) {
  string model = attribute(element, "model");
  pieces.model = model.empty() ? arch->defaultfp : arch->getModel(model);
  const List &children = element->getChildren();
  if (children.empty()) throw LowlevelError("prototype without a return type");
  for (size_t i = 0; i < children.size(); ++i) {
    Datatype *type = decode_type(arch, children[i]->getChildren().at(0));
    if (i == 0) {
      pieces.outtype = type;
    } else {
      pieces.intypes.push_back(type);
      pieces.innames.push_back(attribute(children[i], "name"));
    }
  }
  pieces.firstVarArgSlot = attribute(element, "dotdotdot").empty() ? -1 : (int4)pieces.intypes.size();
}

// Adds data types, function prototypes and typed globals from the children of the XML element
// `xml`, in order:
//   <type>, <def>          a data type in the engine's own format, with exact field offsets
//   <functype name id>     a named function type, for pointers to it; children as below
//   <function addr>        the prototype of the function at `addr` (hex), from <p> children
//   <global addr name>     a global variable; its one child is its type
// A child the engine rejects costs only itself: the answer lists those, one line each.
static string add_types(RdSession *session, const char *xml) {
  Architecture *arch = session->arch;
  Scope *global = arch->symboltab->getGlobalScope();
  unique_ptr<Document> document;
  {
    lock_guard<mutex> guard(xml_lock);
    istringstream text(xml);
    document.reset(xml_tree(text));
  }
  ostringstream rejected;
  for (const Element *element : document->getRoot()->getChildren()) {
    const string &tag = element->getName();
    string name = attribute(element, "name");
    auto reject = [&](const string &why) { rejected << tag << " " << name << attribute(element, "addr") << ": " << why << "\n"; };
    try {
      if (tag == "functype") {
        PrototypePieces pieces;
        decode_prototype(arch, element, pieces);
        arch->types->getTypedef(arch->types->getTypeCode(pieces), name, stoull(attribute(element, "id")), 0);
      } else if (tag == "function") {
        PrototypePieces pieces;
        decode_prototype(arch, element, pieces);
        // A parameter the convention has no place for would be stored at no address at all.
        vector<ParameterPieces> storage;
        pieces.model->assignParameterStorage(pieces, storage, true);
        for (size_t i = 1; i < storage.size(); ++i)
          if (storage[i].addr.isInvalid()) throw LowlevelError("the calling convention has no place for a parameter");
        Funcdata *fd = session->function(stoull(attribute(element, "addr"), nullptr, 16));
        pieces.name = fd->getName();
        fd->getFuncProto().setPieces(pieces);
      } else if (tag == "global") {
        Address where = session->address(stoull(attribute(element, "addr"), nullptr, 16));
        Datatype *type = decode_type(arch, element->getChildren().at(0));
        SymbolEntry *old = global->findAddr(where, Address());
        if (old != nullptr) global->removeSymbol(old->getSymbol());
        global->addSymbol(name, type, where, Address());
      } else {
        XmlDecode decoder(arch, element);
        arch->types->decodeType(decoder);
      }
    } catch (const LowlevelError &e) {
      reject(e.explain);
    } catch (const DecoderError &e) {
      reject(e.explain);
    } catch (const std::exception &e) {
      reject(e.what());
    }
  }
  return rejected.str();
}

int rd_add_types(RdSession *session, const char *xml, const char **out, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    session->text = add_types(session, xml);
    *out = session->text.c_str();
  });
}

// Describes the data type `name` in `*out`: its kind, size and alignment on the first line, then
// one line per field of a struct or union (offset, type, name) or per value of an enum.
int rd_type_layout(RdSession *session, const char *name, const char **out, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Architecture *arch = session->arch;
    Datatype *type = arch->types->findByName(name);
    if (type == nullptr) {
      static mutex parser_lock;
      lock_guard<mutex> guard(parser_lock);
      istringstream text(name);
      string unused;
      type = parse_type(text, unused, arch);
    }
    ostringstream s;
    auto header = [&](const char *kind) {
      s << kind << " " << type_name(type) << ", " << dec << type->getSize() << " bytes, alignment " << type->getAlignment() << "\n";
    };
    auto field = [&](const TypeField &f) {
      s << "  +0x" << hex << f.offset << " " << type_name(f.type) << " " << f.name << dec << " (" << f.type->getSize() << " bytes)\n";
    };
    if (type->getTypedef() != nullptr) {
      header("typedef");
      s << "  of " << type_name(type->getTypedef()) << "\n";
    } else if (type->getMetatype() == TYPE_STRUCT) {
      header("struct");
      const TypeStruct *st = static_cast<const TypeStruct *>(type);
      for (auto it = st->beginField(); it != st->endField(); ++it) field(*it);
    } else if (type->getMetatype() == TYPE_UNION) {
      header("union");
      const TypeUnion *un = static_cast<const TypeUnion *>(type);
      for (int4 i = 0; i < un->numDepend(); ++i) field(*un->getField(i));
    } else if (type->isEnumType()) {
      header("enum");
      const TypeEnum *en = static_cast<const TypeEnum *>(type);
      for (auto it = en->beginEnum(); it != en->endEnum(); ++it) s << "  " << it->second << " = 0x" << hex << it->first << dec << "\n";
    } else if (type->getMetatype() == TYPE_PTR) {
      header("pointer");
      s << "  to " << type_name(static_cast<const TypePointer *>(type)->getPtrTo()) << "\n";
    } else if (type->getMetatype() == TYPE_ARRAY) {
      header("array");
      const TypeArray *array = static_cast<const TypeArray *>(type);
      s << "  of " << array->numElements() << " " << type_name(array->getBase()) << "\n";
    } else {
      header("type");
    }
    session->text = s.str();
    *out = session->text.c_str();
  });
}

// The objects a function's parameters point to, as the engine will type them. Each object is a
// class of pointer-sized values, every one at a known offset from the others: the values the
// engine spreads one pointer type across once a parameter has it. The edges are the engine's
// own (TypeOp::propagateType): copies, merges and INDIRECTs in both directions, and an ADD of a
// constant or of an index times a constant from input to output. A value that comes back to
// its class at another offset, as a pointer stepped through a loop does, gives the class a
// stride. Values loaded from or stored to one field of a class are one class too, since the
// engine gives them all the field's type.
class Objects {
  unordered_map<const Varnode *, int> index;
  vector<int> parent;
  vector<int64_t> delta;  // a node's value is its parent's plus this

 public:
  vector<const Varnode *> nodes;
  map<int, set<uint64_t>> strides;  // by class

  bool has(const Varnode *vn) const { return index.count(vn) != 0; }

  int add(const Varnode *vn) {
    auto found = index.emplace(vn, (int)nodes.size());
    if (found.second) {
      nodes.push_back(vn);
      parent.push_back(found.first->second);
      delta.push_back(0);
    }
    return found.first->second;
  }

  // The class of node `i` and the node's offset from the class's value.
  pair<int, int64_t> find(int i) {
    int64_t offset = 0;
    int top = i;
    while (parent[top] != top) {
      offset += delta[top];
      top = parent[top];
    }
    for (int64_t rest = offset; parent[i] != i;) {
      int next = parent[i];
      int64_t step = delta[i];
      parent[i] = top;
      delta[i] = rest;
      rest -= step;
      i = next;
    }
    return {top, offset};
  }
  pair<int, int64_t> find(const Varnode *vn) { return find(add(vn)); }

  void stride(int cls, int64_t step) {
    if (step != 0) strides[cls].insert((uint64_t)(step < 0 ? -step : step));
  }

  // Says that `b` holds `a` plus `d`. Answers whether that was news.
  bool join(const Varnode *a, const Varnode *b, int64_t d) {
    pair<int, int64_t> x = find(a), y = find(b);
    if (x.first == y.first) {
      int64_t known = y.second - x.second;
      if (known == d) return false;
      int64_t step = d - known;
      size_t before = strides[x.first].size();
      stride(x.first, step);
      return strides[x.first].size() != before;
    }
    parent[y.first] = x.first;
    delta[y.first] = x.second + d - y.second;
    auto moved = strides.find(y.first);
    if (moved != strides.end()) {
      strides[x.first].insert(moved->second.begin(), moved->second.end());
      strides.erase(moved);
    }
    return true;
  }
};

// Whether a value can hold one of the pointers struct recovery follows.
static bool pointer_value(const Varnode *vn, int4 word) {
  return vn->getSize() == word && !vn->isConstant() && !vn->isAnnotation() && !vn->isSpacebase() && !vn->isFree();
}

// What the engine makes of a value from the operations around it, as RdAccess::kind says.
static uint8_t value_kind(const Varnode *vn) {
  bool blockup = false;
  Datatype *type;
  try {
    type = vn->getLocalType(blockup);
  } catch (const LowlevelError &) {
    return 0;
  }
  switch (type->getMetatype()) {
    case TYPE_INT: return 1;
    case TYPE_UINT: return 2;
    case TYPE_FLOAT: return 3;
    case TYPE_BOOL: return 4;
    default: return 0;
  }
}

// The address and value of a load or store from the data space, or null.
static const Varnode *accessed(const PcodeOp *op, AddrSpace *data, const Varnode *&value) {
  if (op->code() != CPUI_LOAD && op->code() != CPUI_STORE) return nullptr;
  if (op->getIn(0)->getSpaceFromConst() != data) return nullptr;
  value = op->code() == CPUI_LOAD ? op->getOut() : op->getIn(2);
  return op->getIn(1);
}

// The evidence for one function, with the tables it points into and the parameters of each
// object, which a plan's lock goes on.
struct Gathered {
  RdEvidence evidence;
  vector<RdObject> objects;
  vector<RdRoot> roots;
  vector<RdAccess> accesses;
  vector<RdLink> links;
  vector<RdStride> strides;
  vector<RdPass> passed;
  deque<string> registers;      // the names RdRoot::reg and RdPass::reg point to
  vector<vector<Varnode *>> root_nodes;  // per object
};

// Builds the evidence for `fd`: the objects its parameters point to, and those that fields
// of them point to in turn.
static void gather(RdSession *session, Funcdata &fd, Gathered &out) {
  Architecture *arch = session->arch;
  AddrSpace *data = arch->getDefaultDataSpace();
  AddrSpace *stack = arch->getStackSpace();
  int4 word = data->getAddrSize();
  Objects objects;
  vector<Varnode *> roots;
  const FuncProto &proto = fd.getFuncProto();
  for (auto it = fd.beginDef(Varnode::input); it != fd.endDef(Varnode::input); ++it) {
    Varnode *vn = *it;
    AddrSpace *space = vn->getSpace();
    if (!pointer_value(vn, word) || vn->hasNoDescend()) continue;
    if (space->getType() != IPTR_PROCESSOR && space != stack) continue;
    if (!proto.possibleInputParam(vn->getAddr(), vn->getSize())) continue;
    objects.add(vn);
    roots.push_back(vn);
  }
  if (roots.empty()) return;
  // Values the code uses as numbers, not pointers: an object they belong to is no struct.
  vector<const Varnode *> numeric;
  const int64_t far = 0x10000;
  for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
    const PcodeOp *op = *it;
    auto input = [&](int4 slot) { return op->getIn(slot); };
    switch (op->code()) {
      case CPUI_INT_EQUAL:
      case CPUI_INT_NOTEQUAL:
      case CPUI_INT_LESS:
      case CPUI_INT_LESSEQUAL:
      case CPUI_INT_SLESS:
      case CPUI_INT_SLESSEQUAL:
        // A pointer is compared with null, or with another pointer.
        for (int4 slot = 0; slot < 2; ++slot)
          if (input(slot)->isConstant() && input(slot)->getOffset() != 0 && pointer_value(input(1 - slot), word))
            numeric.push_back(input(1 - slot));
        continue;
      default:
        break;
    }
    const Varnode *result = op->getOut();
    if (result == nullptr || !pointer_value(result, word)) continue;
    switch (op->code()) {
      case CPUI_COPY:
      case CPUI_INDIRECT:
        if (pointer_value(input(0), word)) objects.join(input(0), result, 0);
        break;
      case CPUI_MULTIEQUAL:
        for (int4 i = 0; i < op->numInput(); ++i)
          if (pointer_value(input(i), word)) objects.join(input(i), result, 0);
        break;
      case CPUI_INT_ADD:
      case CPUI_PTRSUB:
        for (int4 slot = 1; slot >= 0; --slot) {
          const Varnode *base = input(1 - slot), *added = input(slot);
          if (!pointer_value(base, word)) continue;
          if (added->isConstant()) {
            int64_t offset = sign_extend((intb)added->getOffset(), 8 * added->getSize() - 1);
            // So far from a struct's start, the constant is the address of a table, and the
            // value an index into it.
            if (offset >= far || offset <= -far)
              numeric.push_back(base);
            else
              objects.join(base, result, offset);
            break;
          }
          // An index times the size of an element.
          if (op->code() == CPUI_INT_ADD && added->isWritten() && added->getDef()->code() == CPUI_INT_MULT &&
              added->getDef()->getIn(1)->isConstant()) {
            const Varnode *factor = added->getDef()->getIn(1);
            int64_t step = sign_extend((intb)factor->getOffset(), 8 * factor->getSize() - 1);
            if (step == -1) break;  // a difference of pointers
            objects.join(base, result, 0);
            objects.stride(objects.find(base).first, step);
            break;
          }
        }
        break;
      case CPUI_PTRADD:
        if (!pointer_value(input(0), word)) break;
        if (input(1)->isConstant()) {
          objects.join(input(0), result, sign_extend((intb)input(1)->getOffset(), 8 * input(1)->getSize() - 1) * (int64_t)input(2)->getOffset());
        } else {
          objects.join(input(0), result, 0);
          objects.stride(objects.find(input(0)).first, (int64_t)input(2)->getOffset());
        }
        break;
      default:
        break;
    }
  }
  // Fields: what is loaded from or stored to one place of a class is one class. Joining can
  // make two places one, so again until nothing changes.
  map<pair<int, int64_t>, const Varnode *> fields;
  bool settled = false;
  for (int round = 0; round < 8 && !settled; ++round) {
    bool changed = false;
    fields.clear();
    for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
      const Varnode *value = nullptr;
      const Varnode *addr = accessed(*it, data, value);
      if (addr == nullptr || !objects.has(addr) || !pointer_value(value, word)) continue;
      auto found = fields.emplace(objects.find(addr), value);
      if (found.second)
        objects.add(value);
      else
        changed |= objects.join(found.first->second, value, 0);
    }
    settled = !changed;
  }
  // Places found before the last join may name a class by a node that is no longer its own.
  if (!settled) fields.clear();
  // The classes to hand over: those of parameters, then those their fields point to.
  map<int, uint32_t> numbers;
  vector<int> classes;
  vector<int64_t> bases;
  auto number = [&](int cls, int64_t base) {
    auto found = numbers.emplace(cls, (uint32_t)classes.size());
    if (found.second) {
      classes.push_back(cls);
      bases.push_back(base);
    }
    return found.first->second;
  };
  for (Varnode *root : roots) {
    pair<int, int64_t> at = objects.find(root);
    number(at.first, at.second);
  }
  map<int, vector<pair<int64_t, const Varnode *>>> pointed;  // per class: field offset, a value
  for (const auto &field : fields) pointed[objects.find(field.first.first).first].push_back({field.first.second, field.second});
  for (size_t i = 0; i < classes.size(); ++i) {
    for (const auto &field : pointed[classes[i]]) {
      pair<int, int64_t> child = objects.find(field.second);
      uint32_t at = number(child.first, child.second);
      out.links.push_back({(uint32_t)i, field.first - bases[i], at});
    }
  }
  out.objects.assign(classes.size(), RdObject{INT64_MAX, INT64_MIN, 0, 0, 0});
  out.root_nodes.assign(classes.size(), {});
  for (const Varnode *vn : objects.nodes) {
    pair<int, int64_t> at = objects.find(vn);
    auto found = numbers.find(at.first);
    if (found == numbers.end()) continue;
    RdObject &object = out.objects[found->second];
    int64_t offset = at.second - bases[found->second];
    object.low = min(object.low, offset);
    object.high = max(object.high, offset);
    object.locked |= vn->isTypeLock();
    object.global |= vn->isPersist();
  }
  for (const Varnode *vn : numeric) {
    auto found = numbers.find(objects.find(vn).first);
    if (found != numbers.end()) out.objects[found->second].number = 1;
  }
  for (Varnode *root : roots) {
    pair<int, int64_t> at = objects.find(root);
    uint32_t object = numbers[at.first];
    string reg = root->getSpace() == stack ? "" : arch->translate->getRegisterName(root->getSpace(), root->getOffset(), root->getSize());
    out.registers.push_back(reg);
    out.roots.push_back({object, reg.empty() ? nullptr : out.registers.back().c_str(), root->getSpace() == stack ? root->getOffset() : 0, at.second - bases[object]});
    out.root_nodes[object].push_back(root);
  }
  for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
    const Varnode *value = nullptr;
    const Varnode *addr = accessed(*it, data, value);
    if (addr == nullptr || !objects.has(addr)) continue;
    pair<int, int64_t> at = objects.find(addr);
    auto found = numbers.find(at.first);
    if (found == numbers.end()) continue;
    out.accesses.push_back({found->second, at.second - bases[found->second], (uint32_t)value->getSize(), value_kind(value)});
  }
  // Members handed to calls, where the callee's parameters are settled: a holder of the
  // callee's slot names the struct it takes.
  for (auto it = fd.beginOpAlive(); it != fd.endOpAlive(); ++it) {
    PcodeOp *op = *it;
    if (op->code() != CPUI_CALL) continue;
    FuncCallSpecs *fc = fd.getCallSpecs(op);
    if (fc == nullptr || fc->isInputActive() || fc->getEntryAddress().isInvalid()) continue;
    for (int4 i = 0; i < fc->numParams() && i + 1 < op->numInput(); ++i) {
      const Varnode *vn = op->getIn(i + 1);
      if (!objects.has(vn)) continue;
      pair<int, int64_t> at = objects.find(vn);
      auto found = numbers.find(at.first);
      if (found == numbers.end()) continue;
      Address where = fc->getParam(i)->getAddress();
      bool on_stack = where.getSpace() == stack;
      if (!on_stack && where.getSpace()->getType() != IPTR_PROCESSOR) continue;
      string reg = on_stack ? "" : arch->translate->getRegisterName(where.getSpace(), where.getOffset(), fc->getParam(i)->getSize());
      if (!on_stack && reg.empty()) continue;
      out.registers.push_back(reg);
      out.passed.push_back({found->second, session->offset(fc->getEntryAddress()), on_stack ? nullptr : out.registers.back().c_str(),
                            on_stack ? where.getOffset() : 0, at.second - bases[found->second]});
    }
  }
  for (const auto &steps : objects.strides) {
    auto found = numbers.find(objects.find(steps.first).first);
    if (found == numbers.end()) continue;
    for (uint64_t step : steps.second) out.strides.push_back({found->second, step});
  }
  out.evidence = {session->offset(fd.getAddress()), (uint32_t)word,
                  out.objects.data(), out.objects.size(), out.roots.data(), out.roots.size(),
                  out.accesses.data(), out.accesses.size(), out.links.data(), out.links.size(),
                  out.strides.data(), out.strides.size(), out.passed.data(), out.passed.size()};
}

// Gives the parameters of `fd` the structs recore plans for what they point to. Runs when the
// engine starts typing the function: its SSA is settled and nothing unlocked has a type yet.
static void recover_structs(RdSession *session, Funcdata &fd) {
  if (session->plan == nullptr) return;
  Gathered gathered;
  gather(session, fd, gathered);
  if (gathered.objects.empty()) return;
  RdPlan plan;
  if (session->plan(session->structs, &gathered.evidence, &plan) == 0) return;
  Architecture *arch = session->arch;
  if (plan.xml != nullptr) add_types(session, plan.xml);
  auto complete = [&](const char *name) -> Datatype * {
    Datatype *type = arch->types->findByName(name);
    return type != nullptr && type->getMetatype() == TYPE_STRUCT && !type->isIncomplete() ? type : nullptr;
  };
  for (size_t i = 0; i < plan.recovered_count; ++i) {
    Datatype *type = complete(plan.recovered[i]);
    // A named struct may be an array's element in one function and not in another.
    if (type != nullptr) session->recovered[type] |= plan.arrays[i] != 0;
  }
  for (size_t i = 0; i < plan.warning_count; ++i) fd.warningHeader(plan.warnings[i]);
  AddrSpace *data = arch->getDefaultDataSpace();
  for (size_t i = 0; i < gathered.objects.size(); ++i) {
    Datatype *type = plan.names[i] != nullptr ? complete(plan.names[i]) : nullptr;
    if (type == nullptr) continue;
    Datatype *pointer = arch->types->getTypePointer(data->getAddrSize(), type, data->getWordSize());
    for (Varnode *root : gathered.root_nodes[i])
      if (!root->isTypeLock()) root->updateType(pointer, true, false);
  }
}

// Whether a data type is, or points to, a struct recovery defined.
static bool mentions_recovered(const RdSession *session, const Datatype *type) {
  for (int depth = 0; type != nullptr && depth < 8; ++depth) {
    if (session->recovered.count(type) != 0) return true;
    if (type->getMetatype() == TYPE_PTR)
      type = static_cast<const TypePointer *>(type)->getPtrTo();
    else if (type->getMetatype() == TYPE_ARRAY)
      type = static_cast<const TypeArray *>(type)->getBase();
    else
      return false;
  }
  return false;
}

// The recovered structs that `fd`'s code reaches past the end of: through a field at or past
// the end, or by stepping a pointer to one that is no element of an array. Each means that
// `gather` missed a value the engine typed.
static set<string> wrapped(const RdSession *session, Funcdata *fd) {
  set<string> names;
  for (auto it = fd->beginOpAlive(); it != fd->endOpAlive(); ++it) {
    const PcodeOp *op = *it;
    if (op->code() != CPUI_PTRSUB && op->code() != CPUI_PTRADD) continue;
    Datatype *type = op->getIn(0)->getHighTypeReadFacing(op);
    if (type->getMetatype() != TYPE_PTR) continue;
    Datatype *to = static_cast<TypePointer *>(type)->getPtrTo();
    auto found = session->recovered.find(to);
    if (found == session->recovered.end()) continue;
    bool past = op->code() == CPUI_PTRSUB ? op->getIn(1)->isConstant() && op->getIn(1)->getOffset() >= (uintb)to->getSize() : !found->second;
    if (past) names.insert(to->getName());
  }
  return names;
}

// Says how recore plans the structs of the functions this session decompiles: `plan` is asked
// with each function's evidence, and `wrapped` told of a struct that still wrapped. `ctx` goes
// with each call.
void rd_set_struct_hooks(RdSession *session, void *ctx, RdPlanHook plan, RdWrappedHook wrapped) {
  session->structs = ctx;
  session->plan = plan;
  session->wrapped = wrapped;
}

// Names the field at `offset` of the struct `type_name` `name` from now on, wherever it prints.
int rd_name_field(RdSession *session, const char *type_name, uint64_t offset, const char *name, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    Datatype *type = session->arch->types->findByName(type_name);
    if (type == nullptr || type->getMetatype() != TYPE_STRUCT) throw LowlevelError(string("no struct ") + type_name);
    session->arch->types->setFieldName(static_cast<TypeStruct *>(type), (int4)offset, name);
  });
}

int rd_decompile(RdSession *session, uint64_t addr, RdDecompiled *out, char *err, size_t errlen) {
  Funcdata *fd = nullptr;
  Architecture *arch = session->arch;
  // A prototype that was declared, not recovered, is the whole truth and stays as it is.
  bool declared = false;
  bool spills = false;
  bool inlined = false;
  bool ok = guarded(err, errlen, [&] {
    fd = session->function(addr);
    declared = fd->getFuncProto().isInputLocked() && session->kept.count(addr) == 0;
    if (fd->getFuncProto().isInputLocked() && session->kept.erase(addr) != 0) {
      // Recover the prototype afresh instead of replaying the one kept from an earlier run.
      fd->getFuncProto().setInputLock(false);
      fd->getFuncProto().setDotdotdot(false);
      arch->clearAnalysis(fd);
    }
    set_kept_registers(session, addr, true);
    // A function read as part of its callers is decompiled as any other when asked for.
    inlined = fd->getFuncProto().isInline() && fd->getFuncProto().getInjectId() < 0;
    if (inlined) {
      // As part of a caller it was left holding its instructions.
      arch->clearAnalysis(fd);
      fd->getFuncProto().setInline(false);
    }
    Action *root = arch->allacts.getCurrent();
    root->reset(*fd);
    session->image->current = addr;
    // Follows flow from the entry point, then runs the whole simplification pipeline.
    if (root->perform(*fd) < 0) throw LowlevelError("decompilation stopped at a breakpoint");
    if (only_spills_register_param(fd)) {
      // Run again with a convention that passes nothing in registers. The lock stays with the
      // function, so its callers stop passing the register too.
      arch->clearAnalysis(fd);
      fd->getFuncProto().setModel(arch->defaultfp);
      fd->getFuncProto().setModelLock(true);
      root->reset(*fd);
      if (root->perform(*fd) < 0) throw LowlevelError("decompilation stopped at a breakpoint");
    }

    if (follow_formats(session, fd)) {
      arch->clearAnalysis(fd);
      root->reset(*fd);
      if (root->perform(*fd) < 0) throw LowlevelError("decompilation stopped at a breakpoint");
    }
    if (session->stack_aggregates && !fd->getFuncProto().isInputLocked()) {
      vector<ParameterPieces> slots = stack_aggregate(fd);
      if (!slots.empty()) {
        // The parameters recovered, then the slots, as the prototype it keeps: its callers pass
        // what is in them, and its own C reads them as parameters.
        vector<ParameterPieces> params;
        const FuncProto &recovered = fd->getFuncProto();
        for (int4 i = 0; i < recovered.numParams(); ++i) {
          ParameterPieces piece;
          piece.addr = recovered.getParam(i)->getAddress();
          piece.type = recovered.getParam(i)->getType();
          piece.flags = 0;
          params.push_back(piece);
        }
        params.insert(params.end(), slots.begin(), slots.end());
        arch->clearAnalysis(fd);
        FuncProto &proto = fd->getFuncProto();
        proto.clearInput();
        for (size_t i = 0; i < params.size(); ++i) proto.setParam((int4)i, "", params[i]);
        proto.setInputLock(true);
        root->reset(*fd);
        if (root->perform(*fd) < 0) throw LowlevelError("decompilation stopped at a breakpoint");
      }
    }
    set<string> wraps = wrapped(session, fd);
    if (!wraps.empty()) {
      // Once more without them: the walk in `gather` missed a value the engine typed.
      for (const string &name : wraps) session->wrapped(session->structs, session->offset(fd->getAddress()), name.c_str());
      arch->clearAnalysis(fd);
      root->reset(*fd);
      if (root->perform(*fd) < 0) throw LowlevelError("decompilation stopped at a breakpoint");
      for (const string &name : wrapped(session, fd)) session->wrapped(session->structs, session->offset(fd->getAddress()), name.c_str());
      string names;
      for (const string &name : wraps) names += (names.empty() ? "" : ", ") + name;
      fd->warningHeader("Decompiled again without recovered structs the code reaches past the end of: " + names);
    }
    session->locals = name_locals(session, addr, fd);
    ostringstream text;
    if (session->print_c) {
      // The pretty printer numbers its tokens from one unsynchronized static counter
      // (TokenSplit::countbase), the only engine global written after session creation.
      static mutex print_lock;
      lock_guard<mutex> guard(print_lock);
      arch->print->setOutputStream(&text);
      EmitAddressed *addressed = nullptr;
      if (session->want_addresses) arch->print->setLowLevel(addressed = new EmitAddressed);
      arch->print->docFunction(fd);
      if (addressed != nullptr) {
        addressed->flush();
        arch->print->setLowLevel(new EmitNoMarkup);
      }
    }
    session->c_text = text.str();
    ostringstream flow;
    if (session->want_flow) dump_flow(session, fd, flow);
    session->flow = flow.str();

    const FuncProto &proto = fd->getFuncProto();
    session->return_type = type_name(proto.getOutputType());
    session->strings.clear();
    session->params.clear();
    int4 count = proto.numParams();
    session->strings.reserve(2 * count);  // RdParam points into this, so it must not reallocate
    for (int4 i = 0; i < count; ++i) {
      ProtoParameter *param = proto.getParam(i);
      Address storage = param->getAddress();
      string where = arch->translate->getRegisterName(storage.getSpace(), storage.getOffset(),
                                                      param->getSize());
      if (where.empty()) {
        ostringstream s;
        s << storage.getSpace()->getName() << ":0x" << hex << storage.getOffset();
        where = s.str();
      }
      session->strings.push_back(type_name(param->getType()));
      session->strings.push_back(where);
      session->params.push_back({session->strings[2 * i].c_str(), session->strings[2 * i + 1].c_str(),
                                 (uint32_t)param->getSize()});
    }

    session->jump_addrs.clear();
    session->jump_counts.clear();
    session->jump_targets.clear();
    for (int4 i = 0; i < fd->numJumpTables(); ++i) {
      JumpTable *table = fd->getJumpTable(i);
      session->jump_addrs.push_back(table->getOpAddress().getOffset());
      session->jump_counts.push_back(table->numEntries());
      for (int4 j = 0; j < table->numEntries(); ++j)
        session->jump_targets.push_back(table->getAddressByIndex(j).getOffset());
    }

    out->c_text = session->c_text.c_str();
    out->return_type = session->return_type.c_str();
    out->params = session->params.data();
    out->param_count = session->params.size();
    out->jump_addrs = session->jump_addrs.data();
    out->jump_counts = session->jump_counts.data();
    out->jump_table_count = session->jump_addrs.size();
    out->jump_targets = session->jump_targets.data();
    session->outputs.erase(addr);
    if (proto.getOutputType()->getMetatype() != TYPE_VOID) {
      ParameterPieces piece;
      piece.addr = proto.getOutput()->getAddress();
      piece.type = proto.getOutputType();
      // A recovered struct covers what this function reads of it, not what another one would.
      if (mentions_recovered(session, piece.type)) piece.type = arch->types->getBase(piece.type->getSize(), TYPE_UNKNOWN);
      piece.flags = 0;
      session->outputs[addr] = piece;
    }
    out->flow = session->flow.c_str();
    out->locals = session->locals.c_str();
    spills = spills_a_register_param(fd);
    out->flags = (fd->hasBadData() ? RD_BAD_DATA : 0) |
                 (fd->hasUnimplemented() ? RD_UNIMPLEMENTED : 0) |
                 (proto.getOutputType()->getMetatype() != TYPE_VOID ? RD_RETURNS_VALUE : 0);
  });
  if (ok && session->keep_prototypes && !declared) {
    // A variadic function spills all eight vector argument registers, which the engine reads as
    // eight parameters. Kept, that prototype would make every caller pass them all.
    size_t vector_params = 0;
    for (const RdParam &param : session->params) vector_params += strncmp(param.storage, "XMM", 3) == 0;
    if (vector_params < 8 && !reads_unexplained_register(fd) && !spills) {
      // Kept as a lower bound: a call passes these parameters and whatever else the call site
      // shows. A variadic function looks like one with only its fixed parameters.
      // A recovered struct covers what this function reads of it, and callers read other parts.
      FuncProto &proto = fd->getFuncProto();
      for (int4 i = 0; i < proto.numParams(); ++i) {
        ProtoParameter *param = proto.getParam(i);
        if (!mentions_recovered(session, param->getType())) continue;
        ParameterPieces piece;
        piece.addr = param->getAddress();
        piece.type = arch->types->getBase(param->getSize(), TYPE_UNKNOWN);
        piece.flags = 0;
        proto.setParam(i, param->getName(), piece);
      }
      fd->getFuncProto().setInputLock(true);
      fd->getFuncProto().setDotdotdot(session->kept_are_lower_bounds);
      session->kept.insert(addr);
    }
  }
  if (fd != nullptr && session->returns_like.erase(addr) != 0 && !session->keep_prototypes &&
      session->result_in_first_argument) {
    // A prototype is kept whole or not at all. The engine does not look for an argument of a
    // call in the place the call is known to return in, so where the convention returns in the
    // register of its first argument, a result kept without the parameters costs every call
    // that argument.
    fd->getFuncProto().setOutputLock(false);
  }
  guarded(nullptr, 0, [&] { set_kept_registers(session, addr, false); });
  if (inlined) fd->getFuncProto().setInline(true);
  session->image->current = ~(uint64_t)0;
  // Drop the p-code, varnodes and inferred (unlocked) prototype: they are large, and a failed
  // run leaves them half built. Overrides and the function symbol itself are kept.
  if (fd != nullptr) guarded(nullptr, 0, [&] { arch->clearAnalysis(fd); });
  return ok;
}

}  // extern "C"
