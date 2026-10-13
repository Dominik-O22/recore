// C interface between recore and Ghidra's decompiler engine.
//
// One RdSession is one ghidra::Architecture: a program image, its symbol database and a
// SLEIGH translator. Sessions are independent of each other and may run on different
// threads, but a single session must only be used by one thread at a time. The two places
// where the engine touches process-wide state, session creation and C printing, take a lock.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
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
  AddrSpace *space = nullptr;  // the RAM space, known once the translator exists
  // While a function is being decompiled, every other function's entry reads as 0xff bytes,
  // which decode on neither x86 nor AArch64. Flow that runs or jumps into another function is then cut off with a
  // "bad instruction" warning instead of being followed. That happens after a call the engine
  // does not know to be non-returning, and one such miss can chain through thousands of
  // functions. The engine's own flow bounds (FlowInfo::setRange) cannot do this: a restart
  // drops them, and a fall-through across the bound fails the function.
  unordered_set<uint64_t> entries;  // every declared function start
  set<pair<uint64_t, uint64_t>> allowed;  // (function, entry) pairs exempt from the above
  uint64_t current = ~(uint64_t)0;  // the function being decompiled, or none

  SectionImage(const string &lang, const RdSection *secs, size_t count)
      : LoadImage("recore"), language(lang) {
    for (size_t i = 0; i < count; ++i)
      sections.push_back({secs[i].addr, vector<uint1>(secs[i].data, secs[i].data + secs[i].len),
                          secs[i].readonly != 0, secs[i].code != 0});
    sort(sections.begin(), sections.end(),
         [](const Section &a, const Section &b) { return a.addr < b.addr; });
  }

  // The instruction decoder reads a fixed window ahead, so a request may run past the end of a
  // section. Like Ghidra's own loaders, pad with zeros and fail only if the first byte is unmapped.
  void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
    uintb cur = addr.getOffset();
    int4 done = 0;
    while (done < size) {
      const Section *sec = find(cur);
      if (sec == nullptr) break;
      int4 count = (int4)min<uintb>(size - done, sec->end() - cur);
      memcpy(ptr + done, sec->data.data() + (cur - sec->addr), count);
      done += count;
      cur += count;
    }
    // The decoder asks for a window that starts at the instruction, so only a request starting
    // exactly at an entry is an attempt to decode it; windows that merely overlap one are not.
    const Section *first = find(addr.getOffset());
    if (done > 0 && current != ~(uint64_t)0 && addr.getOffset() != current && first->code &&
        entries.count(addr.getOffset()) != 0 && allowed.count({current, addr.getOffset()}) == 0)
      memset(ptr, 0xff, done);
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

class SectionArchitecture : public SleighArchitecture {
  SectionImage *image;  // owned by Architecture::loader once buildLoader has run

  void buildLoader(DocumentStorage &) override {
    collectSpecFiles(*errorstream);
    loader = image;
  }

  // SleighArchitecture keeps one translator per language in a static map and re-points it at
  // whichever Architecture was built last. A translator per session is what makes sessions
  // independent of each other.
  Translate *buildTranslator(DocumentStorage &) override { return new Sleigh(loader, context); }

  void postSpecFile() override {
    Architecture::postSpecFile();
    image->space = getDefaultCodeSpace();
  }

 public:
  SectionArchitecture(SectionImage *img, ostream *errs)
      : SleighArchitecture("recore", img->language, errs), image(img) {}

  // ~SleighArchitecture forgets the translator instead of freeing it, so the session does.
  const Translate *translator() const { return translate; }
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
  bool want_flow = false;
  bool want_addresses = false;
  set<uint64_t> kept;  // functions whose prototype this session locked
  // Names given to variables, per function: the variable's place and its name.
  map<uint64_t, vector<pair<string, string>>> local_names;
  // Where and as what each function decompiled so far returns its value, if it returns one.
  map<uint64_t, ParameterPieces> outputs;

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

  Address address(uint64_t offset) const { return Address(arch->getDefaultCodeSpace(), offset); }

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
static void dump_flow(Funcdata *fd, ostream &out) {
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
      out << "global\t" << vn->getOffset() << (symbol != nullptr ? " " + symbol->getName() : "");
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
    // Use the contents of read-only memory as constants, as Ghidra does by default. This is
    // what turns a call through a pointer table into a call to a known function.
    session->arch->readonlypropagate = true;
    // Every cut at another function's entry counts as a bad instruction, and a function with
    // several conditional tail calls has several. The engine's default gives up at four.
    session->arch->max_baddata = 32;
    // The top megabyte of the address space, which no image occupies.
    session->next_external = session->arch->getDefaultCodeSpace()->getHighest() & ~(uintb)0xfffff;
  });
  if (session->arch != nullptr) session->translator = session->arch->translator();
  if (ok) return session;
  delete session;
  return nullptr;
}

void rd_session_free(RdSession *session) { delete session; }

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
      piece = found->second;
    }
    Funcdata *fd = session->function(function);
    if (fd->getFuncProto().isOutputLocked()) return;  // the caller or an edit has said what it returns
    bool model_locked = fd->getFuncProto().isModelLocked();
    fd->getFuncProto().setOutput(piece);
    fd->getFuncProto().setOutputLock(true);
    // Locking the output locks the calling convention with it, which is still to be recovered.
    fd->getFuncProto().setModelLock(model_locked);
    returns = true;
  });
  return ok && returns;
}

// With `keep` set, the parameters recovered by each successful rd_decompile are locked into the
// function's symbol, so that later decompilations of its callers pass at least those parameters.
void rd_keep_prototypes(RdSession *session, int keep) { session->keep_prototypes = keep != 0; }

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
// A child the engine rejects costs only itself: `*out` lists those, one line each.
int rd_add_types(RdSession *session, const char *xml, const char **out, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
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
    session->text = rejected.str();
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

int rd_decompile(RdSession *session, uint64_t addr, RdDecompiled *out, char *err, size_t errlen) {
  Funcdata *fd = nullptr;
  Architecture *arch = session->arch;
  // A prototype that was declared, not recovered, is the whole truth and stays as it is.
  bool declared = false;
  bool spills = false;
  bool ok = guarded(err, errlen, [&] {
    fd = session->function(addr);
    declared = fd->getFuncProto().isInputLocked() && session->kept.count(addr) == 0;
    if (fd->getFuncProto().isInputLocked() && session->kept.erase(addr) != 0) {
      // Recover the prototype afresh instead of replaying the one kept from an earlier run.
      fd->getFuncProto().setInputLock(false);
      fd->getFuncProto().setDotdotdot(false);
      arch->clearAnalysis(fd);
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
    if (session->want_flow) dump_flow(fd, flow);
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
      fd->getFuncProto().setInputLock(true);
      fd->getFuncProto().setDotdotdot(session->kept_are_lower_bounds);
      session->kept.insert(addr);
    }
  }
  session->image->current = ~(uint64_t)0;
  // Drop the p-code, varnodes and inferred (unlocked) prototype: they are large, and a failed
  // run leaves them half built. Overrides and the function symbol itself are kept.
  if (fd != nullptr) guarded(nullptr, 0, [&] { arch->clearAnalysis(fd); });
  return ok;
}

}  // extern "C"
