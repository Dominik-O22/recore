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
  set<uint64_t> kept;  // functions whose prototype this session locked

  // Backing storage for the last RdDecompiled.
  string c_text, return_type;
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

extern "C" {

// `spec_dir` holds the .ldefs/.pspec/.cspec/.sla files. The first session fixes it for the
// whole process, because the engine caches its language list in static storage.
RdSession *rd_session_new(const char *spec_dir, const char *language, const RdSection *sections,
                          size_t count, char *err, size_t errlen) {
  // Spec loading goes through bison parsers with global state and fills static tables.
  static mutex init_lock;
  static bool started = false;
  lock_guard<mutex> guard(init_lock);

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

// With `keep` set, the parameters recovered by each successful rd_decompile are locked into the
// function's symbol, so that later decompilations of its callers pass exactly those parameters.
void rd_keep_prototypes(RdSession *session, int keep) { session->keep_prototypes = keep != 0; }

// Selects the engine's root action: "decompile" (everything), "normalize" (stops before type
// recovery and structuring; what Ghidra's switch analysis uses) or "paramid" (what Ghidra's
// parameter-ID analysis uses). Only "decompile" structures control flow, so only it prints C.
int rd_set_style(RdSession *session, const char *name, char *err, size_t errlen) {
  return guarded(err, errlen, [&] {
    session->arch->allacts.setCurrent(name);
    session->print_c = strcmp(name, "decompile") == 0;
  });
}

int rd_decompile(RdSession *session, uint64_t addr, RdDecompiled *out, char *err, size_t errlen) {
  Funcdata *fd = nullptr;
  Architecture *arch = session->arch;
  bool ok = guarded(err, errlen, [&] {
    fd = session->function(addr);
    if (fd->getFuncProto().isInputLocked() && session->kept.erase(addr) != 0) {
      // Recover the prototype afresh instead of replaying the one kept from an earlier run.
      fd->getFuncProto().setInputLock(false);
      arch->clearAnalysis(fd);
    }
    Action *root = arch->allacts.getCurrent();
    root->reset(*fd);
    session->image->current = addr;
    // Follows flow from the entry point, then runs the whole simplification pipeline.
    if (root->perform(*fd) < 0) throw LowlevelError("decompilation stopped at a breakpoint");

    ostringstream text;
    if (session->print_c) {
      // The pretty printer numbers its tokens from one unsynchronized static counter
      // (TokenSplit::countbase), the only engine global written after session creation.
      static mutex print_lock;
      lock_guard<mutex> guard(print_lock);
      arch->print->setOutputStream(&text);
      arch->print->docFunction(fd);
    }
    session->c_text = text.str();

    const FuncProto &proto = fd->getFuncProto();
    auto type_name = [](Datatype *type) {
      ostringstream s;
      type->printRaw(s);  // getName() is empty for pointers and arrays
      return s.str();
    };
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
    out->flags = (fd->hasBadData() ? RD_BAD_DATA : 0) |
                 (fd->hasUnimplemented() ? RD_UNIMPLEMENTED : 0) |
                 (proto.getOutputType()->getMetatype() != TYPE_VOID ? RD_RETURNS_VALUE : 0);
  });
  if (ok && session->keep_prototypes) {
    // A variadic function spills all eight vector argument registers, which the engine reads as
    // eight parameters. Kept, that prototype would make every caller pass them all.
    size_t vector_params = 0;
    for (const RdParam &param : session->params) vector_params += strncmp(param.storage, "XMM", 3) == 0;
    if (vector_params < 8) {
      fd->getFuncProto().setInputLock(true);
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
