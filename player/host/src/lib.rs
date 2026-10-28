//! What a lifted Windows game finds outside its executable: Windows, DirectDraw, DirectInput,
//! DirectSound, CD audio and Miles sound, written in Rust. Each import's slot holds an address at
//! or above `recore_machine::HOST`, and a call to it lands in [`Win32::run`] by name. A game
//! describes itself to the host with a [`Game`], and its binary runs with [`run`].

mod callback;
mod cd;
mod com;
mod com_tables;
mod ddraw;
mod dinput;
mod dsound;
mod files;
mod fmt;
mod gdi32;
mod kernel32;
mod miles;
mod misc;
mod resources;
mod session;
mod user32;
mod watch;
mod winmm;

use std::{collections::HashMap, path::PathBuf, time::Instant};

use recore_machine::{Cpu, Frame, HOST, Host, image::Image, regs::*};

/// What sets one game apart, for the host: a game's binary keeps one as a constant and hands it
/// to [`run`]. [`Game::new`] gives one with no disc, no changes to the image and no hook.
pub struct Game {
    /// The window's title.
    pub title: &'static str,
    /// The executable's file name, as `GetModuleFileNameA` gives it.
    pub exe: &'static str,
    /// The executable to load, where it is not `exe` in the game's directory, such as a copy
    /// fixed up for the loader. TT_EXE names another.
    pub image: Option<&'static str>,
    /// Where the game sees itself installed, such as `C:\GAME`.
    pub root: &'static str,
    /// The command line, unless TT_ARGS gives one.
    pub command_line: &'static str,
    /// What the CD-ROM drive holds.
    pub disc: Disc,
    /// Changes the executable gets as it loads, before any of it runs.
    pub prepare: fn(&mut Image),
    /// Called as the game presents each frame, with the frame's number from 1, before it is shown.
    pub present: fn(&mut Cpu, u64),
    /// Names of the game's functions, for the stacks TT_BACKTRACE prints: lines of an address and
    /// a name split by a tab, after a header line, as `include_str!` of a names.tsv gives them.
    pub names: &'static str,
}

impl Game {
    pub const fn new(title: &'static str, exe: &'static str, root: &'static str) -> Game {
        Game { title, exe, image: None, root, command_line: exe, disc: Disc::Empty, prepare: |_| {}, present: |_, _| {}, names: "" }
    }
}

/// What the CD-ROM drive, D:, holds. A path on any other drive names the game's directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disc {
    /// The game's own files, as if it ran from its disc.
    Game,
    /// No disc: nothing on D: opens. A copy whose disc check was cracked by inverting it passes
    /// only when the drive does not hold the game.
    Empty,
}

impl Disc {
    /// Whether `path` names nothing, being on a drive without a disc.
    fn hides(self, path: &str) -> bool {
        self == Disc::Empty && path.get(..2).is_some_and(|drive| drive.eq_ignore_ascii_case("d:"))
    }
}

/// A heap block's size as the heap keeps it: whole 16-byte units, at least one.
fn rounded(size: u32) -> u32 {
    size.max(1).next_multiple_of(16)
}

/// Import slots point at `IMPORTS + 4 * index`.
pub const IMPORTS: u32 = HOST;
/// Memory the host lays out for the game, below the image's 0x400000.
const STACK_TOP: u32 = 0x0030_0000;
const STACK_SIZE: u32 = 0x0010_0000;
const TEB: u32 = 0x0031_0000;
/// The heap `HeapAlloc` and its kin hand out, from here up.
const HEAP: u32 = 0x1000_0000;
/// Where control returns when the entry point returns.
pub const SENTINEL: u32 = 0xefff_fff0;

pub struct Win32 {
    game: &'static Game,
    pub game_dir: PathBuf,
    /// Where files the game writes go (files.rs).
    pub overlay_dir: PathBuf,
    imports: Vec<(String, String)>,
    /// The DLLs `LoadLibraryA` loaded, by lowercase name.
    modules: Vec<String>,
    heap: u32,
    /// The size of each block the heap handed out, for `HeapSize` and `HeapReAlloc`.
    sizes: HashMap<u32, u32>,
    /// Blocks `HeapFree` gave back, by their size rounded to 16 bytes, which `heap_alloc` reuses.
    free: HashMap<u32, Vec<u32>>,
    tls_next: u32,
    clock: kernel32::Clock,
    /// The window's input as the game polled it, recorded or replayed (session.rs).
    inputs: session::Inputs,
    polls: u64,
    statics: HashMap<String, u32>,
    /// The executable's string table, for `LoadStringA`.
    strings: HashMap<u32, Vec<u8>>,
    files: files::Files,
    user: user32::User,
    gdi: gdi32::Gdi,
    dd: ddraw::DirectDraw,
    miles: miles::Miles,
    input: dinput::Input,
    sound: dsound::Sound,
    cd: cd::Cd,
    timers: winmm::Timers,
    vtables: HashMap<com::Iface, u32>,
    /// Game code a host function hands control to, set up with `Cpu::redirect`.
    next: Option<u32>,
    /// The window, unless the game runs headless.
    link: Option<recore_window::Link>,
    /// Frames presented since the game started, as TT_SHOTS and TT_INPUT count them.
    presents: u64,
    /// When the frame rate was last reported.
    rate_from: Option<Instant>,
    trace: bool,
    watch: watch::Watch,
    /// Imports and COM methods whose callers TT_BACKTRACE=<name>,... prints as game addresses
    /// (`game_stack`).
    backtrace: Vec<String>,
}

impl Win32 {
    pub fn new(game: &'static Game, game_dir: PathBuf, image: &Image, exe: &[u8]) -> Win32 {
        let imports = image.imports.iter().map(|i| (i.dll.clone(), i.name.clone())).collect();
        let overlay_dir = PathBuf::from(std::env::var_os("TT_OVERLAY").unwrap_or_else(|| "out/game-files".into()));
        Win32 {
            game,
            game_dir,
            overlay_dir,
            imports,
            modules: Vec::new(),
            heap: HEAP,
            sizes: HashMap::new(),
            free: HashMap::new(),
            tls_next: 0,
            clock: kernel32::Clock::from_env(),
            inputs: session::Inputs::open(),
            polls: 0,
            statics: HashMap::new(),
            strings: resources::strings(exe),
            files: files::Files::default(),
            user: user32::User::new(),
            gdi: gdi32::Gdi::default(),
            dd: ddraw::DirectDraw::default(),
            miles: miles::Miles::default(),
            input: dinput::Input::default(),
            sound: dsound::Sound::default(),
            cd: cd::Cd::default(),
            timers: winmm::Timers::default(),
            vtables: HashMap::new(),
            next: None,
            link: None,
            rate_from: None,
            presents: 0,
            trace: std::env::var_os("TT_TRACE").is_some(),
            watch: watch::Watch::from_env(),
            backtrace: std::env::var("TT_BACKTRACE").unwrap_or_default().split(',').filter(|s| !s.is_empty()).map(String::from).collect(),
        }
    }

    /// Sets the machine up as Windows starts a process: the import slots (`slots`, in the
    /// image's order), the thread block and the stack.
    pub fn boot(slots: &[u32], c: &mut Cpu) {
        for (i, slot) in slots.iter().enumerate() {
            c.mem.poke(*slot, &(IMPORTS + 4 * i as u32).to_le_bytes());
        }
        let mut teb = vec![0u8; 0x1000];
        teb[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        teb[4..8].copy_from_slice(&STACK_TOP.to_le_bytes());
        teb[8..12].copy_from_slice(&(STACK_TOP - STACK_SIZE).to_le_bytes());
        teb[0x18..0x1c].copy_from_slice(&TEB.to_le_bytes());
        c.mem.poke(TEB, &teb);
        c.set_reg(FS_OFFSET, TEB);
        let sp = STACK_TOP - 16;
        c.mem.poke(sp, &SENTINEL.to_le_bytes());
        c.set_reg(ESP, sp);
    }

    /// A block of `size` bytes from the heap, 16-byte aligned. Nothing is ever freed.
    pub fn alloc(&mut self, size: u32) -> u32 {
        let at = (self.heap + 15) & !15;
        self.heap = at + size.max(1);
        self.sizes.insert(at, size);
        at
    }

    /// A block for `HeapAlloc`: the last freed block of the same rounded size, zeroed as fresh heap
    /// is, or new heap.
    pub fn heap_alloc(&mut self, c: &mut Cpu, size: u32) -> u32 {
        match self.free.get_mut(&rounded(size)).and_then(Vec::pop) {
            Some(at) => {
                c.mem.poke(at, &vec![0; rounded(size) as usize]);
                self.sizes.insert(at, size);
                at
            }
            None => self.alloc(rounded(size)),
        }
    }

    /// `HeapFree`: whether `at` was a block the heap handed out.
    pub fn heap_free(&mut self, at: u32) -> bool {
        let Some(size) = self.sizes.remove(&at) else { return false };
        self.free.entry(rounded(size)).or_default().push(at);
        true
    }

    /// `HeapReAlloc`: the block resized in place when its rounded size holds `size`, else a new
    /// block with the old bytes, unless `in_place` forbids moving it (0 then).
    pub fn heap_realloc(&mut self, c: &mut Cpu, at: u32, size: u32, in_place: bool) -> u32 {
        let Some(&old) = self.sizes.get(&at) else { return 0 };
        if size <= rounded(old) {
            if size < old {
                c.mem.poke(at + size, &vec![0; (old - size) as usize]);
            }
            self.sizes.insert(at, size);
            return at;
        }
        if in_place {
            return 0;
        }
        let new = self.heap_alloc(c, size);
        let bytes = c.mem.bytes(at, old as usize);
        c.mem.poke(new, &bytes);
        self.heap_free(at);
        new
    }

    /// Fresh pages for `size` bytes, as `VirtualAlloc` gives them.
    pub fn alloc_pages(&mut self, size: u32) -> u32 {
        let at = (self.heap + 0xffff) & !0xffff;
        self.heap = at + ((size + 0xfff) & !0xfff).max(0x1000);
        at
    }

    /// Writes `text` and its zero at `buf`, at most `cap` bytes with the zero; the length
    /// written without the zero.
    pub fn put_str(&mut self, c: &mut Cpu, buf: u32, cap: u32, text: &str) -> u32 {
        self.put_bytes(c, buf, cap, text.as_bytes())
    }

    /// [`Win32::put_str`] for text in the game's code page.
    pub fn put_bytes(&mut self, c: &mut Cpu, buf: u32, cap: u32, text: &[u8]) -> u32 {
        let bytes = &text[..text.len().min(cap.saturating_sub(1) as usize)];
        c.mem.poke(buf, bytes);
        c.mem.poke(buf + bytes.len() as u32, &[0]);
        bytes.len() as u32
    }

    /// A string in host memory that lives as long as the game, made once per text.
    pub fn static_str(&mut self, c: &mut Cpu, text: &str) -> u32 {
        if let Some(&at) = self.statics.get(text) {
            return at;
        }
        let at = self.alloc(text.len() as u32 + 1);
        c.mem.poke(at, text.as_bytes());
        self.statics.insert(text.to_string(), at);
        at
    }

    fn run(&mut self, c: &mut Cpu, dll: &str, name: &str, frame: Frame) {
        if self.trace {
            eprintln!("host {dll}!{name} from {:#x}", c.u32_at(c.reg(ESP)));
        }
        if self.backtrace.iter().any(|b| b == name) {
            eprintln!("host: {name} called from {}", game_stack(self.game.names));
        }
        let done = self.create(c, name, frame)
            || kernel32::run(self, c, name, frame)
            || files::run(self, c, name, frame)
            || user32::run(self, c, name, frame)
            || gdi32::run(self, c, name, frame)
            || winmm::run(self, c, name, frame)
            || (dll.eq_ignore_ascii_case("mss32.dll") && miles::run(self, c, name, frame))
            || misc::run(self, c, dll, name, frame);
        if !done {
            panic!("{dll}!{name} is not implemented");
        }
    }

    /// The imports that make a host object: DirectDrawCreate, DirectInputCreateA, and
    /// DirectDrawEnumerateA, which finds one driver, the primary display's.
    fn create(&mut self, c: &mut Cpu, name: &str, f: Frame) -> bool {
        match name {
            "DirectDrawEnumerateA" => {
                let (callback, context) = (c.arg(f, 0), c.arg(f, 1));
                let (description, driver) = (self.static_str(c, "Primary Display Driver"), self.static_str(c, "display"));
                self.call_each(c, f, 2, callback, &[vec![0, description, driver, context]], 0);
            }
            "DirectDrawCreate" => {
                let out = c.arg(f, 1);
                let dd = self.new_object(c, com::Iface::DirectDraw, 0);
                c.set_u32(out, dd);
                c.ret(f, Some(0), 3);
            }
            "DirectSoundCreate" => {
                let out = c.arg(f, 1);
                self.direct_sound_create(c, out);
                c.ret(f, Some(0), 3);
            }
            "DirectInputCreateA" => {
                let out = c.arg(f, 2);
                let di = self.new_object(c, com::Iface::DirectInput, 0);
                c.set_u32(out, di);
                c.ret(f, Some(0), 4);
            }
            _ => return false,
        }
        true
    }

    /// The end of a frame: the primary surface goes to the window.
    fn present(&mut self, c: &mut Cpu) {
        self.clock.flush();
        self.inputs.flush();
        self.presents += 1;
        let frames = self.presents;
        if self.trace || frames.is_power_of_two() {
            eprintln!("host: frame {frames}");
        }
        if frames.is_multiple_of(256) {
            let now = Instant::now();
            if let Some(last) = self.rate_from.replace(now) {
                eprintln!("host: frames {}..{frames} at {:.1} per second", frames - 256, 256.0 / (now - last).as_secs_f64());
            }
        }
        self.watch.frame(c, frames);
        (self.game.present)(c, frames);
        self.record_sound();
        let Some(frame) = self.dd.screen(c) else { return };
        if let Some(link) = &mut self.link {
            link.present(frame);
        }
    }

    /// Takes the window's input into the state the game reads.
    pub fn sync_input(&mut self) {
        let Some(link) = &self.link else { return };
        self.polls += 1;
        if !self.inputs.replaying() && link.input().quit {
            self.clock.flush();
            self.inputs.flush();
            std::process::exit(0);
        }
        let live = || {
            let mut input = link.input();
            let (keys, scans) = input.held();
            session::Snapshot { cursor: input.cursor, moved: std::mem::take(&mut input.moved), buttons: input.buttons, keys, scans, messages: std::mem::take(&mut input.messages) }
        };
        let Some(input) = self.inputs.take(self.polls, live) else { return };
        self.user.cursor = input.cursor;
        for (msg, wparam, lparam) in input.messages {
            self.user.queue.push_back(user32::Message { msg, wparam, lparam });
        }
        self.input.moved.0 += input.moved.0;
        self.input.moved.1 += input.moved.1;
        self.input.moved.2 += input.moved.2;
        self.input.buttons = input.buttons;
        self.user.keys = [0; 256];
        for &k in &input.keys {
            self.user.keys[k as usize] = 0x80;
        }
        let mut scans = [0u8; 256];
        for &k in &input.scans {
            scans[k as usize] = 0x80;
        }
        // Each change of a key is an event for the keyboard's buffer (GetDeviceData).
        for (k, (&was, &now)) in self.input.scans.iter().zip(&scans).enumerate() {
            if was != now {
                self.input.events.push_back((k as u8, now != 0));
            }
        }
        self.input.scans = scans;
    }
}

/// The game functions on the Rust stack, innermost first, as the lifted functions' names give
/// them (`f_<address>`, or `b_<address>` for a body several entries share), with the names
/// `names` ([`Game::names`]) gives them.
pub(crate) fn game_stack(names: &str) -> String {
    let trace = std::backtrace::Backtrace::force_capture().to_string();
    let mut frames: Vec<&str> = Vec::new();
    for word in trace.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_') {
        if let Some(addr) = word.strip_prefix("f_").or_else(|| word.strip_prefix("b_"))
            && addr.len() == 6
            && addr.chars().all(|ch| ch.is_ascii_hexdigit())
            && frames.last() != Some(&addr)
        {
            frames.push(addr);
        }
    }
    frames.iter().map(|a| name_of(names, a).map_or_else(|| format!("0x{a}"), |name| format!("{name} (0x{a})"))).collect::<Vec<_>>().join(" < ")
}

/// The name `names` gives the function at `addr`, six hex digits without 0x.
fn name_of<'a>(names: &'a str, addr: &str) -> Option<&'a str> {
    names.lines().skip(1).find_map(|line| {
        let mut columns = line.split('\t');
        (columns.next()?.trim_start_matches("0x") == addr).then(|| columns.next()).flatten()
    })
}

impl Host for Win32 {
    fn call(&mut self, c: &mut Cpu, addr: u32, frame: Frame) -> Option<u32> {
        if addr >= com::METHODS {
            self.com(c, addr, frame);
            return self.next.take();
        }
        let index = ((addr - IMPORTS) / 4) as usize;
        let Some((dll, name)) = self.imports.get(index).cloned() else { panic!("a call to host address {addr:#x}, which nothing is at") };
        self.run(c, &dll, &name, frame);
        self.next.take()
    }

    fn import(&mut self, c: &mut Cpu, name: &str, frame: Frame) -> Option<u32> {
        let dll = self.imports.iter().find(|(_, n)| n == name).map_or_else(String::new, |(d, _)| d.clone());
        self.run(c, &dll, name, frame);
        self.next.take()
    }
}

/// Runs `game` in a window, or headless with `TT_HEADLESS`: `functions` are the lifted functions
/// by address. The game's files are under `TT_GAME` (default game), its executable among them
/// unless [`Game::image`] or `TT_EXE` names another. `TT_SHOTS=frame:path.png,...` runs offscreen
/// and saves those frames.
pub fn run(functions: Vec<(u32, recore_machine::Lifted)>, game: &'static Game) {
    let dir = PathBuf::from(std::env::var_os("TT_GAME").unwrap_or_else(|| "game".into()));
    let exe = std::env::var_os("TT_EXE").map(PathBuf::from).or_else(|| game.image.map(PathBuf::from)).unwrap_or_else(|| dir.join(game.exe));
    let mut image = Image::load(&exe).unwrap_or_else(|e| panic!("{e:#}"));
    (game.prepare)(&mut image);
    let (entry, slots) = (image.entry, image.imports.iter().map(|i| i.slot).collect::<Vec<u32>>());
    recore_machine::install(functions.into_iter().chain(callback::NATIVE.iter().copied()).collect(), image.code());
    let bytes = std::fs::read(&exe).unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    let mut host = Win32::new(game, dir, &image, &bytes);
    let start = move |host: Win32| {
        let mut c = Cpu::new(Some(image), None, Box::new(host), std::env::var_os("TT_PAGED").is_none()).expect("memory");
        Win32::boot(&slots, &mut c);
        recore_machine::dispatch(&mut c, entry);
        eprintln!("the entry point returned EAX = {:#x}", c.reg(EAX));
    };
    if std::env::var_os("TT_HEADLESS").is_some() {
        recore_window::on_game_stack(move || start(host));
        return;
    }
    let shots: Vec<(u64, PathBuf)> = std::env::var("TT_SHOTS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.split_once(':'))
        .filter_map(|(n, p)| Some((n.parse().ok()?, PathBuf::from(p))))
        .collect();
    if !shots.is_empty() {
        host.link = Some(recore_window::Link::offscreen(shots));
        recore_window::on_game_stack(move || start(host));
    } else if let Err(e) = recore_window::run(game.title, move |link| {
        host.link = Some(link);
        start(host);
    }) {
        eprintln!("the window failed: {e:#}");
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::Disc;

    #[test]
    fn an_empty_disc_hides_only_the_cd_drive() {
        assert!(Disc::Empty.hides("d:\\GAME.EXE"));
        assert!(!Disc::Empty.hides("C:\\GAME\\GAME.EXE"));
        assert!(!Disc::Empty.hides("DATA\\a.bin"));
        assert!(!Disc::Game.hides("D:\\GAME.EXE"));
    }
}
