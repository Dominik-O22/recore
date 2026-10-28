//! Where the lifted game's frames go and its input comes from. The game presents one [`Frame`] per
//! flip, the finished picture, through its [`Link`], and takes [`Input`] from it. A link leads to
//! a native window (window.rs), to PNG files (TT_SHOTS), or, built for wasm, to the web page the
//! game's worker runs in (page.rs).
//!
//! The game draws its own pointer, so the system's is hidden over the picture. While the game
//! holds the mouse as an exclusive DirectInput device ([`Link::capture`]), as it does in a level,
//! the pointer is locked and the mouse's motion is reported as relative motion in game pixels,
//! as DirectInput reports it, with no edge to stop it.

mod keys;
#[cfg(target_family = "wasm")]
mod page;
#[cfg(not(target_family = "wasm"))]
mod window;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(not(target_family = "wasm"))]
pub use window::run;
#[cfg(target_family = "wasm")]
pub use page::run;

/// A picture of the game's screen: rows of 0x00RRGGBB pixels.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
}

/// The input the game has not taken yet, in game pixels.
#[derive(Default)]
pub struct Input {
    pub cursor: (i32, i32),
    /// Relative motion since the game last took it: x, y and the wheel.
    pub moved: (i32, i32, i32),
    pub buttons: [bool; 3],
    /// Virtual keys held.
    pub keys: Vec<u8>,
    /// DirectInput scan codes held.
    pub scans: Vec<u8>,
    /// Window messages: message, wParam, lParam.
    pub messages: Vec<(u32, u32, u32)>,
    pub quit: bool,
    /// Virtual keys pressed since the game last took the held keys ([`Input::held`]), and keys
    /// released before it did, still held until it has.
    fresh: Vec<u8>,
    released: Vec<(u8, u8)>,
}

impl Input {
    fn move_to(&mut self, x: i32, y: i32) {
        self.cursor = (x, y);
        self.messages.push((0x200, 0, (y as u32 & 0xffff) << 16 | (x as u32 & 0xffff)));
    }

    /// Button `index` (left, right, middle) pressed or released where the pointer is.
    fn button(&mut self, index: usize, down: bool) {
        self.buttons[index] = down;
        let (x, y) = self.cursor;
        self.messages.push(([0x201, 0x204, 0x207][index] + u32::from(!down), 0, (y as u32 & 0xffff) << 16 | (x as u32 & 0xffff)));
    }

    /// A key pressed or released: `code` names its position, `typed` is the character it types.
    /// A letter goes by the label the layout gives its key, so the key marked Y is Y on a QWERTZ
    /// keyboard too, where its position is US Z; DirectInput reported positions, and the game
    /// asks Y/N. Other keys go by position.
    fn key(&mut self, code: &str, typed: Option<char>, down: bool) {
        let by_label = typed.filter(char::is_ascii_alphabetic).and_then(|c| keys::by_name(c.encode_utf8(&mut [0; 4])));
        let Some((vk, scan)) = by_label.or_else(|| keys::by_code(code)) else { return };
        self.released.retain(|&(k, _)| k != vk);
        if down {
            self.keys.retain(|&k| k != vk);
            self.scans.retain(|&k| k != scan);
            self.keys.push(vk);
            self.scans.push(scan);
            self.fresh.push(vk);
        } else if self.fresh.contains(&vk) {
            self.released.push((vk, scan));
        } else {
            self.keys.retain(|&k| k != vk);
            self.scans.retain(|&k| k != scan);
        }
        let lparam = u32::from(scan) << 16 | 1 | if down { 0 } else { 0xc000_0000 };
        self.messages.push((if down { 0x100 } else { 0x101 }, u32::from(vk), lparam));
        if let (true, Some(c)) = (down, typed.filter(|c| (*c as u32) < 256)) {
            self.messages.push((0x102, c as u32, lparam));
        }
    }

    /// The virtual keys and scan codes held, for the game to take. A key pressed and released
    /// since it last took them counts as held this once, so the game sees even a tap shorter
    /// than its polls.
    pub fn held(&mut self) -> (Vec<u8>, Vec<u8>) {
        let held = (self.keys.clone(), self.scans.clone());
        self.fresh.clear();
        for (vk, scan) in std::mem::take(&mut self.released) {
            self.keys.retain(|&k| k != vk);
            self.scans.retain(|&k| k != scan);
        }
        held
    }
}

/// What the game holds of where its frames go.
pub struct Link {
    out: Out,
    input: Arc<Mutex<Input>>,
    /// TT_INPUT's events, applied as the game presents the frame they name, so a script lands at
    /// the same point of the game's run every time.
    script: Vec<(u64, Event)>,
    presented: u64,
}

enum Out {
    #[cfg(not(target_family = "wasm"))]
    Window(window::Sender),
    /// TT_SHOTS: the frames numbered (from 1) saved as PNGs; the game ends after the last.
    Shots(Vec<(u64, PathBuf)>),
    #[cfg(target_family = "wasm")]
    Page(page::Page),
}

impl Link {
    fn new(out: Out, input: Arc<Mutex<Input>>) -> Link {
        Link { out, input, script: script(&std::env::var("TT_INPUT").unwrap_or_default()), presented: 0 }
    }

    /// A link that saves the frames numbered in `shots` and ends the game after the last.
    pub fn offscreen(shots: Vec<(u64, PathBuf)>) -> Link {
        Link::new(Out::Shots(shots), Arc::default())
    }

    /// The input the game has not taken yet.
    pub fn input(&self) -> MutexGuard<'_, Input> {
        #[cfg_attr(not(target_family = "wasm"), allow(unused_mut))]
        let mut input = self.input.lock().expect("input");
        #[cfg(target_family = "wasm")]
        if let Out::Page(page) = &self.out {
            page.take_input(&mut input);
        }
        input
    }

    /// Hands a frame on: to the window, which the game waits for while it draws the last one, to
    /// a file, or to the page.
    pub fn present(&mut self, frame: Frame) {
        self.presented += 1;
        for (_, event) in self.script.iter().filter(|(at, _)| *at == self.presented) {
            event.apply(&mut self.input.lock().expect("input"));
        }
        match &mut self.out {
            #[cfg(not(target_family = "wasm"))]
            Out::Window(window) => window.present(frame),
            Out::Shots(shots) => {
                if let Some((_, path)) = shots.iter().find(|s| s.0 == self.presented) {
                    save_png(path, &frame).unwrap_or_else(|e| panic!("{}: {e:#}", path.display()));
                    eprintln!("window: frame {} saved to {}", self.presented, path.display());
                }
                if shots.iter().all(|s| s.0 <= self.presented) {
                    std::process::exit(0);
                }
            }
            #[cfg(target_family = "wasm")]
            Out::Page(page) => page.present(&frame),
        }
    }

    /// Whether the game holds the mouse: the pointer is locked and only its motion counts.
    pub fn capture(&self, on: bool) {
        match &self.out {
            #[cfg(not(target_family = "wasm"))]
            Out::Window(window) => window.capture(on),
            Out::Shots(_) => {}
            #[cfg(target_family = "wasm")]
            Out::Page(_) => page::capture(on),
        }
    }
}

fn save_png(path: &std::path::Path, frame: &Frame) -> anyhow::Result<()> {
    let rgba: Vec<u8> = frame.pixels.iter().flat_map(|p| [(p >> 16) as u8, (p >> 8) as u8, *p as u8, 255]).collect();
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(std::fs::File::create(path)?), frame.width, frame.height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header()?.write_image_data(&rgba)?;
    Ok(())
}

/// Runs `game` to its end on a stack deep enough for the lifted code: a thread of its own
/// natively; wasm's one stack is sized when the game's wasm build links it.
pub fn on_game_stack(game: impl FnOnce() + Send + 'static) {
    #[cfg(not(target_family = "wasm"))]
    std::thread::Builder::new().name("game".into()).stack_size(1 << 30).spawn(game).expect("the game thread").join().ok();
    #[cfg(target_family = "wasm")]
    game();
}

/// A scripted input event, applied before a numbered frame.
enum Event {
    Move(i32, i32),
    /// Relative motion, as the locked pointer reports it.
    Motion(i32, i32),
    Button(usize, bool),
    Key(&'static str, bool),
}

impl Event {
    fn apply(&self, input: &mut Input) {
        match *self {
            Event::Move(x, y) => input.move_to(x, y),
            Event::Motion(dx, dy) => {
                input.moved.0 += dx;
                input.moved.1 += dy;
            }
            Event::Button(index, down) => input.button(index, down),
            Event::Key(code, down) => input.key(code, None, down),
        }
    }
}

/// `frame:move x y`, `frame:motion dx dy`, `frame:click x y`, `frame:rclick x y`,
/// `frame:press`/`frame:release` (left button, `rpress`/`rrelease` for the right), and
/// `frame:key <name>` (keys::by_name), separated by `;`. A click presses at the frame and
/// releases three frames later.
fn script(text: &str) -> Vec<(u64, Event)> {
    let mut out = Vec::new();
    for item in text.split(';').filter(|s| !s.trim().is_empty()) {
        let Some((frame, rest)) = item.split_once(':') else { continue };
        let Ok(frame) = frame.trim().parse::<u64>() else { continue };
        let words: Vec<&str> = rest.split_whitespace().collect();
        let xy = || (words.get(1).and_then(|v| v.parse().ok()).unwrap_or(0), words.get(2).and_then(|v| v.parse().ok()).unwrap_or(0));
        match words.first().copied() {
            Some("move") => out.push((frame, Event::Move(xy().0, xy().1))),
            Some("motion") => out.push((frame, Event::Motion(xy().0, xy().1))),
            Some(b @ ("click" | "rclick")) => {
                let index = usize::from(b == "rclick");
                out.push((frame, Event::Move(xy().0, xy().1)));
                out.push((frame + 1, Event::Button(index, true)));
                out.push((frame + 4, Event::Button(index, false)));
            }
            Some(b @ ("press" | "release" | "rpress" | "rrelease")) => out.push((frame, Event::Button(usize::from(b.starts_with('r')), !b.ends_with("release")))),
            Some("key") => {
                if let Some(code) = words.get(1).and_then(|name| keys::code_by_name(name)) {
                    out.push((frame, Event::Key(code, true)));
                    out.push((frame + 3, Event::Key(code, false)));
                }
            }
            _ => {}
        }
    }
    out
}
