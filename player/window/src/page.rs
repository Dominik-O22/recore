//! The web page, for a game built for wasm and run in a page's worker (web/). The worker supplies
//! the imports of module `tt`: frames go to its canvas, and input comes from the page as lines of
//! text, the page's events already in game pixels.

use crate::{Frame, Input, Link, Out};

#[link(wasm_import_module = "tt")]
unsafe extern "C" {
    /// Draws `width` x `height` RGBA pixels.
    #[link_name = "present"]
    fn present_rgba(rgba: *const u8, width: u32, height: u32);
    /// Whether the game holds the mouse, so the page locks the pointer on the next click.
    #[link_name = "capture"]
    fn capture_mouse(on: u32);
    /// Copies the page's events since the last call into `buf`, at most `cap` bytes of whole
    /// lines; answers how many bytes.
    #[link_name = "input"]
    fn take_events(buf: *mut u8, cap: u32) -> u32;
}

pub struct Page {
    rgba: Vec<u8>,
}

impl Page {
    pub fn present(&mut self, frame: &Frame) {
        self.rgba.clear();
        self.rgba.extend(frame.pixels.iter().flat_map(|p| [(p >> 16) as u8, (p >> 8) as u8, *p as u8, 255]));
        // SAFETY: the pixels are `width` x `height` x 4 bytes, read before the call returns.
        unsafe { present_rgba(self.rgba.as_ptr(), frame.width, frame.height) };
    }

    /// Applies the page's events to `input`: `move x y`, `motion dx dy`, `button index 0|1`,
    /// `wheel delta` and `key 0|1 <KeyboardEvent.code> <code point typed, or 0>`.
    pub fn take_input(&self, input: &mut Input) {
        let mut buf = vec![0u8; 1 << 16];
        // SAFETY: the page writes at most `cap` bytes into `buf`.
        let len = unsafe { take_events(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        for line in String::from_utf8_lossy(&buf[..len.min(buf.len())]).lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            let int = |i: usize| words.get(i).and_then(|w| w.parse::<i32>().ok()).unwrap_or(0);
            match words.first().copied() {
                Some("move") => input.move_to(int(1), int(2)),
                Some("motion") => {
                    input.moved.0 += int(1);
                    input.moved.1 += int(2);
                }
                Some("button") => input.button(int(1).clamp(0, 2) as usize, int(2) != 0),
                Some("wheel") => input.moved.2 += int(1),
                Some("key") => input.key(words.get(2).copied().unwrap_or(""), char::from_u32(int(3) as u32).filter(|c| *c != '\0'), int(1) != 0),
                _ => {}
            }
        }
    }
}

pub fn capture(on: bool) {
    // SAFETY: a plain call into the page.
    unsafe { capture_mouse(u32::from(on)) };
}

/// Runs `game` with frames going to the page, on this thread: the worker's.
pub fn run(_title: &str, game: impl FnOnce(Link) + Send + 'static) -> anyhow::Result<()> {
    game(Link::new(Out::Page(Page { rgba: Vec::new() }), Default::default()));
    Ok(())
}
