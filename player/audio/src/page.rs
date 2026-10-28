//! The web page's audio worklet, which plays stereo frames from a ring the
//! game's worker fills: the mixer runs here, on the game's thread, and [`Audio::pump`] keeps the
//! ring a little ahead of what the worklet has played.

use crate::{Command, Mixer};

#[link(wasm_import_module = "tt")]
unsafe extern "C" {
    /// The worklet's frames a second, or 0 when the page has no sound.
    fn audio_rate() -> u32;
    /// Frames in the ring not played yet.
    fn audio_queued() -> u32;
    /// Adds `frames` stereo frames, interleaved, to the ring.
    fn audio_write(samples: *const f32, frames: u32);
}

/// How far ahead the ring is kept. The game pumps at each frame, 13 to 20 a second.
const AHEAD_SECONDS: f32 = 0.15;

pub struct Audio {
    mixer: Mixer,
    rate: u32,
    mixed: Vec<f32>,
}

impl Audio {
    pub fn open() -> Option<Audio> {
        // SAFETY: a plain call into the page.
        let rate = unsafe { audio_rate() };
        (rate != 0).then(|| Audio { mixer: Mixer::new(rate, 2), rate, mixed: Vec::new() })
    }

    pub fn send(&mut self, command: Command) {
        self.mixer.command(command);
    }

    /// Mixes what plays next into the ring, up to [`AHEAD_SECONDS`] ahead.
    pub fn pump(&mut self) {
        let ahead = (self.rate as f32 * AHEAD_SECONDS) as u32;
        // SAFETY: a plain call into the page.
        let queued = unsafe { audio_queued() };
        let Some(frames) = ahead.checked_sub(queued).filter(|&f| f > 0) else { return };
        self.mixed.clear();
        self.mixed.resize(frames as usize * 2, 0.0);
        self.mixer.mix(&mut self.mixed);
        // SAFETY: `mixed` holds `frames` stereo frames, read before the call returns.
        unsafe { audio_write(self.mixed.as_ptr(), frames) };
    }
}
