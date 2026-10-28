//! The CD's music, which the game plays through MCI command strings (`mciSendStringA`) in the
//! time format tmsf: a position is a track, then minutes, seconds and frames (75 a second) into
//! it. The audio tracks are Ogg Vorbis files of 44100 Hz stereo, trackNN.ogg in TT_CD (default
//! cd, which scripts/cd_tracks.py writes from the disc image); track 1 is the game's data. Without
//! them the game finds no CD audio device and plays no music. A track is decoded when it first
//! plays, which takes about a millisecond for each second of music.
//!
//! As with DirectSound, where the music is comes from the game's clock and the mixer only plays.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use recore_machine::{Cpu, Frame};
use recore_audio::{Command, Sound, Voice};

use crate::Win32;

/// The mixer's voice for the CD.
const VOICE: u32 = 0x7fff_0000;
/// MCIERR_HARDWARE: no CD audio device; MCIERR_UNRECOGNIZED_COMMAND.
const NO_DEVICE: u32 = 262;
const UNRECOGNIZED: u32 = 261;

/// A place on the disc: a track and milliseconds into it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Place {
    track: u32,
    ms: u64,
}

#[derive(Default)]
pub struct Cd {
    /// Each audio track's length in milliseconds, once the device is open.
    lengths: BTreeMap<u32, u64>,
    /// Tracks decoded so far.
    tracks: BTreeMap<u32, Arc<Sound>>,
    /// What plays: from where, how long, and when it started on the game's clock.
    playing: Option<(Place, u64, u64)>,
}

impl Cd {
    fn dir() -> PathBuf {
        PathBuf::from(std::env::var_os("TT_CD").unwrap_or_else(|| "cd".into()))
    }

    fn path(track: u32) -> PathBuf {
        Cd::dir().join(format!("track{track:02}.ogg"))
    }

    /// The audio tracks there are, each with its length.
    fn open(&mut self) -> bool {
        if self.lengths.is_empty() {
            for track in 2..100 {
                let Some(frames) = std::fs::read(Cd::path(track)).ok().and_then(|bytes| ogg_frames(&bytes)) else { continue };
                self.lengths.insert(track, frames * 1000 / 44100);
            }
        }
        !self.lengths.is_empty()
    }

    fn last(&self) -> u32 {
        self.lengths.keys().next_back().copied().unwrap_or(1)
    }

    fn length(&self, track: u32) -> u64 {
        self.lengths.get(&track).copied().unwrap_or(0)
    }

    /// The place `ms` after `from`, across tracks; past the last track's end, its end.
    fn after(&self, from: Place, ms: u64) -> Place {
        let mut at = Place { track: from.track, ms: from.ms + ms };
        while at.ms >= self.length(at.track) && at.track < self.last() {
            at = Place { track: at.track + 1, ms: at.ms - self.length(at.track) };
        }
        Place { ms: at.ms.min(self.length(at.track)), ..at }
    }

    /// Milliseconds from `from` to `to`.
    fn span(&self, from: Place, to: Place) -> u64 {
        let before = |p: Place| (2..p.track).map(|t| self.length(t)).sum::<u64>() + p.ms;
        before(to).saturating_sub(before(from))
    }

    fn track(&mut self, track: u32) -> Option<Arc<Sound>> {
        if let Some(sound) = self.tracks.get(&track) {
            return Some(sound.clone());
        }
        let file = std::fs::File::open(Cd::path(track)).ok()?;
        let mut reader = lewton::inside_ogg::OggStreamReader::new(std::io::BufReader::new(file)).ok()?;
        let mut samples = Vec::new();
        while let Some(packet) = reader.read_dec_packet_itl().ok()? {
            samples.extend(packet);
        }
        let sound = Arc::new(Sound { channels: u16::from(reader.ident_hdr.audio_channels), samples });
        self.tracks.insert(track, sound.clone());
        Some(sound)
    }

    /// The music from `from` for `ms`: one track as it is, or the frames of each track on the way
    /// joined.
    fn sound(&mut self, from: Place, ms: u64) -> Option<Arc<Sound>> {
        if from.ms == 0 && ms == self.length(from.track) {
            return self.track(from.track);
        }
        let frame = |ms: u64| (ms * 44100 / 1000) as usize * 2;
        let (mut samples, mut at, mut left) = (Vec::new(), from, ms);
        while left > 0 && at.track <= self.last() {
            let take = left.min(self.length(at.track) - at.ms.min(self.length(at.track)));
            let track = self.track(at.track)?;
            let (start, end) = (frame(at.ms).min(track.samples.len()), frame(at.ms + take).min(track.samples.len()));
            samples.extend_from_slice(&track.samples[start..end]);
            left -= take;
            at = Place { track: at.track + 1, ms: 0 };
        }
        Some(Arc::new(Sound { channels: 2, samples }))
    }

    /// Where the music is at `now`, and whether it still plays.
    fn position(&self, now: u64) -> (Place, bool) {
        match self.playing {
            Some((from, ms, started)) => {
                let elapsed = (now - started) / 1000;
                (self.after(from, elapsed.min(ms)), elapsed < ms)
            }
            None => (Place { track: 2, ms: 0 }, false),
        }
    }
}

/// The frames of an Ogg stream: the granule position of its last page, which for Vorbis counts
/// the frames up to that page's end.
fn ogg_frames(bytes: &[u8]) -> Option<u64> {
    let last = bytes.windows(4).rposition(|w| w == b"OggS")?;
    Some(u64::from_le_bytes(bytes.get(last + 6..last + 14)?.try_into().ok()?))
}

/// A tmsf place: `t`, or `t:m:s:f` with the parts after the track optional.
fn place(text: &str) -> Option<Place> {
    let parts: Vec<u64> = text.split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let part = |i: usize| parts.get(i).copied().unwrap_or(0);
    Some(Place { track: part(0) as u32, ms: (part(1) * 60 + part(2)) * 1000 + part(3) * 1000 / 75 })
}

/// `mm:ss:ff`.
fn mmssff(ms: u64) -> String {
    format!("{:02}:{:02}:{:02}", ms / 60_000, ms / 1000 % 60, ms % 1000 * 75 / 1000)
}

/// `mciSendStringA(command, answer, answer size, window)` for the device `cdaudio`.
pub fn send(w: &mut Win32, c: &mut Cpu, f: Frame) {
    let (command, answer, size) = (c.arg(f, 0), c.arg(f, 1), c.arg(f, 2));
    let command = c.mem.c_str(command).to_ascii_lowercase();
    let words: Vec<&str> = command.split_whitespace().filter(|&w| w != "wait" && w != "notify").collect();
    let now = w.clock.micros();
    let reply = |w: &mut Win32, c: &mut Cpu, text: &str| {
        if answer != 0 && size != 0 {
            w.put_str(c, answer, size, text);
        }
        0
    };
    let result = match words.as_slice() {
        [_, device, ..] if *device != "cdaudio" => UNRECOGNIZED,
        ["open", ..] => if w.cd.open() { 0 } else { NO_DEVICE },
        _ if w.cd.lengths.is_empty() => NO_DEVICE,
        ["set", ..] => 0,
        ["status", _, "number", "of", "tracks"] => {
            let tracks = w.cd.last().to_string();
            reply(w, c, &tracks)
        }
        ["status", _, "length", "track", n] => {
            let length = mmssff(w.cd.length(n.parse().unwrap_or(0)));
            reply(w, c, &length)
        }
        ["status", _, "position"] => {
            let (at, _) = w.cd.position(now);
            let text = format!("{:02}:{}", at.track, mmssff(at.ms));
            reply(w, c, &text)
        }
        ["status", _, "mode"] => {
            let (_, playing) = w.cd.position(now);
            reply(w, c, if playing { "playing" } else { "stopped" })
        }
        ["play", _, rest @ ..] => {
            let find = |key: &str| rest.iter().position(|w| *w == key).and_then(|i| rest.get(i + 1)).and_then(|t| place(t));
            let end = Place { track: w.cd.last(), ms: w.cd.length(w.cd.last()) };
            let from = find("from").unwrap_or_else(|| w.cd.position(now).0);
            let to = find("to").unwrap_or(end);
            let ms = w.cd.span(from, to);
            match w.cd.sound(from, ms) {
                Some(sound) => {
                    w.cd.playing = Some((from, ms, now));
                    w.send(Command::Play(VOICE, sound, Voice { rate: 44100, volume: 1.0, pan: 0.0, loops: 1 }));
                    0
                }
                None => NO_DEVICE,
            }
        }
        ["stop" | "pause" | "close", ..] => {
            w.cd.playing = None;
            w.send(Command::Stop(VOICE));
            0
        }
        _ => {
            eprintln!("host: MCI {command:?} is not understood");
            UNRECOGNIZED
        }
    };
    if w.trace {
        eprintln!("host: MCI {command:?} -> {result}");
    }
    c.ret(f, Some(result), 4);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cd() -> Cd {
        Cd { lengths: [(2, 10_000), (3, 5_000)].into_iter().collect(), ..Cd::default() }
    }

    #[test]
    fn places_are_read_and_written_in_tmsf() {
        assert_eq!(place("3"), Some(Place { track: 3, ms: 0 }));
        assert_eq!(place("02:01:30:15"), Some(Place { track: 2, ms: 90_200 }));
        assert_eq!(mmssff(90_200), "01:30:15");
    }

    #[test]
    fn a_span_and_a_position_run_across_tracks() {
        let cd = cd();
        let (from, to) = (Place { track: 2, ms: 8_000 }, Place { track: 3, ms: 1_000 });
        assert_eq!(cd.span(from, to), 3_000);
        assert_eq!(cd.after(from, 2_500), Place { track: 3, ms: 500 });
        assert_eq!(cd.after(from, 60_000), Place { track: 3, ms: 5_000 });
    }
}
