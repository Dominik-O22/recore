//! Miles Sound System (mss32.dll): one digital driver, samples the game fills from its memory, and
//! streams of WAV files.
//!
//! When a sample ends is decided here, by the game's clock, from its length, rate and loop
//! count, so a scripted run is as deterministic with sound as without. The mixer (recore-audio) only
//! plays: on the output device in a window, into the WAV file TT_AUDIO_WAV names as the game's
//! clock moves, or nowhere in other windowless runs, and nowhere with TT_MUTE. CD music through
//! Miles (the AIL_redbook functions) finds no CD and is left to misc.rs, which answers 0 to every
//! Miles function this file does not have.

use std::{collections::HashMap, sync::Arc};

use recore_machine::{Cpu, Frame};
use recore_audio::{Audio, Command, Recorder, Sound, Voice};

use crate::Win32;

/// SMP_DONE and SMP_PLAYING, as AIL_sample_status and AIL_stream_status answer.
const DONE: u32 = 2;
const PLAYING: u32 = 4;
/// The one digital driver, and the first sample and stream handles.
const DRIVER: u32 = 0x6000_0001;
const SAMPLES: u32 = 0x6000_1000;
const STREAMS: u32 = 0x6000_2000;

/// A sample or a stream, as the game set it, and where its playing is.
struct Channel {
    sound: Option<Arc<Sound>>,
    /// A sample's data in game memory, its format (DIG_F_*) and flags (DIG_PCM_SIGN 1).
    address: u32,
    len: u32,
    format: u32,
    signed: bool,
    rate: u32,
    /// Miles' 0 to 127, and pan 0 left to 127 right.
    volume: u32,
    pan: u32,
    /// Times to play, 0 for ever.
    loops: u32,
    /// When it started, in the game's microseconds, moved on by pauses; none when not playing.
    started: Option<u64>,
    paused_at: Option<u64>,
}

impl Channel {
    fn new() -> Channel {
        Channel { sound: None, address: 0, len: 0, format: 1, signed: true, rate: 22050, volume: 127, pan: 64, loops: 1, started: None, paused_at: None }
    }

    fn voice(&self) -> Voice {
        Voice {
            rate: self.rate,
            volume: self.volume.min(127) as f32 / 127.0,
            pan: (self.pan.min(127) as f32 - 64.0) / 63.0,
            loops: self.loops,
        }
    }

    /// Microseconds the sound plays for, once.
    fn length(&self) -> u64 {
        self.sound.as_ref().map_or(0, |s| s.frames() as u64 * 1_000_000 / u64::from(self.rate.max(1)))
    }

    fn status(&self, now: u64) -> u32 {
        let Some(started) = self.started else { return DONE };
        let at = self.paused_at.unwrap_or(now);
        if self.loops == 0 || at.saturating_sub(started) < self.length() * u64::from(self.loops) { PLAYING } else { DONE }
    }
}

/// Where the mixer's sound goes.
#[derive(Default)]
enum Out {
    #[default]
    None,
    Device(Audio),
    File(Recorder),
}

#[derive(Default)]
pub struct Miles {
    out: Out,
    channels: HashMap<u32, Channel>,
    next_sample: u32,
    next_stream: u32,
    /// Sounds read from game memory, by address, length, format and sign.
    cache: HashMap<(u32, u32, u32, bool), Arc<Sound>>,
}

/// The samples of `bytes` in format `format` (DIG_F_MONO_8 0, MONO_16 1, STEREO_8 2,
/// STEREO_16 3) as 16-bit PCM. 8-bit samples are unsigned unless `signed`.
pub(crate) fn decode(bytes: &[u8], format: u32, signed: bool) -> Sound {
    let channels = if format & 2 != 0 { 2 } else { 1 };
    let samples = if format & 1 != 0 {
        bytes.as_chunks::<2>().0.iter().map(|b| i16::from_le_bytes(*b)).collect()
    } else {
        bytes.iter().map(|&b| if signed { i16::from(b as i8) << 8 } else { (i16::from(b) - 128) << 8 }).collect()
    };
    Sound { channels, samples }
}

/// A PCM WAV file's sound and rate: its `fmt ` and `data` chunks.
fn wav(bytes: &[u8]) -> Option<(Sound, u32)> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?));
    if bytes.get(0..4)? != b"RIFF" || bytes.get(8..12)? != b"WAVE" {
        return None;
    }
    let (mut at, mut format) = (12, None);
    while at + 8 <= bytes.len() {
        let (id, len) = (bytes.get(at..at + 4)?, u32_at(at + 4)? as usize);
        let body = at + 8;
        match id {
            b"fmt " => format = Some((u16_at(body)?, u16_at(body + 2)?, u32_at(body + 4)?, u16_at(body + 14)?)),
            b"data" => {
                let (tag, channels, rate, bits) = format?;
                if tag != 1 {
                    return None;
                }
                let data = bytes.get(body..(body + len).min(bytes.len()))?;
                let dig = u32::from(channels == 2) * 2 + u32::from(bits == 16);
                return Some((decode(data, dig, false), rate));
            }
            _ => {}
        }
        at = body + len + (len & 1);
    }
    None
}

impl Win32 {
    /// Opens where the mixer's sound goes, once: the output device when there is a window to
    /// play for, the WAV file TT_AUDIO_WAV names, or nowhere with TT_MUTE.
    pub(crate) fn open_sound(&mut self) {
        let set = |name| std::env::var_os(name).is_some();
        if matches!(self.miles.out, Out::None) && !set("TT_MUTE") {
            self.miles.out = match std::env::var_os("TT_AUDIO_WAV") {
                Some(path) => Recorder::create(path.as_ref()).map_or(Out::None, Out::File),
                None if set("TT_SHOTS") || set("TT_HEADLESS") => Out::None,
                None => Audio::open().map_or(Out::None, Out::Device),
            };
        }
    }

    pub(crate) fn send(&mut self, command: Command) {
        match &mut self.miles.out {
            Out::Device(audio) => audio.send(command),
            Out::File(recorder) => recorder.command(command),
            Out::None => {}
        }
    }

    /// Writes TT_AUDIO_WAV up to the game's present time, or keeps the device fed where it needs
    /// it (the web page); called at each frame.
    pub fn record_sound(&mut self) {
        match &mut self.miles.out {
            Out::File(recorder) => {
                let now = self.clock.micros();
                if let Err(e) = recorder.advance(now) {
                    eprintln!("host: TT_AUDIO_WAV: {e}");
                    self.miles.out = Out::None;
                }
            }
            Out::Device(audio) => audio.pump(),
            Out::None => {}
        }
    }

    /// Starts `handle` playing its sound from the start.
    fn start(&mut self, handle: u32, now: u64) {
        let Some(ch) = self.miles.channels.get_mut(&handle) else { return };
        ch.started = Some(now);
        ch.paused_at = None;
        if let Some(sound) = ch.sound.clone() {
            let voice = ch.voice();
            self.send(Command::Play(handle, sound, voice));
        }
    }
}

pub fn run(w: &mut Win32, c: &mut Cpu, name: &str, f: Frame) -> bool {
    let a = |c: &mut Cpu, n| c.arg(f, n);
    // The functions are stdcall; the bytes they take are in their names.
    let taken = name.rsplit_once('@').and_then(|(_, n)| n.parse::<u32>().ok()).unwrap_or(0) / 4;
    let handle = a(c, 0);
    let value = match name {
        "_AIL_startup@0" | "_AIL_shutdown@0" => 0,
        "_AIL_set_preference@8" => 0,
        // AIL_waveOutOpen(&driver, &waveout, device, format): one driver, and the mixer when there
        // is a window to play for.
        "_AIL_waveOutOpen@16" => {
            c.set_u32(handle, DRIVER);
            w.open_sound();
            0
        }
        "_AIL_waveOutClose@4" => 0,
        // AIL_digital_configuration(driver, &rate, &format, name): the game reopens the driver in
        // another mode when the name starts "Emulated".
        "_AIL_digital_configuration@16" => {
            let (rate, format, text) = (a(c, 1), a(c, 2), a(c, 3));
            if rate != 0 {
                c.set_u32(rate, 22050);
            }
            if format != 0 {
                c.set_u32(format, 3);
            }
            if text != 0 {
                w.put_str(c, text, 64, "DirectSound");
            }
            0
        }
        "_AIL_set_digital_master_volume@8" => {
            let master = a(c, 1).min(127) as f32 / 127.0;
            w.send(Command::Master(master));
            0
        }
        "_AIL_allocate_sample_handle@4" => {
            let h = SAMPLES + w.miles.next_sample;
            w.miles.next_sample += 1;
            w.miles.channels.insert(h, Channel::new());
            h
        }
        "_AIL_release_sample_handle@4" => {
            w.miles.channels.remove(&handle);
            w.send(Command::Stop(handle));
            0
        }
        "_AIL_init_sample@4" => {
            w.miles.channels.insert(handle, Channel::new());
            w.send(Command::Stop(handle));
            0
        }
        "_AIL_set_sample_type@12" => {
            let (format, flags) = (a(c, 1), a(c, 2));
            if let Some(ch) = w.miles.channels.get_mut(&handle) {
                (ch.format, ch.signed) = (format, flags & 1 != 0);
            }
            0
        }
        "_AIL_set_sample_address@12" => {
            let (address, len) = (a(c, 1), a(c, 2));
            if let Some(ch) = w.miles.channels.get_mut(&handle) {
                (ch.address, ch.len, ch.started) = (address, len, None);
                let key = (address, len, ch.format, ch.signed);
                let sound = match w.miles.cache.get(&key) {
                    Some(sound) => sound.clone(),
                    None => {
                        let sound = Arc::new(decode(&c.mem.bytes(address, len as usize), ch.format, ch.signed));
                        w.miles.cache.insert(key, sound.clone());
                        sound
                    }
                };
                ch.sound = Some(sound);
            }
            0
        }
        "_AIL_set_sample_playback_rate@8" | "_AIL_set_sample_volume@8" | "_AIL_set_sample_pan@8" | "_AIL_set_sample_loop_count@8" | "_AIL_set_stream_volume@8" => {
            let (v, now) = (a(c, 1), w.clock.micros());
            if let Some(ch) = w.miles.channels.get_mut(&handle) {
                match name {
                    // A new rate while it plays keeps the part already played.
                    "_AIL_set_sample_playback_rate@8" => {
                        if let Some(started) = ch.started {
                            let done = (now - started) as f64 * f64::from(ch.rate) / f64::from(v.max(1));
                            ch.started = Some(now - done as u64);
                        }
                        ch.rate = v.max(1);
                    }
                    "_AIL_set_sample_pan@8" => ch.pan = v,
                    "_AIL_set_sample_loop_count@8" => ch.loops = v,
                    _ => ch.volume = v,
                }
                let voice = ch.voice();
                w.send(Command::Set(handle, voice));
            }
            0
        }
        "_AIL_sample_playback_rate@4" => w.miles.channels.get(&handle).map_or(0, |ch| ch.rate),
        "_AIL_sample_volume@4" => w.miles.channels.get(&handle).map_or(0, |ch| ch.volume),
        "_AIL_start_sample@4" | "_AIL_start_stream@4" => {
            let now = w.clock.micros();
            w.start(handle, now);
            0
        }
        "_AIL_end_sample@4" => {
            if let Some(ch) = w.miles.channels.get_mut(&handle) {
                ch.started = None;
            }
            w.send(Command::Stop(handle));
            0
        }
        "_AIL_sample_status@4" | "_AIL_stream_status@4" => {
            let now = w.clock.micros();
            w.miles.channels.get(&handle).map_or(DONE, |ch| ch.status(now))
        }
        // AIL_open_stream(driver, file, memory): the whole WAV file, read now.
        "_AIL_open_stream@12" => {
            let named = a(c, 1);
            let path = c.mem.c_str(named);
            match w.host_file(&path).and_then(|p| std::fs::read(p).ok()).and_then(|bytes| wav(&bytes)) {
                Some((sound, rate)) => {
                    let h = STREAMS + w.miles.next_stream;
                    w.miles.next_stream += 1;
                    let ch = Channel { sound: Some(Arc::new(sound)), rate, ..Channel::new() };
                    w.miles.channels.insert(h, ch);
                    h
                }
                None => {
                    eprintln!("host: AIL_open_stream {path:?}: not a PCM WAV file the game can find");
                    0
                }
            }
        }
        // A paused stream's clock stops: it resumes where it paused.
        "_AIL_pause_stream@8" => {
            let (on, now) = (a(c, 1) != 0, w.clock.micros());
            if let Some(ch) = w.miles.channels.get_mut(&handle) {
                match (on, ch.paused_at, ch.started) {
                    (true, None, Some(_)) => ch.paused_at = Some(now),
                    (false, Some(at), Some(started)) => {
                        ch.started = Some(started + (now - at));
                        ch.paused_at = None;
                    }
                    _ => {}
                }
            }
            w.send(Command::Pause(handle, on));
            0
        }
        "_AIL_close_stream@4" => {
            w.miles.channels.remove(&handle);
            w.send(Command::Stop(handle));
            0
        }
        _ => return false,
    };
    c.ret(f, Some(value), taken);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_pcm_wav_file() {
        let mut file = b"RIFF\0\0\0\0WAVE".to_vec();
        file.extend(b"fmt \x10\0\0\0");
        file.extend([1u16, 2].iter().flat_map(|v| v.to_le_bytes()));
        file.extend([22050u32, 88200].iter().flat_map(|v| v.to_le_bytes()));
        file.extend([4u16, 16].iter().flat_map(|v| v.to_le_bytes()));
        file.extend(b"LIST\x02\0\0\0xy");
        file.extend(b"data\x08\0\0\0");
        file.extend([1i16, -2, 300, -32768].iter().flat_map(|v| v.to_le_bytes()));
        let (sound, rate) = wav(&file).expect("a PCM WAV file");
        assert_eq!((rate, sound.channels, sound.samples.as_slice()), (22050, 2, [1, -2, 300, -32768].as_slice()));
    }

    #[test]
    fn a_sample_plays_for_its_length_times_its_loops() {
        let sound = Sound { channels: 1, samples: vec![0; 22050] };
        let ch = Channel { sound: Some(Arc::new(sound)), rate: 11025, loops: 3, started: Some(1_000_000), ..Channel::new() };
        assert_eq!([ch.status(6_999_999), ch.status(7_000_000)], [PLAYING, DONE]);
        assert_eq!(Channel::new().status(0), DONE);
    }
}
