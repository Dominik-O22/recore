//! Sound out: a [`Mixer`] of voices, played on the default output device ([`Audio`]; in the web
//! build, the page's audio worklet) or written to a WAV file as the game's clock moves
//! ([`Recorder`]). The host sends [`Command`]s and the mixer only plays them. When a voice ends is
//! the host's to decide, by the game's clock, so what the game sees does not depend on the sound
//! card.

#[cfg(not(target_family = "wasm"))]
mod device;
#[cfg(target_family = "wasm")]
mod page;

use std::{
    io::{Seek, SeekFrom, Write},
    sync::Arc,
};

#[cfg(not(target_family = "wasm"))]
pub use device::Audio;
#[cfg(target_family = "wasm")]
pub use page::Audio;

/// 16-bit PCM, channels interleaved.
pub struct Sound {
    pub channels: u16,
    pub samples: Vec<i16>,
}

impl Sound {
    pub fn frames(&self) -> usize {
        self.samples.len() / usize::from(self.channels.max(1))
    }
}

/// How a voice plays its sound.
#[derive(Clone, Copy, Debug)]
pub struct Voice {
    /// Frames of the sound a second.
    pub rate: u32,
    /// 0 to 1.
    pub volume: f32,
    /// -1 left to 1 right.
    pub pan: f32,
    /// Times to play the sound, 0 for ever.
    pub loops: u32,
}

pub enum Command {
    /// Plays `sound` on voice `id`, in place of what it played.
    Play(u32, Arc<Sound>, Voice),
    Set(u32, Voice),
    Pause(u32, bool),
    Stop(u32),
    /// The volume of everything, 0 to 1.
    Master(f32),
}

struct Playing {
    id: u32,
    sound: Arc<Sound>,
    voice: Voice,
    /// The position in the sound, in its frames.
    at: f64,
    played: u32,
    paused: bool,
}

pub struct Mixer {
    voices: Vec<Playing>,
    master: f32,
    rate: u32,
    channels: usize,
}

impl Mixer {
    /// A mixer for `rate` frames a second of `channels` channels.
    pub fn new(rate: u32, channels: usize) -> Mixer {
        Mixer { voices: Vec::new(), master: 1.0, rate, channels: channels.max(1) }
    }

    pub fn command(&mut self, command: Command) {
        match command {
            Command::Play(id, sound, voice) => {
                self.voices.retain(|v| v.id != id);
                self.voices.push(Playing { id, sound, voice, at: 0.0, played: 0, paused: false });
            }
            Command::Set(id, voice) => self.voices.iter_mut().filter(|v| v.id == id).for_each(|v| v.voice = voice),
            Command::Pause(id, paused) => self.voices.iter_mut().filter(|v| v.id == id).for_each(|v| v.paused = paused),
            Command::Stop(id) => self.voices.retain(|v| v.id != id),
            Command::Master(volume) => self.master = volume,
        }
    }

    /// Fills `out`, whole frames of interleaved channels, with what plays next, from -1 to 1.
    pub fn mix(&mut self, out: &mut [f32]) {
        for frame in out.chunks_mut(self.channels) {
            frame.fill(0.0);
            self.next(frame);
            frame.iter_mut().for_each(|v| *v = v.clamp(-1.0, 1.0));
        }
    }

    /// Mixes the next output frame into `frame`, left and right in its first two channels.
    fn next(&mut self, frame: &mut [f32]) {
        let rate = f64::from(self.rate);
        for v in self.voices.iter_mut().filter(|v| !v.paused) {
            let (s, frames) = (&v.sound, v.sound.frames());
            if frames == 0 {
                continue;
            }
            let i = v.at as usize;
            let t = (v.at - i as f64) as f32;
            let ch = usize::from(s.channels.max(1));
            let sample = |k: usize, c: usize| f32::from(s.samples[(k.min(frames - 1)) * ch + c.min(ch - 1)]) / 32768.0;
            let pick = |c: usize| sample(i, c) * (1.0 - t) + sample(i + 1, c) * t;
            let (l, r) = (pick(0), pick(1));
            let gain = v.voice.volume * self.master;
            let (gl, gr) = ((1.0 - v.voice.pan).min(1.0), (1.0 + v.voice.pan).min(1.0));
            match frame {
                [one] => *one += (l + r) * 0.5 * gain,
                [left, right, ..] => {
                    *left += l * gain * gl;
                    *right += r * gain * gr;
                }
                [] => {}
            }
            v.at += f64::from(v.voice.rate) / rate;
            if v.at >= frames as f64 {
                v.at -= frames as f64;
                v.played += 1;
            }
        }
        self.voices.retain(|v| v.sound.frames() > 0 && (v.voice.loops == 0 || v.played < v.voice.loops));
    }
}

/// A WAV file of what the mixer plays, 44100 Hz 16-bit stereo, written as the game's clock moves:
/// the same run writes the same file.
pub struct Recorder {
    mixer: Mixer,
    file: std::fs::File,
    /// Frames written, and the game's microseconds they cover.
    frames: u64,
}

impl Recorder {
    const RATE: u32 = 44100;

    pub fn create(path: &std::path::Path) -> std::io::Result<Recorder> {
        let mut recorder = Recorder { mixer: Mixer::new(Self::RATE, 2), file: std::fs::File::create(path)?, frames: 0 };
        recorder.header()?;
        Ok(recorder)
    }

    pub fn command(&mut self, command: Command) {
        self.mixer.command(command);
    }

    /// Writes what plays up to the game's `micros`.
    pub fn advance(&mut self, micros: u64) -> std::io::Result<()> {
        let until = micros * u64::from(Self::RATE) / 1_000_000;
        if until <= self.frames {
            return Ok(());
        }
        let mut mixed = vec![0.0; (until - self.frames) as usize * 2];
        self.mixer.mix(&mut mixed);
        let bytes: Vec<u8> = mixed.iter().flat_map(|v| ((v * 32767.0) as i16).to_le_bytes()).collect();
        self.file.write_all(&bytes)?;
        self.frames = until;
        self.header()
    }

    /// The RIFF header for the frames written so far, rewritten after each write.
    fn header(&mut self) -> std::io::Result<()> {
        let data = (self.frames * 4) as u32;
        let mut h = Vec::with_capacity(44);
        h.extend(b"RIFF");
        h.extend((36 + data).to_le_bytes());
        h.extend(b"WAVEfmt ");
        h.extend(16u32.to_le_bytes());
        h.extend(1u16.to_le_bytes());
        h.extend(2u16.to_le_bytes());
        h.extend(Self::RATE.to_le_bytes());
        h.extend((Self::RATE * 4).to_le_bytes());
        h.extend(4u16.to_le_bytes());
        h.extend(16u16.to_le_bytes());
        h.extend(b"data");
        h.extend(data.to_le_bytes());
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&h)?;
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }
}
