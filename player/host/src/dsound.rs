//! DirectSound 3: the game makes a buffer per sound, fills it through `Lock`, and plays it once
//! or looping. A buffer's samples are game memory, and its play cursor moves with the game's
//! clock, so the game sees sounds start, run and end as they would whatever the sound card does.
//! Each buffer is a voice of the mixer (recore-audio), which `Play` gives the buffer's samples as they
//! are then, from the cursor on, and `Unlock` gives them again while it plays.

use std::{collections::HashMap, sync::Arc};

use recore_machine::Cpu;
use recore_audio::{Command, Voice};

use crate::{
    Win32,
    com::{Args, Iface},
    miles,
};

const OK: u32 = 0;
const DSBCAPS_PRIMARYBUFFER: u32 = 1;
const DSBPLAY_LOOPING: u32 = 1;
const DSBLOCK_FROMWRITECURSOR: u32 = 1;
const DSBLOCK_ENTIREBUFFER: u32 = 2;
/// The primary buffer has no size of its own; `Lock` on it gets this many bytes.
const PRIMARY_BYTES: u32 = 0x1_0000;
/// Buffer `i` is the mixer's voice `VOICES + i`.
const VOICES: u32 = 0x7000_0000;

/// The PCM layout of a buffer's samples.
#[derive(Clone, Copy)]
struct Format {
    rate: u32,
    block: u32,
    channels: u16,
    bits: u16,
}

#[derive(Clone)]
struct Buffer {
    data: u32,
    size: u32,
    format: Format,
    /// The rate it plays at, which `SetFrequency` changes.
    frequency: u32,
    volume: i32,
    pan: i32,
    /// While playing: when the cursor was last at `cursor`, and whether it loops.
    playing: Option<(u64, bool)>,
    /// Bytes into the buffer.
    cursor: u32,
    /// The primary buffer, which is the mix itself and never a voice.
    primary: bool,
}

impl Buffer {
    /// Moves the cursor to where it is at `now`, stopping a sound that played to its end.
    fn advance(&mut self, now: u64) {
        let Some((since, looping)) = self.playing else { return };
        let bytes = (now - since) * u64::from(self.frequency) / 1_000_000 * u64::from(self.format.block);
        let at = u64::from(self.cursor) + bytes;
        if looping {
            self.cursor = (at % u64::from(self.size.max(1))) as u32;
            self.playing = Some((now, true));
        } else if at >= u64::from(self.size) {
            (self.cursor, self.playing) = (0, None);
        } else {
            self.cursor = at as u32;
            self.playing = Some((now, false));
        }
    }

    /// How the mixer plays it. Volume is attenuation in hundredths of a decibel, pan the
    /// attenuation of the other side, positive to the right.
    fn voice(&self) -> Voice {
        let gain = |hundredths: i32| 10f32.powf(-(hundredths.unsigned_abs().min(10_000) as f32) / 2000.0);
        Voice {
            rate: self.frequency,
            volume: gain(self.volume),
            pan: self.pan.signum() as f32 * (1.0 - gain(self.pan)),
            loops: if self.playing.is_some_and(|(_, looping)| looping) { 0 } else { 1 },
        }
    }
}

/// The DirectSound object's buffers; a buffer object's id is its index here.
#[derive(Default)]
pub struct Sound {
    buffers: Vec<Buffer>,
    /// Buffers' samples decoded from game memory, by address and length.
    decoded: HashMap<(u32, u32), Arc<recore_audio::Sound>>,
}

/// WAVEFORMATEX at `at`: the sample rate, and the bytes of one sample of every channel.
fn format(c: &mut Cpu, at: u32) -> Format {
    if at == 0 {
        return Format { rate: 22050, block: 2, channels: 1, bits: 16 };
    }
    let (channels, rate) = (c.ld_u16(at + 2), c.u32_at(at + 4));
    let (block, bits) = (c.ld_u16(at + 12) as u32, c.ld_u16(at + 14));
    Format { rate: rate.max(1), block: block.max(1), channels: channels.clamp(1, 2), bits }
}

impl Win32 {
    /// `DirectSoundCreate(guid, &object, outer)`.
    pub fn direct_sound_create(&mut self, c: &mut Cpu, out: u32) {
        let object = self.new_object(c, Iface::DirectSound, 0);
        c.set_u32(out, object);
        self.open_sound();
    }

    /// Starts buffer `id` on its voice from its cursor: to the end, or round the whole buffer
    /// back to the cursor when it loops. Samples from the buffer's start are decoded once, until
    /// `Unlock` writes there.
    fn play_voice(&mut self, c: &mut Cpu, id: usize) {
        let b = &self.sound.buffers[id];
        let (data, size, cursor) = (b.data, b.size, b.cursor - b.cursor % b.format.block);
        let format = u32::from(b.format.channels == 2) * 2 + u32::from(b.format.bits == 16);
        let (voice, looping) = (b.voice(), b.playing.is_some_and(|(_, looping)| looping));
        let sound = match self.sound.decoded.get(&(data, size)) {
            Some(sound) if cursor == 0 => sound.clone(),
            _ => {
                let mut bytes = c.mem.bytes(data + cursor, (size - cursor) as usize);
                if looping {
                    bytes.extend(c.mem.bytes(data, cursor as usize));
                }
                let sound = Arc::new(miles::decode(&bytes, format, false));
                if cursor == 0 {
                    self.sound.decoded.insert((data, size), sound.clone());
                }
                sound
            }
        };
        self.send(Command::Play(VOICES + id as u32, sound, voice));
    }

    fn new_buffer(&mut self, c: &mut Cpu, buffer: Buffer) -> u32 {
        self.sound.buffers.push(buffer);
        self.new_object(c, Iface::SoundBuffer, self.sound.buffers.len() as u32 - 1)
    }
}

pub fn method(w: &mut Win32, c: &mut Cpu, iface: Iface, name: &str, a: &Args) -> Option<u32> {
    let now = w.clock.micros();
    let v = match (iface, name) {
        // CreateSoundBuffer(DSBUFFERDESC*, &buffer, outer).
        (Iface::DirectSound, "CreateSoundBuffer") => {
            let (desc, out) = (a.get(c, 0), a.get(c, 1));
            let (flags, bytes, wave) = (c.u32_at(desc + 4), c.u32_at(desc + 8), c.u32_at(desc + 16));
            let size = if flags & DSBCAPS_PRIMARYBUFFER != 0 { PRIMARY_BYTES } else { bytes };
            let format = format(c, wave);
            let data = w.alloc(size);
            let primary = flags & DSBCAPS_PRIMARYBUFFER != 0;
            let buffer = Buffer { data, size, format, frequency: format.rate, volume: 0, pan: 0, playing: None, cursor: 0, primary };
            let object = w.new_buffer(c, buffer);
            c.set_u32(out, object);
            OK
        }
        // A copy that plays the same samples on its own cursor.
        (Iface::DirectSound, "DuplicateSoundBuffer") => {
            let (original, out) = (a.get(c, 0), a.get(c, 1));
            let id = c.u32_at(original + 4) as usize;
            let buffer = Buffer { playing: None, cursor: 0, ..w.sound.buffers[id].clone() };
            let object = w.new_buffer(c, buffer);
            c.set_u32(out, object);
            OK
        }
        (Iface::DirectSound, "SetCooperativeLevel" | "Compact" | "SetSpeakerConfig" | "Initialize") => OK,
        // DSCAPS: the size, then flags saying it plays 8 and 16 bits, mono and stereo.
        (Iface::DirectSound, "GetCaps") => {
            let caps = a.get(c, 0);
            c.set_u32(caps + 4, 0xf0f);
            OK
        }
        (Iface::DirectSound, "GetSpeakerConfig") => {
            let out = a.get(c, 0);
            c.set_u32(out, 4);
            OK
        }
        (Iface::SoundBuffer, _) => {
            let id = a.id as usize;
            let b = &mut w.sound.buffers[id];
            b.advance(now);
            let primary = b.primary;
            match name {
                "Play" => {
                    let flags = a.get(c, 2);
                    b.playing = Some((now, flags & DSBPLAY_LOOPING != 0));
                    if !primary {
                        w.play_voice(c, id);
                    }
                    OK
                }
                "Stop" => {
                    b.playing = None;
                    w.send(Command::Stop(VOICES + id as u32));
                    OK
                }
                // DSBSTATUS_PLAYING 1, DSBSTATUS_LOOPING 4.
                "GetStatus" => {
                    let out = a.get(c, 0);
                    let status = b.playing.map_or(0, |(_, looping)| if looping { 5 } else { 1 });
                    c.set_u32(out, status);
                    OK
                }
                // The play cursor, and the write cursor a little after it.
                "GetCurrentPosition" => {
                    let (play, write) = (a.get(c, 0), a.get(c, 1));
                    let ahead = (b.cursor + b.format.block * (b.format.rate / 100)) % b.size.max(1);
                    let cursor = b.cursor;
                    if play != 0 {
                        c.set_u32(play, cursor);
                    }
                    if write != 0 {
                        c.set_u32(write, ahead);
                    }
                    OK
                }
                "SetCurrentPosition" => {
                    b.cursor = a.get(c, 0) % b.size.max(1);
                    OK
                }
                // Lock(offset, bytes, &p1, &n1, &p2, &n2, flags): a span that wraps past the
                // end comes back as two.
                "Lock" => {
                    let (offset, bytes, flags) = (a.get(c, 0), a.get(c, 1), a.get(c, 6));
                    let start = if flags & DSBLOCK_FROMWRITECURSOR != 0 { b.cursor } else { offset % b.size.max(1) };
                    let bytes = if flags & DSBLOCK_ENTIREBUFFER != 0 { b.size } else { bytes.min(b.size) };
                    let first = bytes.min(b.size - start);
                    let (data, second) = (b.data, bytes - first);
                    for (n, v) in [data + start, first, if second > 0 { data } else { 0 }, second].into_iter().enumerate() {
                        let out = a.get(c, 2 + n as u32);
                        if out != 0 {
                            c.set_u32(out, v);
                        }
                    }
                    OK
                }
                // What was decoded from where the game wrote is stale. A buffer the game writes
                // while it plays, as a stream is, goes on from its cursor with what is there now.
                "Unlock" => {
                    let (data, size, playing) = (b.data, b.size, b.playing.is_some());
                    w.sound.decoded.retain(|&(at, len), _| at + len <= data || at >= data + size);
                    if playing && !primary {
                        w.play_voice(c, id);
                    }
                    OK
                }
                "Restore" | "Initialize" | "SetFormat" => OK,
                "SetVolume" | "SetPan" | "SetFrequency" => {
                    let v = a.get(c, 0);
                    match name {
                        "SetVolume" => b.volume = v as i32,
                        "SetPan" => b.pan = v as i32,
                        // 0 is the buffer's own rate.
                        _ => b.frequency = if v == 0 { b.format.rate } else { v },
                    }
                    if b.playing.is_some() && !primary {
                        let voice = b.voice();
                        w.send(Command::Set(VOICES + id as u32, voice));
                    }
                    OK
                }
                "GetVolume" | "GetPan" | "GetFrequency" => {
                    let out = a.get(c, 0);
                    let value = match name {
                        "GetVolume" => b.volume as u32,
                        "GetPan" => b.pan as u32,
                        _ => b.frequency,
                    };
                    c.set_u32(out, value);
                    OK
                }
                // DSBCAPS: size, flags, bytes, then zeros.
                "GetCaps" => {
                    let caps = a.get(c, 0);
                    let size = b.size;
                    c.set_u32(caps + 4, 0);
                    c.set_u32(caps + 8, size);
                    OK
                }
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(v)
}
