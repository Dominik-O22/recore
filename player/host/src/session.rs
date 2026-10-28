//! A windowed session recorded so it can be replayed offscreen, step for step (tools/play.sh,
//! tools/replay.sh). A window run differs from the last only in what the game reads from the
//! clock and from the window. With TT_RECORD=<dir>, every clock reading goes to `<dir>/clock`
//! and every change of input, with the number of the input poll that took it, to `<dir>/input`.
//! With TT_REPLAY=<dir>, the host answers from those files instead, so the game takes the same
//! path, a crash included.

use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};

/// Where the session's files are, and whether they are written or read.
fn directory() -> Option<(PathBuf, bool)> {
    match (std::env::var_os("TT_RECORD"), std::env::var_os("TT_REPLAY")) {
        (Some(dir), _) => Some((dir.into(), true)),
        (None, Some(dir)) => Some((dir.into(), false)),
        _ => None,
    }
}

/// Numbers in the order the game reads them: each the zigzag LEB128 of its difference from the
/// last of its kind, the kind given by the caller, in a zlib stream. The game busy-waits on the
/// clock, thousands of readings a frame that differ by 0 to 2, which the stream packs tightly.
pub enum Tape {
    Off,
    Record { file: ZlibEncoder<BufWriter<File>>, last: [u64; 2] },
    Replay { bytes: std::io::Bytes<BufReader<ZlibDecoder<File>>>, ended: bool, last: [u64; 2] },
}

impl Tape {
    pub fn open(name: &str) -> Tape {
        match directory() {
            Some((dir, true)) => {
                let file = BufWriter::new(File::create(dir.join(name)).expect("the session's tape"));
                Tape::Record { file: ZlibEncoder::new(file, Compression::fast()), last: [0; 2] }
            }
            Some((dir, false)) => {
                let file = File::open(dir.join(name)).expect("the session's tape");
                Tape::Replay { bytes: BufReader::new(ZlibDecoder::new(file)).bytes(), ended: false, last: [0; 2] }
            }
            None => Tape::Off,
        }
    }

    pub fn replaying(&self) -> bool {
        matches!(self, Tape::Replay { .. })
    }

    /// A reading of kind `kind` (0 or 1): `live` recorded, or the next one recorded. Past the end
    /// of a replay, which a crash leaves up to a frame short of, the readings are live.
    pub fn number(&mut self, kind: usize, live: impl FnOnce() -> u64) -> u64 {
        match self {
            Tape::Off => live(),
            Tape::Record { file, last } => {
                let value = live();
                let delta = value.wrapping_sub(last[kind]) as i64;
                last[kind] = value;
                let mut zigzag = ((delta << 1) ^ (delta >> 63)) as u64;
                loop {
                    let byte = (zigzag & 0x7f) as u8;
                    zigzag >>= 7;
                    let more = zigzag != 0;
                    file.write_all(&[byte | u8::from(more) << 7]).expect("the session's tape");
                    if !more {
                        break;
                    }
                }
                value
            }
            Tape::Replay { bytes, ended, last } => {
                let (mut zigzag, mut shift) = (0u64, 0);
                loop {
                    let Some(Ok(byte)) = bytes.next().filter(|_| !*ended) else {
                        if !*ended {
                            eprintln!("replay: the recorded clock ends here; it is live from now on");
                            *ended = true;
                        }
                        return live();
                    };
                    zigzag |= u64::from(byte & 0x7f) << shift;
                    shift += 7;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                let delta = (zigzag >> 1) as i64 ^ -((zigzag & 1) as i64);
                last[kind] = last[kind].wrapping_add(delta as u64);
                last[kind]
            }
        }
    }

    pub fn flush(&mut self) {
        if let Tape::Record { file, .. } = self {
            file.flush().ok();
        }
    }
}

/// What one input poll took from the window.
#[derive(Clone, Default, PartialEq)]
pub struct Snapshot {
    pub cursor: (i32, i32),
    pub moved: (i32, i32, i32),
    pub buttons: [bool; 3],
    pub keys: Vec<u8>,
    pub scans: Vec<u8>,
    /// Window messages: message, wParam, lParam.
    pub messages: Vec<(u32, u32, u32)>,
}

impl Snapshot {
    /// One line: poll, cursor, movement, buttons, keys, scans and messages, `-` for none.
    fn line(&self, poll: u64) -> String {
        let list = |v: &[u8]| if v.is_empty() { "-".to_string() } else { v.iter().map(u8::to_string).collect::<Vec<_>>().join(",") };
        let messages = if self.messages.is_empty() { "-".to_string() } else { self.messages.iter().map(|(m, w, l)| format!("{m}:{w}:{l}")).collect::<Vec<_>>().join(",") };
        let buttons: String = self.buttons.iter().map(|&b| if b { '1' } else { '0' }).collect();
        let (c, m) = (self.cursor, self.moved);
        format!("{poll} {} {} {} {} {} {buttons} {} {} {messages}", c.0, c.1, m.0, m.1, m.2, list(&self.keys), list(&self.scans))
    }

    fn parse(line: &str) -> Option<(u64, Snapshot)> {
        let f: Vec<&str> = line.split(' ').collect();
        let [poll, cx, cy, dx, dy, dz, buttons, keys, scans, messages] = f[..] else { return None };
        let list = |s: &str| if s == "-" { Vec::new() } else { s.split(',').filter_map(|v| v.parse().ok()).collect() };
        let messages = if messages == "-" {
            Vec::new()
        } else {
            messages
                .split(',')
                .filter_map(|m| {
                    let mut p = m.split(':').filter_map(|v| v.parse().ok());
                    Some((p.next()?, p.next()?, p.next()?))
                })
                .collect()
        };
        let mut b = buttons.chars().map(|c| c == '1');
        Some((
            poll.parse().ok()?,
            Snapshot {
                cursor: (cx.parse().ok()?, cy.parse().ok()?),
                moved: (dx.parse().ok()?, dy.parse().ok()?, dz.parse().ok()?),
                buttons: [b.next()?, b.next()?, b.next()?],
                keys: list(keys),
                scans: list(scans),
                messages,
            },
        ))
    }
}

/// The input polls that changed something, by the number of the poll.
pub enum Inputs {
    Off,
    Record { file: BufWriter<File>, last: Snapshot },
    Replay { polls: std::vec::IntoIter<(u64, Snapshot)>, next: Option<(u64, Snapshot)> },
}

impl Inputs {
    pub fn open() -> Inputs {
        match directory() {
            Some((dir, true)) => Inputs::Record { file: BufWriter::new(File::create(dir.join("input")).expect("the session's input")), last: Snapshot::default() },
            Some((dir, false)) => {
                let text = std::fs::read_to_string(dir.join("input")).expect("the session's input");
                let mut polls = text.lines().filter_map(Snapshot::parse).collect::<Vec<_>>().into_iter();
                let next = polls.next();
                Inputs::Replay { polls, next }
            }
            None => Inputs::Off,
        }
    }

    pub fn replaying(&self) -> bool {
        matches!(self, Inputs::Replay { .. })
    }

    /// What poll number `poll` takes: `live`, written down when it changes anything, or what the
    /// recording took at this poll. `None` leaves the input as it was.
    pub fn take(&mut self, poll: u64, live: impl FnOnce() -> Snapshot) -> Option<Snapshot> {
        match self {
            Inputs::Off => Some(live()),
            Inputs::Record { file, last } => {
                let now = live();
                let same = (now.cursor, now.buttons, &now.keys, &now.scans) == (last.cursor, last.buttons, &last.keys, &last.scans);
                if !same || now.moved != (0, 0, 0) || !now.messages.is_empty() {
                    writeln!(file, "{}", now.line(poll)).expect("the session's input");
                    *last = now.clone();
                }
                Some(now)
            }
            Inputs::Replay { polls, next } => {
                if next.as_ref().is_some_and(|(at, _)| *at == poll) {
                    let (_, snapshot) = std::mem::replace(next, polls.next())?;
                    return Some(snapshot);
                }
                None
            }
        }
    }

    pub fn flush(&mut self) {
        if let Inputs::Record { file, .. } = self {
            file.flush().ok();
        }
    }
}
