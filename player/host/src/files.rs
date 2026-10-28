//! Files: the game sees itself installed at its [`Game::root`]. Reads find a path under the
//! overlay directory first, then under the game directory, matching each component without
//! regard to case. Writes go to the overlay, so the game directory is never changed.

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use recore_machine::{Cpu, Frame};

use crate::Win32;

const INVALID: u32 = u32::MAX;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const STD_HANDLES: [u32; 3] = [0xf1, 0xf2, 0xf3];

pub struct Open {
    file: File,
}

pub struct Find {
    names: Vec<(String, u64, bool)>,
    next: usize,
}

/// A mapping of a file, and the views made of it.
pub struct Mapping {
    handle: u32,
}

#[derive(Default)]
pub struct Files {
    open: HashMap<u32, Open>,
    finds: HashMap<u32, Find>,
    mappings: HashMap<u32, Mapping>,
    next: u32,
    /// The current directory, relative to the install directory, with `\` separators.
    cwd: String,
}

/// The path relative to the install directory `root` that a Windows path names, from the
/// current directory `cwd`. A path on another drive names the same place on it.
fn relative(root: &str, cwd: &str, path: &str) -> String {
    let path = path.replace('/', "\\");
    let lower = path.to_lowercase();
    let root = root.to_lowercase();
    let rest = if let Some(r) = lower.strip_prefix(&root).filter(|r| r.is_empty() || r.starts_with('\\')) {
        path[path.len() - r.len()..].trim_start_matches('\\').to_string()
    } else if lower.len() > 1 && lower.as_bytes()[1] == b':' {
        path[2..].trim_start_matches('\\').to_string()
    } else if cwd.is_empty() {
        path.trim_start_matches(".\\").to_string()
    } else {
        format!("{cwd}\\{}", path.trim_start_matches(".\\"))
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("\\")
}

/// The existing path under `base` that `rel` names, matching components without regard to case.
fn find_case(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut at = base.to_path_buf();
    for part in rel.split('\\').filter(|p| !p.is_empty()) {
        let exact = at.join(part);
        if exact.exists() {
            at = exact;
            continue;
        }
        let entry = fs::read_dir(&at).ok()?.flatten().find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(part))?;
        at = entry.path();
    }
    Some(at)
}

fn glob(name: &str, pattern: &str) -> bool {
    fn go(n: &[u8], p: &[u8]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(n, &p[1..]) || (!n.is_empty() && go(&n[1..], p)),
            (Some(b'?'), Some(_)) => go(&n[1..], &p[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => go(&n[1..], &p[1..]),
            _ => false,
        }
    }
    let pattern = if pattern == "*.*" { "*" } else { pattern };
    go(name.as_bytes(), pattern.as_bytes())
}

impl Win32 {
    fn overlay(&self) -> PathBuf {
        self.overlay_dir.clone()
    }

    /// The path relative to the install directory that a game path names.
    fn path(&self, path: &str) -> String {
        relative(self.game.root, &self.files.cwd, path)
    }

    /// Where the existing file a game path names is, overlay first, for host code that reads it.
    pub fn host_file(&self, path: &str) -> Option<PathBuf> {
        self.existing(&self.path(path))
    }

    /// Where an existing file the game names is, overlay first.
    fn existing(&self, rel: &str) -> Option<PathBuf> {
        find_case(&self.overlay(), rel).or_else(|| find_case(&self.game_dir, rel))
    }

    fn handle(&mut self) -> u32 {
        self.files.next += 4;
        0x1000 + self.files.next
    }

    fn fill_find(c: &mut Cpu, data: u32, name: &str, size: u64, dir: bool) {
        c.mem.poke(data, &[0; 320]);
        c.set_u32(data, if dir { 0x10 } else { 0x80 });
        c.set_u32(data + 28, (size >> 32) as u32);
        c.set_u32(data + 32, size as u32);
        let bytes: Vec<u8> = name.bytes().take(259).chain([0]).collect();
        c.mem.poke(data + 44, &bytes);
    }
}

pub fn run(w: &mut Win32, c: &mut Cpu, name: &str, f: Frame) -> bool {
    let a = |c: &mut Cpu, n| c.arg(f, n);
    let teb = c.reg(recore_machine::regs::FS_OFFSET);
    match name {
        "CreateFileA" | "CreateFileW" => {
            let (path, access, disposition) = (a(c, 0), a(c, 1), a(c, 4));
            let path = if name == "CreateFileA" { c.mem.c_str(path) } else { wide_str(c, path) };
            let rel = w.path(&path);
            let write = access & 0x4000_0000 != 0;
            let opened = if w.game.disc.hides(&path) {
                None
            } else if write {
                let target = find_case(&w.overlay(), &rel).unwrap_or_else(|| w.overlay().join(rel.replace('\\', "/")));
                if let Some(parent) = target.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if !target.exists()
                    && let Some(src) = find_case(&w.game_dir, &rel).filter(|_| disposition == 3 || disposition == 4)
                {
                    let _ = fs::copy(src, &target);
                }
                OpenOptions::new().read(true).write(true).create(disposition != 3 && disposition != 5).truncate(disposition == 2 || disposition == 5).open(&target).ok()
            } else {
                w.existing(&rel).and_then(|p| File::open(p).ok())
            };
            if w.trace || std::env::var_os("TT_FILES").is_some() {
                eprintln!("host: CreateFile {path:?} {} -> {rel:?} {}", if write { "write" } else { "read" }, if opened.is_some() { "opened" } else { "not found" });
            }
            let handle = match opened {
                Some(file) => {
                    let h = w.handle();
                    w.files.open.insert(h, Open { file });
                    h
                }
                None => {
                    c.set_u32(teb + 0x34, ERROR_FILE_NOT_FOUND);
                    INVALID
                }
            };
            c.ret(f, Some(handle), 7);
        }
        // FILE_ATTRIBUTE_DIRECTORY or FILE_ATTRIBUTE_NORMAL, or INVALID_FILE_ATTRIBUTES.
        "GetFileAttributesA" => {
            let named = a(c, 0);
            let path = c.mem.c_str(named);
            let found = if w.game.disc.hides(&path) { None } else { w.existing(&w.path(&path)) };
            if w.trace || std::env::var_os("TT_FILES").is_some() {
                eprintln!("host: GetFileAttributes {path:?} {}", if found.is_some() { "found" } else { "not found" });
            }
            let attributes = found.map_or(INVALID, |p| if p.is_dir() { 0x10 } else { 0x80 });
            if attributes == INVALID {
                c.set_u32(teb + 0x34, ERROR_FILE_NOT_FOUND);
            }
            c.ret(f, Some(attributes), 1);
        }
        "ReadFile" => {
            let (h, buf, len, read) = (a(c, 0), a(c, 1), a(c, 2), a(c, 3));
            let got = match w.files.open.get_mut(&h) {
                Some(open) => {
                    let mut bytes = vec![0; len as usize];
                    let n = read_full(&mut open.file, &mut bytes);
                    for (i, b) in bytes[..n].iter().enumerate() {
                        c.st(buf + i as u32, 1, u128::from(*b));
                    }
                    n as u32
                }
                None => 0,
            };
            if read != 0 {
                c.set_u32(read, got);
            }
            c.ret(f, Some(1), 5);
        }
        "WriteFile" => {
            let (h, buf, len, written) = (a(c, 0), a(c, 1), a(c, 2), a(c, 3));
            let bytes = c.mem.bytes(buf, len as usize);
            if STD_HANDLES.contains(&h) {
                eprint!("{}", String::from_utf8_lossy(&bytes));
            } else if let Some(open) = w.files.open.get_mut(&h) {
                let _ = open.file.write_all(&bytes);
            }
            if written != 0 {
                c.set_u32(written, len);
            }
            c.ret(f, Some(1), 5);
        }
        "SetFilePointer" => {
            let (h, low, high, method) = (a(c, 0), a(c, 1), a(c, 2), a(c, 3));
            let distance = if high != 0 { ((u64::from(c.u32_at(high)) << 32) | u64::from(low)) as i64 } else { i64::from(low as i32) };
            let pos = w.files.open.get_mut(&h).map_or(0, |open| {
                let to = match method {
                    0 => SeekFrom::Start(distance.max(0) as u64),
                    1 => SeekFrom::Current(distance),
                    _ => SeekFrom::End(distance),
                };
                open.file.seek(to).unwrap_or(0)
            });
            if high != 0 {
                c.set_u32(high, (pos >> 32) as u32);
            }
            c.ret(f, Some(pos as u32), 4);
        }
        "GetFileSize" => {
            let (h, high) = (a(c, 0), a(c, 1));
            let size = w.files.open.get(&h).and_then(|o| o.file.metadata().ok()).map_or(0, |m| m.len());
            if high != 0 {
                c.set_u32(high, (size >> 32) as u32);
            }
            c.ret(f, Some(size as u32), 2);
        }
        "GetFileType" => {
            let h = a(c, 0);
            c.ret(f, Some(if STD_HANDLES.contains(&h) { 2 } else { 1 }), 1);
        }
        "GetStdHandle" => {
            let n = a(c, 0) as i32;
            c.ret(f, Some(STD_HANDLES[(-10 - n).clamp(0, 2) as usize]), 1);
        }
        "SetStdHandle" => c.ret(f, Some(1), 2),
        "SetHandleCount" => {
            let n = a(c, 0);
            c.ret(f, Some(n), 1);
        }
        "CloseHandle" => {
            let h = a(c, 0);
            w.files.open.remove(&h);
            w.files.mappings.remove(&h);
            c.ret(f, Some(1), 1);
        }
        "FlushFileBuffers" => c.ret(f, Some(1), 1),
        "SetEndOfFile" => {
            let h = a(c, 0);
            if let Some(open) = w.files.open.get_mut(&h) {
                let pos = open.file.stream_position().unwrap_or(0);
                let _ = open.file.set_len(pos);
            }
            c.ret(f, Some(1), 1);
        }
        "DeleteFileA" => {
            let path = a(c, 0);
            let rel = w.path(&c.mem.c_str(path));
            let removed = find_case(&w.overlay(), &rel).is_some_and(|p| fs::remove_file(p).is_ok());
            c.ret(f, Some(u32::from(removed)), 1);
        }
        "FindFirstFileA" => {
            let (pattern, data) = (a(c, 0), a(c, 1));
            let pattern = c.mem.c_str(pattern);
            let rel = w.path(&pattern);
            let (dir, wildcard) = rel.rsplit_once('\\').unwrap_or(("", &rel));
            let mut names: Vec<(String, u64, bool)> = Vec::new();
            let bases = if w.game.disc.hides(&pattern) { vec![] } else { vec![w.overlay(), w.game_dir.clone()] };
            for base in bases {
                let Some(at) = find_case(&base, dir) else { continue };
                let Ok(entries) = fs::read_dir(at) else { continue };
                for e in entries.flatten() {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if glob(&n, wildcard) && !names.iter().any(|(m, _, _)| m.eq_ignore_ascii_case(&n)) {
                        let meta = e.metadata().ok();
                        names.push((n, meta.as_ref().map_or(0, |m| m.len()), meta.is_some_and(|m| m.is_dir())));
                    }
                }
            }
            names.sort();
            // Windows lists a directory's "." and ".." first, and games skip the first two
            // entries for them.
            if !dir.is_empty() && glob(".", wildcard) {
                names.splice(0..0, [(".".to_string(), 0, true), ("..".to_string(), 0, true)]);
            }
            if w.trace || std::env::var_os("TT_FILES").is_some() {
                eprintln!("host: FindFirstFile {rel:?}: {} entries", names.len());
            }
            let handle = if let Some((n, size, dir)) = names.first().cloned() {
                Win32::fill_find(c, data, &n, size, dir);
                let h = w.handle();
                w.files.finds.insert(h, Find { names, next: 1 });
                h
            } else {
                c.set_u32(teb + 0x34, ERROR_FILE_NOT_FOUND);
                INVALID
            };
            c.ret(f, Some(handle), 2);
        }
        "FindNextFileA" => {
            let (h, data) = (a(c, 0), a(c, 1));
            let next = w.files.finds.get_mut(&h).and_then(|find| {
                let item = find.names.get(find.next).cloned();
                find.next += 1;
                item
            });
            let found = match next {
                Some((n, size, dir)) => {
                    Win32::fill_find(c, data, &n, size, dir);
                    1
                }
                None => {
                    c.set_u32(teb + 0x34, 18);
                    0
                }
            };
            c.ret(f, Some(found), 2);
        }
        "FindClose" => {
            let h = a(c, 0);
            w.files.finds.remove(&h);
            c.ret(f, Some(1), 1);
        }
        "GetCurrentDirectoryA" => {
            let (size, buf) = (a(c, 0), a(c, 1));
            let root = w.game.root;
            let dir = if w.files.cwd.is_empty() { root.to_string() } else { format!("{root}\\{}", w.files.cwd) };
            let len = w.put_str(c, buf, size, &dir);
            c.ret(f, Some(len), 2);
        }
        "SetCurrentDirectoryA" => {
            let path = a(c, 0);
            let path = c.mem.c_str(path);
            w.files.cwd = w.path(&path);
            c.ret(f, Some(1), 1);
        }
        // C: is fixed (DRIVE_FIXED 3) and D: a CD-ROM (DRIVE_CDROM 5), which holds what
        // `Game::disc` says.
        "GetDriveTypeA" => {
            let root = a(c, 0);
            let cdrom = root != 0 && c.mem.c_str(root).to_ascii_uppercase().starts_with('D');
            c.ret(f, Some(if cdrom { 5 } else { 3 }), 1);
        }
        "GetLogicalDriveStringsA" => {
            let (size, buf) = (a(c, 0), a(c, 1));
            let drives = b"C:\\\0D:\\\0\0";
            if size as usize >= drives.len() {
                c.mem.poke(buf, drives);
            }
            c.ret(f, Some(drives.len() as u32 - 1), 2);
        }
        "GetDiskFreeSpaceA" => {
            for (n, v) in [(1, 8u32), (2, 512), (3, 0x0010_0000), (4, 0x0020_0000)] {
                let out = a(c, n);
                if out != 0 {
                    c.set_u32(out, v);
                }
            }
            c.ret(f, Some(1), 5);
        }
        "GetTempPathA" => {
            let (size, buf) = (a(c, 0), a(c, 1));
            let len = w.put_str(c, buf, size, &format!("{}\\TEMP\\", w.game.root));
            c.ret(f, Some(len), 2);
        }
        "GetFullPathNameA" => {
            let (path, size, buf, part) = (a(c, 0), a(c, 1), a(c, 2), a(c, 3));
            let rel = w.path(&c.mem.c_str(path));
            let root = w.game.root;
            let full = if rel.is_empty() { root.to_string() } else { format!("{root}\\{rel}") };
            let len = w.put_str(c, buf, size, &full);
            if part != 0 {
                let name = full.rfind('\\').map_or(0, |i| i + 1) as u32;
                c.set_u32(part, buf + name);
            }
            c.ret(f, Some(len), 4);
        }
        "CreateFileMappingA" => {
            let h = a(c, 0);
            let m = w.handle();
            w.files.mappings.insert(m, Mapping { handle: h });
            c.ret(f, Some(m), 6);
        }
        // A view is a copy of the file's bytes in fresh memory.
        "MapViewOfFile" => {
            let (m, offset, len) = (a(c, 0), a(c, 3), a(c, 4));
            let view = match w.files.mappings.get(&m).and_then(|map| w.files.open.get_mut(&map.handle)) {
                Some(open) => {
                    let size = open.file.metadata().map_or(0, |m| m.len()) as u32;
                    let len = if len == 0 { size.saturating_sub(offset) } else { len };
                    let mut bytes = vec![0; len as usize];
                    let _ = open.file.seek(SeekFrom::Start(u64::from(offset)));
                    let n = read_full(&mut open.file, &mut bytes);
                    let at = w.alloc_pages(len);
                    c.mem.poke(at, &bytes[..n]);
                    at
                }
                None => 0,
            };
            c.ret(f, Some(view), 5);
        }
        "UnmapViewOfFile" => c.ret(f, Some(1), 1),
        _ => return false,
    }
    true
}

fn read_full(file: &mut File, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        match file.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    n
}

fn wide_str(c: &mut Cpu, at: u32) -> String {
    let mut units = Vec::new();
    while units.len() < 0x1000 {
        let u = c.ld(at + 2 * units.len() as u32, 2) as u16;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::relative;

    #[test]
    fn a_path_under_the_root_on_another_drive_or_relative_names_the_same_file() {
        assert_eq!(relative("C:\\GAME", "", "c:\\game\\DATA\\a.bin"), "DATA\\a.bin");
        assert_eq!(relative("C:\\GAME", "", "D:\\DATA\\a.bin"), "DATA\\a.bin");
        assert_eq!(relative("C:\\GAME", "DATA", ".\\a.bin"), "DATA\\a.bin");
        assert_eq!(relative("C:\\GAME", "DATA", "..\\b/../a.bin"), "a.bin");
        assert_eq!(relative("C:\\GAME", "", "C:\\GAMES\\a.bin"), "GAMES\\a.bin");
    }
}
