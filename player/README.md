# The player

`recore-mcp lift` turns a 32-bit Windows game into a Cargo workspace of Rust functions that run
on `recore-machine`. Every call the game makes to Windows or a DLL lands in the machine's `Host`.
The player is that host, shared by every game: Windows, DirectDraw, DirectInput, DirectSound, CD
audio and Miles, plus a window, offscreen frames and sound output.

It is its own Cargo workspace, so recore's build and CI never compile winit, softbuffer or cpal.
It moves none of recore's measures. What shows it works is a game that plays: each game keeps a
smoke script that plays a fixed input on the virtual clock and compares the frames with hashes.

## Crates

- `host` (`recore-host`) answers the imports. Each Windows DLL has a file: kernel32.rs, user32.rs,
  gdi32.rs, ddraw.rs, dinput.rs, dsound.rs, winmm.rs with cd.rs for CD audio, miles.rs. misc.rs
  answers what a game can run without.
- `window` (`recore-window`) shows the frames in a window, saves them as PNGs (`TT_SHOTS`), or, in
  the wasm build, hands them to a web page. It also takes the input.
- `audio` (`recore-audio`) mixes the voices the host starts, on the output device or into a WAV.

## A game on the player

A game's repository holds its `lift.toml`, a native crate and its ports. The native crate gives
the host a `Game` and a `run` for `lift.toml`'s `run`:

```rust
pub const GAME: recore_host::Game = recore_host::Game {
    disc: recore_host::Disc::Empty,
    ..recore_host::Game::new("Window title", "game.exe", "C:\\GAME")
};

pub fn run(functions: Vec<(u32, recore_machine::Lifted)>) {
    recore_host::run(functions, &GAME);
}
```

`Game` also takes the executable to load, the command line, changes to the image before it runs,
a hook at each frame, and names for the stacks `TT_BACKTRACE` prints. The code range comes from
the image's executable sections.

When the game stops on an import the host does not have, add it to the DLL's file, or to
misc.rs's `STUBS` when answering a constant is enough.

## Settings

The host reads these from the environment. They start with `TT_` for the first game it ran.

| Variable | What it does |
| --- | --- |
| `TT_GAME` | The game's directory, `game` by default |
| `TT_EXE` | The executable to load in place of `Game::image` |
| `TT_ARGS` | The command line in place of `Game::command_line` |
| `TT_OVERLAY` | Where the files the game writes go, `out/game-files` by default; the game directory stays as it is |
| `TT_CD` | The CD's audio tracks as `trackNN.ogg`, `cd` by default |
| `TT_SHOTS` | `frame:path.png,...`: runs offscreen on the virtual clock and saves those frames |
| `TT_INPUT` | Scripted input, applied at the frames it names (window/src/lib.rs) |
| `TT_HEADLESS` | Runs with no window and no frames |
| `TT_AUDIO_WAV` | Writes the sound to a WAV file as the game's clock moves |
| `TT_MUTE` | No sound |
| `TT_CLOCK` | `real` or `virtual` |
| `TT_TRACE` | Prints every import and COM call |
| `TT_FILES` | Prints every file the game opens or looks for |
| `TT_BACKTRACE` | `name,...`: prints the game functions that called those imports or methods |
| `TT_WATCH` | Prints game memory each frame it changes (host/src/watch.rs) |
| `TT_RECORD`, `TT_REPLAY` | `dir`: records the input and clock of a session there, or plays one back |
| `TT_PAGED` | Runs on paged memory instead of flat memory |
