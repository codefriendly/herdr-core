//! Resume after loss: the command a program reports for itself in a root OSC
//! 7501 record (`resume=claude,--resume,abc:key=<HC_RESUME_KEY>`), typed into
//! the replacement shell. Core knows no agents. A report counts only with the
//! key core gave this program (and what it starts) in its environment: output
//! some other program merely showed can't know it. The key never stays in
//! kept output: it is masked in what viewers get and in the holder's tail.

use crate::foreground::Foreground;
use crate::runtime::{Core, State};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The environment variable holding a program's key.
pub const KEY_VAR: &str = "HC_RESUME_KEY";

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
pub struct Resume {
    /// The command, as the program reported it.
    pub argv: Vec<String>,
    /// The folder of the program in front when it was bound (or the terminal's last known one).
    pub cwd: String,
    /// The program in front at the first foreground check after the report (never the
    /// terminal's own shell); its exit clears the command, its loss keeps it. 0 until then,
    /// and after a restore until the resumed program reports again.
    pub pid: i32,
}

const MAX_ARGS: usize = 64;
const MAX_BYTES: usize = 8192;

/// A report's resume fields: the key it carries, and the command (None clears).
#[derive(Debug, PartialEq)]
pub struct Report<'a> {
    pub key: &'a [u8],
    pub argv: Option<Vec<String>>,
}

/// The last `resume` and `key` values in a report body. None when there is no
/// `resume`, or it is not a plain command (ignored, like unknown keys).
pub fn parse(raw: &[u8]) -> Option<Report<'_>> {
    let last = |key: &[u8]| raw.split(|c| *c == b':').filter_map(|f| f.strip_prefix(key)).next_back();
    let value = last(b"resume=")?;
    let key = last(b"key=").unwrap_or_default();
    let argv = if value.is_empty() { None } else { Some(decode(value).filter(|argv| valid(argv))?) };
    Some(Report { key, argv })
}

/// Comma-separated arguments; anything outside the OSC value alphabet is `%XX`.
fn decode(value: &[u8]) -> Option<Vec<String>> {
    if !value.iter().all(|c| c.is_ascii_alphanumeric() || b"_.+-/=,%".contains(c)) {
        return None;
    }
    value
        .split(|c| *c == b',')
        .map(|arg| {
            let mut out = Vec::with_capacity(arg.len());
            let mut rest = arg;
            while let Some((&c, tail)) = rest.split_first() {
                if c == b'%' {
                    let hex = std::str::from_utf8(tail.get(..2)?).ok()?;
                    out.push(u8::from_str_radix(hex, 16).ok()?);
                    rest = &tail[2..];
                } else {
                    out.push(c);
                    rest = tail;
                }
            }
            String::from_utf8(out).ok()
        })
        .collect()
}

/// Typed into a shell, so: a plain command name first (shells disagree on
/// quoted paths), no control characters, and nothing quoting can't carry.
fn valid(argv: &[String]) -> bool {
    let plain = |a: &str| {
        !a.is_empty() && !a.starts_with('-') && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    };
    argv.first().is_some_and(|a| plain(a))
        && argv.len() <= MAX_ARGS
        && argv.iter().map(String::len).sum::<usize>() <= MAX_BYTES
        && !argv.iter().any(|a| a.chars().any(|c| c.is_control() || c == '\'' || c == '\\'))
}

/// The command line to type, Enter included; arguments with other than
/// plain characters go in single quotes.
pub fn typed(argv: &[String]) -> String {
    let quote = |a: &String| {
        if !a.is_empty() && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.+-/=,:@%".contains(&b)) {
            a.clone()
        } else {
            format!("'{a}'")
        }
    };
    let mut line = argv.iter().map(quote).collect::<Vec<_>>().join(" ");
    line.push('\r');
    line
}

/// Overwrites key values in OSC 7501 records (`key=` fields) as output streams
/// past, with `x`: the same length, so nothing else moves. It keeps its place
/// between calls, so a record split anywhere across reads is masked too.
#[derive(Default)]
pub struct Masker(Mask);

#[derive(Default, Clone, Copy)]
enum Mask {
    #[default]
    Outside,
    Esc,
    /// How much of `7501;` came after `ESC ]`.
    Prefix(usize),
    /// At a field's start: how much of `key=` it has matched.
    Field(usize),
    /// In another field.
    Value,
    /// In a key: overwritten.
    Key,
}

impl Masker {
    /// Read as Ghostty's parser reads them: CAN and SUB end any sequence, ESC
    /// starts one (C0 and DEL after it are ignored), BEL ends an OSC, and inside
    /// an OSC the other C0 bytes are dropped (so they split neither `7501;` nor `key=`).
    pub fn mask(&mut self, buf: &mut [u8]) {
        use Mask::*;
        for b in buf.iter_mut() {
            let c = *b;
            let osc = matches!(self.0, Prefix(_) | Field(_) | Value | Key);
            self.0 = match (self.0, c) {
                (_, 0x18 | 0x1a) => Outside,
                (_, 0x1b) => Esc,
                (Outside, _) => Outside,
                (Esc, b']') => Prefix(0),
                (Esc, 0..=0x1f | 0x7f) => Esc,
                (Esc, _) => Outside,
                (_, 0x07) if osc => Outside,
                (state, 0..=0x1f) if osc => state,
                (Prefix(i), _) if c == b"7501;"[i] => {
                    if i == 4 {
                        Field(0)
                    } else {
                        Prefix(i + 1)
                    }
                }
                (Prefix(_), _) => Outside,
                (Field(_) | Value | Key, b':') => Field(0),
                (Field(i), _) if c == b"key="[i] => {
                    if i == 3 {
                        Key
                    } else {
                        Field(i + 1)
                    }
                }
                (Field(_) | Value, _) => Value,
                (Key, _) => {
                    *b = b'x';
                    Key
                }
            };
        }
    }
}

impl Core {
    /// A root report's `resume=`, from live output of the terminal's own holder,
    /// carrying the key of the program running in it. Taken at once; which
    /// process owns it is settled at the next foreground check (`check_resume`).
    pub(crate) fn resume_reported(&self, st: &mut State, id: u32, from: &str, r: &ghostty_vt::StatusReport) {
        if !r.id.is_empty() || r.state == "clear" {
            return;
        }
        let Some(report) = parse(&r.raw) else { return };
        let Some(t) = st.reg.terminals.get(&id).filter(|t| t.is_live() && t.holder.as_deref() == Some(from)) else {
            return;
        };
        if t.resume_key.as_deref().is_none_or(|k| k.as_bytes() != report.key) {
            return;
        }
        let Some(argv) = report.argv else {
            st.resume_bind.remove(&id);
            if t.resume.is_some() {
                self.set_resume(st, id, None);
            }
            return;
        };
        st.resume_bind.insert(id);
        if t.resume.as_ref().is_some_and(|r| r.argv == argv) {
            return;
        }
        let cwd = t.last_cwd.clone().unwrap_or_else(|| t.cwd.clone());
        self.set_resume(st, id, Some(Resume { argv, cwd, pid: 0 }));
    }

    /// On each foreground check: bind a new command to the program in front (not
    /// the terminal's own shell); clear the command once that program exited
    /// while the terminal lives on (a loss keeps it, and so does a host shutdown).
    pub(crate) fn check_resume(&self, st: &mut State, id: u32, now: Option<&Foreground>) {
        let Some(t) = st.reg.terminals.get(&id) else { return };
        let shell = t.pid.map(|p| p as i32);
        if st.resume_bind.contains(&id)
            && let Some(front) = now.filter(|f| Some(f.pid) != shell)
            && let Some(r) = t.resume.as_ref()
        {
            let resume = Resume { argv: r.argv.clone(), cwd: front.cwd.clone(), pid: front.pid };
            st.resume_bind.remove(&id);
            self.set_resume(st, id, Some(resume));
            return;
        }
        let exited = t.holder.is_some()
            && t.resume.as_ref().is_some_and(|r| r.pid > 0 && crate::foreground::about(r.pid).is_none());
        if exited && !crate::platform::host_shutdown_in_progress() {
            self.set_resume(st, id, None);
        }
    }

    /// Clearing also drops what was still waiting: a binding, and a command not yet typed.
    pub(crate) fn set_resume(&self, st: &mut State, id: u32, resume: Option<Resume>) {
        if resume.is_none() {
            st.resume_bind.remove(&id);
            st.resume_typing.remove(&id);
        }
        let Some(t) = st.reg.terminals.get_mut(&id) else { return };
        if t.resume == resume {
            return;
        }
        match &resume {
            Some(r) => eprintln!("core: {} resumes with {:?} in {}", t.address, r.argv, r.cwd),
            None => eprintln!("core: {} resume cleared", t.address),
        }
        t.resume = resume.clone();
        // Queued in state order: a reboot right after still finds it.
        self.save(st);
        self.emit(st, "resume", id, serde_json::json!({"resume": resume}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_last_resume_and_key_decode_into_a_plain_command() {
        let body = b"state=idle:resume=old:app=claude:resume=claude,--resume,a%20b%2Cc,/tmp/x.jsonl:key=k1";
        assert_eq!(
            parse(body),
            Some(Report { key: b"k1", argv: Some(argv(&["claude", "--resume", "a b,c", "/tmp/x.jsonl"])) })
        );
        assert_eq!(parse(b"state=idle:key=k1:resume="), Some(Report { key: b"k1", argv: None }), "empty clears");
        assert_eq!(parse(b"state=idle:resume=x").map(|r| r.key), Some(&b""[..]), "no key: never matches");
        assert_eq!(parse(b"state=idle:app=claude:key=k1"), None, "silent");
        for bad in [
            &b"state=idle:resume=/usr/bin/claude"[..], // a path
            b"state=idle:resume=-x",                   // an option
            b"state=idle:resume=sh,-c,it%27s",         // a quote
            b"state=idle:resume=sh,a%0Ab",             // a control character
            b"state=idle:resume=sh,a%5Cb",             // a backslash
            b"state=idle:resume=sh,a%2",               // a broken escape
            b"state=idle:resume=sh,a%FF",              // not UTF-8
            b"state=idle:resume=sh a",                 // outside the alphabet
        ] {
            assert_eq!(parse(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        let many = format!("state=idle:resume=a{}", ",x".repeat(MAX_ARGS));
        assert_eq!(parse(many.as_bytes()), None, "too many arguments");
    }

    #[test]
    fn keys_are_masked_wherever_records_split() {
        let stream: &[u8] = b"a\x1b]7501;state=idle:key=s3cr3t:resume=x\x07b\x1b]7501;key=k2\x1b\\c\x1b]0;key=title\x07\x1b]7501;app=akey=no:key=open";
        let want: &[u8] = b"a\x1b]7501;state=idle:key=xxxxxx:resume=x\x07b\x1b]7501;key=xx\x1b\\c\x1b]0;key=title\x07\x1b]7501;app=akey=no:key=xxxx";
        for size in [1, 2, 3, 7, 600, stream.len()] {
            let (mut masker, mut out) = (Masker::default(), Vec::new());
            for chunk in stream.chunks(size) {
                let mut chunk = chunk.to_vec();
                masker.mask(&mut chunk);
                out.extend(chunk);
            }
            assert_eq!(out, want, "in reads of {size}");
        }
        // Longer than anything a relay or parser holds back, split in the key itself.
        let long = format!("\x1b]7501;state=idle:message={}:resume=a:key=0123456789abcdef\x07", "m".repeat(3000));
        let (mut masker, mut first, mut rest) =
            (Masker::default(), long.as_bytes()[..3030].to_vec(), long.as_bytes()[3030..].to_vec());
        masker.mask(&mut first);
        masker.mask(&mut rest);
        let out = String::from_utf8([first, rest].concat()).unwrap();
        assert!(out.ends_with(":key=xxxxxxxxxxxxxxxx\x07"), "{}", &out[3000..]);
    }

    #[test]
    fn the_masker_reads_records_as_ghostty_does() {
        let mask = |bytes: &[u8]| {
            let mut out = bytes.to_vec();
            Masker::default().mask(&mut out);
            out
        };
        // CAN and SUB end any sequence, wherever in it: what follows is text, never overwritten.
        assert_eq!(mask(b"\x1b]7501;key=ab\x18text:x"), b"\x1b]7501;key=xx\x18text:x");
        assert_eq!(mask(b"\x1b]7501;key=ab\x1atext"), b"\x1b]7501;key=xx\x1atext");
        for cut in [&b"\x1b]75"[..], b"\x1b]7501;", b"\x1b]7501;ke", b"\x1b]7501;state=id"] {
            for cancel in [0x18, 0x1a] {
                let stream = [cut, &[cancel], b"key=text:more\x07"].concat();
                assert_eq!(mask(&stream), stream, "after {cut:?} and {cancel:#x}");
            }
        }
        assert_eq!(mask(b"\x1b]7501;state=\tidle:app=a\x07"), b"\x1b]7501;state=\tidle:app=a\x07");
        // Inside an OSC Ghostty drops these C0 bytes, so `key=` still counts with them in it.
        assert_eq!(mask(b"\x1b]75\t01;ke\ty=s3\x01c\x07"), b"\x1b]75\t01;ke\ty=xx\x01x\x07");
        assert_eq!(mask(b"\x1b]7501;state=idle:\x7fkey=s\x07"), b"\x1b]7501;state=idle:\x7fkey=s\x07", "DEL is put");
        // Between ESC and `]` Ghostty ignores DEL, like C0.
        assert_eq!(mask(b"\x1b\x7f]7501;key=s3\x07"), b"\x1b\x7f]7501;key=xx\x07");
        // A masker primed with a screen's unfinished record (a new core) masks the rest of its key.
        let mut primed = Masker::default();
        primed.mask(&mut b"\x1b]7501;state=idle:key=0123".to_vec());
        let mut rest = b"4567\x07after".to_vec();
        primed.mask(&mut rest);
        assert_eq!(rest, b"xxxx\x07after");
        let mut primed = Masker::default();
        primed.mask(&mut b"\x1b]7501;state=idle:".to_vec());
        let mut rest = b"key=0123\x07".to_vec();
        primed.mask(&mut rest);
        assert_eq!(rest, b"key=xxxx\x07", "split just before key=");
    }

    fn report(body: &str) -> ghostty_vt::StatusReport {
        ghostty_vt::StatusReport {
            state: "idle",
            kind: None,
            progress: None,
            id: String::new(),
            app: String::new(),
            title: String::new(),
            message: String::new(),
            raw: body.into(),
        }
    }

    /// A core with one kept, live terminal (pid 10, its shell) held by `h`, whose program got key `k`.
    fn core_with_terminal() -> (std::sync::Arc<Core>, std::path::PathBuf, u32) {
        let root = std::env::temp_dir().join(format!("hc-resume-{}", crate::platform::random_hex()));
        let paths = crate::paths::Paths {
            state: root.join("state"),
            config: root.join("config.toml"),
            socket: root.join("run/core.sock"),
            holder_socket: root.join("run/core.holder.sock"),
        };
        paths.create_dirs().unwrap();
        let info = crate::api::CoreInfo { id: "test".into(), name: "test".into() };
        let core = Core::start(paths, info).unwrap();
        let id = {
            let mut st = core.lock();
            let new = crate::terminals::NewTerminal { argv: vec!["sh".into()], keep: true, ..Default::default() };
            let id = st.reg.create(new, 0).unwrap();
            let t = st.reg.terminals.get_mut(&id).unwrap();
            (t.holder, t.resume_key, t.pid) = (Some("h".into()), Some("k".into()), Some(10));
            id
        };
        (core, root, id)
    }

    #[tokio::test]
    async fn only_the_key_counts_a_clear_cancels_what_waits_and_restored_programs_own_theirs() {
        let (core, root, id) = core_with_terminal();
        let agent = Foreground { pid: 20, name: "node-MainThread".into(), argv: vec![], cwd: "/w".into() };
        let shell = Foreground { pid: 10, ..agent.clone() };
        let resume = |core: &Core| core.lock().reg.terminals[&id].resume.clone();
        {
            let mut st = core.lock();
            for body in ["state=idle:resume=x,1", "state=idle:resume=x,1:key=bad", "state=idle:resume=x,1:key=k"] {
                core.resume_reported(&mut st, id, "other-holder", &report(body));
            }
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=x,1"));
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=x,1:key=bad"));
            assert!(st.reg.terminals[&id].resume.is_none(), "no key, a wrong key, or another holder's output");

            // Taken at once, whatever runs in front; bound to the program, never the shell.
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=qwen,--resume,1:key=k"));
            core.check_resume(&mut st, id, Some(&shell));
            assert_eq!(st.reg.terminals[&id].resume.as_ref().unwrap().pid, 0, "not the terminal's own shell");
            core.check_resume(&mut st, id, Some(&agent));
            let r = st.reg.terminals[&id].resume.clone().unwrap();
            assert_eq!((r.argv, r.cwd.as_str(), r.pid), (argv(&["qwen", "--resume", "1"]), "/w", 20));

            // R1: a replacement withdrawn before the next check stays withdrawn, with or without a command.
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=qwen,--resume,2:key=k"));
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=:key=k"));
            core.check_resume(&mut st, id, Some(&agent));
            assert!(st.reg.terminals[&id].resume.is_none());
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=qwen,--resume,3:key=k:resume="));
            core.check_resume(&mut st, id, Some(&agent));
            assert!(st.reg.terminals[&id].resume.is_none(), "the last value in one record wins");
        }

        // R1: keep --off cancels a command waiting to be bound, and one waiting to be typed.
        let call = crate::api::Call { core: &core, conn: None, plain: None };
        let keep = |on: bool| serde_json::json!({"terminal": crate::terminals::address(id), "keep": on});
        {
            let mut st = core.lock();
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=qwen,--resume,4:key=k"));
            st.resume_typing.insert(id, "qwen --resume 4\r".into());
        }
        crate::api::dispatch(&call, "terminal.keep", keep(false)).await.unwrap();
        {
            let mut st = core.lock();
            assert!(st.reg.terminals[&id].resume.is_none());
            assert!(!st.resume_bind.contains(&id) && !st.resume_typing.contains_key(&id));
            core.check_resume(&mut st, id, Some(&agent));
            assert!(st.reg.terminals[&id].resume.is_none(), "nothing comes back at the next check");
            st.resume_typing.insert(id, "x\r".into());
        }
        crate::api::dispatch(&call, "terminal.keep", keep(false)).await.unwrap();
        assert!(!core.lock().resume_typing.contains_key(&id), "even with nothing committed");
        crate::api::dispatch(&call, "terminal.keep", keep(true)).await.unwrap();

        // R2: after a restore (pid 0, a fresh key), the resumed program's first report may clear it.
        {
            let mut st = core.lock();
            let t = st.reg.terminals.get_mut(&id).unwrap();
            t.resume = Some(Resume { argv: argv(&["qwen", "--resume", "5"]), cwd: "/w".into(), pid: 0 });
            t.resume_key = Some("k2".into());
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=:key=k"));
            assert!(st.reg.terminals[&id].resume.is_some(), "the old program's key no longer counts");
        }
        {
            let mut st = core.lock();
            core.resume_reported(&mut st, id, "h", &report("state=idle:resume=:key=k2"));
        }
        assert!(resume(&core).is_none());
        core.flush_saved().await.unwrap();
        let saved = std::fs::read_to_string(root.join("state/terminals.json")).unwrap();
        assert!(!saved.contains("qwen"), "the clear is saved: {saved}");
        drop(core);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn typed_commands_quote_only_what_needs_it() {
        assert_eq!(typed(&argv(&["claude", "--resume", "abc-1"])), "claude --resume abc-1\r");
        assert_eq!(typed(&argv(&["pi", "--session", "/a b/s.jsonl", ""])), "pi --session '/a b/s.jsonl' ''\r");
    }
}
