//! Resume after loss: the command a program reports for itself in a root OSC
//! 7501 record (`resume=claude,--resume,abc`), typed into the replacement
//! shell. Core knows no agents: it only checks that the command names the
//! program that was in front when it came, and that the command is plain.

use crate::foreground::Foreground;
use crate::runtime::{Core, State};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
pub struct Resume {
    /// The command, as the program reported it; it starts with the program's own name.
    pub argv: Vec<String>,
    /// The folder the program ran in when it reported it.
    pub cwd: String,
    /// The process that reported it; its exit clears the command, its loss
    /// keeps it. 0 once restored, until the program reports again.
    pub pid: i32,
}

const MAX_ARGS: usize = 64;
const MAX_BYTES: usize = 8192;

/// The last `resume` value in a report body: `Some(None)` clears; `None`
/// when there is none or it is not a plain command (ignored, like unknown keys).
pub fn parse(raw: &[u8]) -> Option<Option<Vec<String>>> {
    let value = raw.split(|c| *c == b':').filter_map(|field| field.strip_prefix(b"resume=")).next_back()?;
    if value.is_empty() {
        return Some(None);
    }
    decode(value).filter(|argv| valid(argv)).map(Some)
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

/// Whether the program in front is the one a command starts. Windows names
/// end in `.exe`; Linux keeps only the first 15 bytes of a name.
pub fn names_match(front: &str, command: &str) -> bool {
    let bare = |n: &str| {
        let cut = n.len().saturating_sub(4);
        if n.get(cut..).is_some_and(|e| e.eq_ignore_ascii_case(".exe")) { n[..cut].to_string() } else { n.to_string() }
    };
    let (front, command) = (bare(front), bare(command));
    front == command || (front.len() >= 15 && command.starts_with(&front))
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

impl Core {
    /// A root report's `resume=`, from live output of the terminal's own holder.
    /// Only the program in front may set it, and the next foreground check
    /// must find that same process still there (see `check_resume`): output
    /// can arrive after its writer exited and another program started.
    pub(crate) fn resume_reported(&self, st: &mut State, id: u32, instance: &str, r: &ghostty_vt::StatusReport) {
        if !r.id.is_empty() || r.state == "clear" {
            return;
        }
        let Some(report) = parse(&r.raw) else { return };
        let Some(t) = st.reg.terminals.get(&id).filter(|t| t.is_live() && t.holder.as_deref() == Some(instance)) else {
            return;
        };
        let Some(front) = t.foreground.as_ref() else { return };
        match report {
            Some(argv) if names_match(&front.name, &argv[0]) => {
                st.resume_pending.insert(id, (argv, front.pid));
            }
            None if t.resume.as_ref().is_some_and(|r| r.pid == front.pid) => self.set_resume(st, id, None),
            _ => {}
        }
    }

    /// On each foreground check: accept a pending report whose process is
    /// still in front; clear the command once its process exited while the
    /// terminal lives on (a loss keeps it, and so does a host shutdown).
    pub(crate) fn check_resume(&self, st: &mut State, id: u32, now: Option<&Foreground>) {
        if let Some((argv, pid)) = st.resume_pending.remove(&id)
            && let Some(front) = now.filter(|f| f.pid == pid)
        {
            let resume = Resume { argv, cwd: front.cwd.clone(), pid };
            if st.reg.terminals.get(&id).and_then(|t| t.resume.as_ref()) != Some(&resume) {
                self.set_resume(st, id, Some(resume));
            }
            return;
        }
        let exited = st.reg.terminals.get(&id).is_some_and(|t| {
            t.holder.is_some()
                && t.resume.as_ref().is_some_and(|r| r.pid > 0 && crate::foreground::about(r.pid).is_none())
        });
        if exited && !crate::platform::host_shutdown_in_progress() {
            self.set_resume(st, id, None);
        }
    }

    pub(crate) fn set_resume(&self, st: &mut State, id: u32, resume: Option<Resume>) {
        let Some(t) = st.reg.terminals.get_mut(&id) else { return };
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
    fn the_last_resume_key_decodes_into_a_plain_command() {
        let body = b"state=idle:resume=old:app=claude:resume=claude,--resume,a%20b%2Cc,/tmp/x.jsonl";
        assert_eq!(parse(body), Some(Some(argv(&["claude", "--resume", "a b,c", "/tmp/x.jsonl"]))));
        assert_eq!(parse(b"state=idle:resume="), Some(None), "empty clears");
        assert_eq!(parse(b"state=idle:app=claude"), None, "silent");
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
    fn the_program_in_front_matches_by_name_without_exe_or_linux_truncation() {
        assert!(names_match("claude", "claude"));
        assert!(names_match("opencode.exe", "opencode"));
        assert!(names_match("codex.EXE", "codex"));
        assert!(names_match("averyveryverylo", "averyveryverylongname"));
        assert!(!names_match("cat", "claude"));
        assert!(!names_match("claud", "claude"), "only a full 15-byte name is a truncation");
    }

    #[test]
    fn typed_commands_quote_only_what_needs_it() {
        assert_eq!(typed(&argv(&["claude", "--resume", "abc-1"])), "claude --resume abc-1\r");
        assert_eq!(typed(&argv(&["pi", "--session", "/a b/s.jsonl", ""])), "pi --session '/a b/s.jsonl' ''\r");
    }
}
