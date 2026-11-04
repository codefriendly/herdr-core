#![cfg(unix)] // Clearing on exit needs the program in front, which a pseudo console doesn't name.
mod common;
use common::*;
use serde_json::{Value, json};

/// `fakeagent` (a copy of bash) on PATH, and `agent.sh <name> <resume>` for it:
/// it saves its key to `<name>-key`, waits for `<name>-report`, reports
/// `resume=<resume>` with its key, then waits for `<name>-quit`.
fn fake_agent(s: &mut Session) -> String {
    let bin = s.root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy(
        if std::path::Path::new("/bin/bash").exists() { "/bin/bash" } else { "/bin/sh" },
        bin.join("fakeagent"),
    )
    .unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
    s.env.push(("PATH".into(), path));
    let script = s.root.join("agent.sh");
    let body = format!(
        r#"printf %s "$HC_RESUME_KEY" > {}/"$1-key"; w "$1-report"; r "state=idle:resume=$2:key=$HC_RESUME_KEY"; w "$1-quit""#,
        s.root.display()
    );
    std::fs::write(&script, common::script(s, &body)).unwrap();
    script.display().to_string()
}

fn resume(s: &Session, t: &str) -> Value {
    get(s, t)["resume"].clone()
}

#[test]
fn a_keyed_report_counts_at_once_and_a_loss_types_it_once_per_session() {
    let mut s = Session::new();
    // Checks far apart: a report counts before any check has seen its program.
    s.env.push(("HC_FOREGROUND_MS".into(), "700".into()));
    let agent = fake_agent(&mut s);
    let dir = s.root.join("work");
    std::fs::create_dir(&dir).unwrap();
    let dir = std::fs::canonicalize(&dir).unwrap().display().to_string();
    // What another program shows can't carry the key: with none, or a wrong one, it never counts.
    let evil = s.root.join("evil");
    std::fs::write(&evil, "\x1b]7501;state=idle:resume=sh,-c,boom\x1b\\\x1b]7501;state=idle:resume=sh,x:key=0\x07")
        .unwrap();
    // On restore it reports again: a clear, with the key of the restored program.
    let command = format!("fakeagent,{agent},back,");
    let start = |name: &str| {
        // Under a shell with job control, as in a pane: the agent is not the terminal's own program.
        let body = script(
            &s,
            &format!("set -m; cd {dir}; cat {}; fakeagent {agent} {name} {command}; exec sleep 100", evil.display()),
        );
        run(&s, &["--keep", "sh", "-c", &body])
    };
    let (t1, t2) = (start("one"), start("two"));
    let mut viewer = framed::Viewer::attach(&s, &t1, 80, 24, json!({}));
    wait_until("keys saved", || s.root.join("one-key").exists() && s.root.join("two-key").exists());
    touch(&s, "one-report");
    touch(&s, "two-report");
    let want = json!(["fakeagent", agent, "back", ""]);
    for t in [&t1, &t2] {
        wait_until("resume set", || resume(&s, t)["argv"] == want);
    }
    for t in [&t1, &t2] {
        wait_until("bound to the agent", || {
            let r = get(&s, t);
            r["resume"]["pid"].as_i64() > Some(0) && r["resume"]["pid"] == r["foreground"]["pid"]
        });
        assert_eq!(resume(&s, t)["cwd"], dir);
    }
    let key = std::fs::read_to_string(s.root.join("one-key")).unwrap();
    viewer.drain(std::time::Duration::from_millis(200));
    let shown = String::from_utf8_lossy(&viewer.raw).to_string();
    assert!(shown.contains("resume=fakeagent") && !shown.contains(&key), "the key never reaches viewers: {shown:?}");
    let state = std::fs::read_to_string(s.root.join("state/herdr-core/test/terminals.json")).unwrap();
    assert!(state.contains("back"), "on disk at once: {state}");

    let status = s.json(&["server", "status"]);
    unsafe {
        libc::kill(status["pid"].as_i64().unwrap() as i32, libc::SIGKILL);
        libc::kill(status["holder"]["pid"].as_i64().unwrap() as i32, libc::SIGKILL);
    }
    wait_until("core gone", || !s.connect_ok());
    let typed = format!("fakeagent {agent} back ''");
    wait_until("one terminal resumes", || [&t1, &t2].iter().any(|t| text(&s, t).contains(&typed)));
    std::thread::sleep(std::time::Duration::from_millis(300));
    let (first, other) = if text(&s, &t1).contains(&typed) { (&t1, &t2) } else { (&t2, &t1) };
    assert!(!text(&s, other).contains(&typed), "the same session resumes once");
    assert_eq!(get(&s, first)["cwd"], dir, "in its folder");
    assert_eq!(resume(&s, first)["pid"], 0, "kept until the resumed program reports again");

    assert!(resume(&s, other).is_null(), "the duplicate keeps no copy: its shell can't claim the session");

    // The terminal that has the session is lost again: it resumes it again, the other stays a shell.
    let old = get(&s, first)["pid"].as_i64().unwrap();
    unsafe {
        libc::kill(old as i32, libc::SIGKILL);
    }
    wait_until("resumed again in a later pass", || {
        get(&s, first)["pid"].as_i64().is_some_and(|p| p != old) && text(&s, first).contains(&typed)
    });
    assert!(!text(&s, other).contains(&typed));

    // The resumed program clears it with its own, fresh key (the one killed with its shell had the old one).
    let fresh = std::fs::read_to_string(s.root.join("back-key")).unwrap();
    assert_ne!(fresh, key, "a fresh key for each program");
    touch(&s, "back-report");
    wait_until("cleared by the resumed program", || resume(&s, first).is_null());
}

#[test]
fn a_report_not_yet_bound_when_lost_binds_nothing_after_restore() {
    let mut s = Session::new();
    s.env.push(("HC_FOREGROUND_MS".into(), "2000".into()));
    let agent = fake_agent(&mut s);
    // Restored, it runs without reporting: it must not take over the old report.
    let body = script(&s, &format!("set -m; fakeagent {agent} x fakeagent,{agent},later,x; exec sleep 100"));
    let t = run(&s, &["--keep", "sh", "-c", &body]);
    wait_until("key saved", || s.root.join("x-key").exists());
    touch(&s, "x-report");
    wait_until("taken", || !resume(&s, &t).is_null());
    let holder = s.json(&["server", "status"])["holder"]["pid"].as_i64().unwrap();
    unsafe {
        libc::kill(holder as i32, libc::SIGKILL);
    }
    let typed = format!("fakeagent {agent} later x");
    wait_until_for("restored and typed", std::time::Duration::from_secs(15), || text(&s, &t).contains(&typed));
    wait_until("the restored child in front", || get(&s, &t)["foreground"]["name"] == "fakeagent");
    std::thread::sleep(std::time::Duration::from_millis(4500)); // two foreground checks
    assert_eq!(resume(&s, &t)["pid"], 0, "unbound: {}", resume(&s, &t));
}

#[test]
fn the_exit_of_its_program_clears_it_and_a_loss_keeps_it() {
    let mut s = Session::new();
    s.env.push(("HC_FOREGROUND_MS".into(), "30".into()));
    let agent = fake_agent(&mut s);
    let body = script(&s, &format!("set -m; fakeagent {agent} x fakeagent,--session,1; exec sleep 100"));
    let t = run(&s, &["--keep", "sh", "-c", &body]);
    let mut events = s.connect();
    events.call(1, "events.subscribe", json!({"terminal": t}));
    touch(&s, "x-report");
    let set = next_event(&mut events, |e| e["params"]["type"] == "resume");
    assert_eq!(set["params"]["data"]["resume"]["argv"], json!(["fakeagent", "--session", "1"]));
    wait_until("bound", || resume(&s, &t)["pid"].as_i64() > Some(0));
    touch(&s, "x-quit");
    let cleared =
        next_event(&mut events, |e| e["params"]["type"] == "resume" && e["params"]["data"]["resume"].is_null());
    assert!(cleared["params"]["data"]["resume"].is_null());
    assert!(resume(&s, &t).is_null());
    assert_eq!(get(&s, &t)["state"], "live");
}
