#![cfg(unix)] // Windows has no foreground program to name: a pseudo console's is its shell.
mod common;
use common::*;
use serde_json::{Value, json};

/// A program named `fakeagent` (a copy of bash) running `agent.sh <name> <resume>`:
/// it waits for `<name>-report`, reports `resume=<resume>`, then waits for `<name>-quit`.
fn fake_agent(s: &Session) -> String {
    let bin = s.root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy(
        if std::path::Path::new("/bin/bash").exists() { "/bin/bash" } else { "/bin/sh" },
        bin.join("fakeagent"),
    )
    .unwrap();
    let script = s.root.join("agent.sh");
    std::fs::write(&script, common::script(s, r#"w "$1-report"; r "state=idle:resume=$2"; w "$1-quit""#)).unwrap();
    format!("{} {}", bin.join("fakeagent").display(), script.display())
}

fn resume(s: &Session, t: &str) -> Value {
    get(s, t)["resume"].clone()
}

#[test]
fn the_program_in_front_sets_its_resume_command_and_a_loss_types_it_once() {
    let mut s = Session::new();
    s.env.push(("HC_FOREGROUND_MS".into(), "30".into()));
    let agent = fake_agent(&s);
    let dir = s.root.join("work");
    std::fs::create_dir(&dir).unwrap();
    let dir = std::fs::canonicalize(&dir).unwrap().display().to_string();
    let evil = s.root.join("evil");
    std::fs::write(&evil, "\x1b]7501;state=idle:resume=fakeagent,--evil\x1b\\").unwrap();
    // Output shown by another program never counts, even with the named one in front right after.
    let start = |name: &str| {
        let body = script(
            &s,
            &format!("cd {dir}; w go; cat {}; exec {agent} {name} fakeagent,--session,a%20b", evil.display()),
        );
        run(&s, &["--keep", "sh", "-c", &body])
    };
    let (t1, t2) = (start("one"), start("two"));
    touch(&s, "go");
    for t in [&t1, &t2] {
        wait_until("the agent in front", || get(&s, t)["foreground"]["name"] == "fakeagent");
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(resume(&s, &t1).is_null(), "{}", resume(&s, &t1));

    touch(&s, "one-report");
    touch(&s, "two-report");
    let want = json!(["fakeagent", "--session", "a b"]);
    for t in [&t1, &t2] {
        wait_until("resume set", || resume(&s, t)["argv"] == want);
        let r = get(&s, t);
        assert_eq!(r["resume"]["cwd"], dir);
        assert_eq!(r["resume"]["pid"], r["foreground"]["pid"]);
    }
    let state = std::fs::read_to_string(s.root.join("state/herdr-core/test/terminals.json")).unwrap();
    assert!(state.contains("a b"), "on disk at once: {state}");

    let status = s.json(&["server", "status"]);
    unsafe {
        libc::kill(status["pid"].as_i64().unwrap() as i32, libc::SIGKILL);
        libc::kill(status["holder"]["pid"].as_i64().unwrap() as i32, libc::SIGKILL);
    }
    wait_until("core gone", || !s.connect_ok());
    let typed = "fakeagent --session 'a b'";
    wait_until("one terminal resumes", || [&t1, &t2].iter().any(|t| text(&s, t).contains(typed)));
    std::thread::sleep(std::time::Duration::from_millis(300));
    let resumed: Vec<_> = [&t1, &t2].into_iter().filter(|t| text(&s, t).contains(typed)).collect();
    assert_eq!(resumed.len(), 1, "the same session resumes once");
    let r = get(&s, resumed[0]);
    assert_eq!(r["cwd"], dir, "in its folder");
    assert_eq!(r["resume"]["argv"], want, "kept until the resumed program reports again");
    assert_eq!(r["resume"]["pid"], 0);

    assert!(s.json(&["keep", resumed[0], "--off"])["resume"].is_null(), "keep --off clears it");
    assert!(resume(&s, resumed[0]).is_null());
}

#[test]
fn only_a_command_naming_the_program_counts_and_its_exit_clears_it() {
    let mut s = Session::new();
    s.env.push(("HC_FOREGROUND_MS".into(), "30".into()));
    let agent = fake_agent(&s);
    let body =
        script(&s, &format!("set -m; w go; {agent} m other,--x; {agent} x fakeagent,--session,1; exec sleep 100"));
    let t = run(&s, &["--keep", "sh", "-c", &body]);
    let mut events = s.connect();
    events.call(1, "events.subscribe", json!({"terminal": t}));
    touch(&s, "go");
    wait_until("the agent in front", || get(&s, &t)["foreground"]["name"] == "fakeagent");
    touch(&s, "m-report");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(resume(&s, &t).is_null(), "another program's command: {}", resume(&s, &t));
    touch(&s, "m-quit");

    let pid = |s: &Session| get(s, &t)["foreground"]["pid"].clone();
    let first = pid(&s);
    wait_until("the next agent in front", || pid(&s) != first && get(&s, &t)["foreground"]["name"] == "fakeagent");
    touch(&s, "x-report");
    let set = next_event(&mut events, |e| e["params"]["type"] == "resume");
    assert_eq!(set["params"]["data"]["resume"]["argv"], json!(["fakeagent", "--session", "1"]));
    touch(&s, "x-quit");
    let cleared = next_event(&mut events, |e| e["params"]["type"] == "resume");
    assert!(cleared["params"]["data"]["resume"].is_null(), "{cleared}");
    assert!(resume(&s, &t).is_null());
    assert_eq!(get(&s, &t)["state"], "live");
}
