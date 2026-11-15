//! demo-printer-guard: print only through the guard.
//!
//! `up` starts the local network: the ce-net local dev sim (the registry where cells publish and
//! find each other), the unchanged printer twin, and the three cells on one port: `gcode.lint`,
//! `printer.guard` and the `printer.twin` door. `try-all` runs the four attempts against it and
//! writes the report. `lint <file>` prints the lint summary of one G-code file.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ce_net_proto::v3::Key;
use ce_net_proto::v3::sign::Signer;
use printer_guard::{Decision, Guard, Policy, gcode_sha256, owner_grant, twin_job};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use twin_door::{CELL, Door, Envelope, PrintBody, Twin, key_str, mint_call};

/// Public dependencies, pinned.
const TWIN_REPO: (&str, &str) = ("ce-net-printer-twin-cell", "045795d5f14439736eb14ff2e41305598f28a17f");
const SIM_REPO: (&str, &str) = ("ce-net-local-dev-sim", "0dd3be88460ae717b1ad3ac31bd698a0574c87f8");
/// The twin's `serve` listens here (fixed in printer_cell.py).
const TWIN_URL: &str = "http://127.0.0.1:8765";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn port(var: &str, default: u16) -> u16 {
    std::env::var(var).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn registry_url() -> String {
    format!("http://127.0.0.1:{}/mcp", port("PG_REGISTRY_PORT", 7979))
}

fn cells_url() -> String {
    format!("http://127.0.0.1:{}", port("PG_PORT", 7840))
}

fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The demo's fixed keys: the report names them, so they are the same on every run. A real
/// deployment uses keys of its own.
fn demo_key(label: &str) -> Signer {
    Signer::ed25519(&Sha256::digest(format!("demo-printer-guard/{label}").as_bytes()).into())
}

fn random32() -> [u8; 32] {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("/dev/urandom");
    b
}

fn node_key() -> [u8; 32] {
    let Key::Ed25519(k) = demo_key("node:printer-1").key() else { unreachable!() };
    k
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1)
}

// ---------------------------------------------------------------- registry (local dev sim)

fn rpc(tool: &str, args: Value) -> Result<Value, String> {
    let msg = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    let (_, v) = wire::post(&registry_url(), &msg, &[])?;
    if v["result"]["isError"].as_bool() == Some(true) {
        return Err(format!("{tool}: {}", v["result"]["content"][0]["text"].as_str().unwrap_or("?")));
    }
    Ok(v["result"]["structuredContent"].clone())
}

/// Find a cell's URL by its exact name in the registry.
fn find(name: &str) -> Result<String, String> {
    let r = rpc("apps_search", json!({"q": name}))?;
    r["apps"].as_array().into_iter().flatten().find(|a| a["name"] == name).and_then(|a| a["url"].as_str()).map(String::from).ok_or_else(|| format!("{name} is not published in the registry; is `cargo run -- up` running?"))
}

// ---------------------------------------------------------------- up

fn ensure_dep(deps: &Path, (name, rev): (&str, &str)) -> PathBuf {
    let dir = deps.join(name);
    if !dir.join(".git").exists() {
        eprintln!("fetching github.com/ce-net/{name} @ {}", &rev[..7]);
        let ok = Command::new("git").args(["clone", "-q", &format!("https://github.com/ce-net/{name}")]).arg(&dir).status().is_ok_and(|s| s.success());
        if !ok {
            die(format!("git clone of ce-net/{name} failed"));
        }
    }
    let ok = Command::new("git").arg("-C").arg(&dir).args(["-c", "advice.detachedHead=false", "checkout", "-q", rev]).status().is_ok_and(|s| s.success());
    if !ok {
        die(format!("{name}: cannot check out {rev}"));
    }
    dir
}

fn wait_for(what: &str, f: impl Fn() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    die(format!("{what} did not come up"));
}

struct Kids(Vec<Child>);

impl Drop for Kids {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn up() {
    let root = root_dir();
    let deps = std::env::var("PG_DEPS_DIR").map(PathBuf::from).unwrap_or_else(|_| root.join(".deps"));
    let twin_dir = ensure_dep(&deps, TWIN_REPO);
    let sim_dir = ensure_dep(&deps, SIM_REPO);
    let run = root.join(".run");
    let _ = std::fs::remove_dir_all(&run);
    std::fs::create_dir_all(&run).unwrap_or_else(|e| die(e));
    let policy: Policy = serde_json::from_str(&std::fs::read_to_string(root.join("policy.json")).unwrap_or_else(|e| die(e))).unwrap_or_else(|e| die(format!("policy.json: {e}")));
    let mut kids = Kids(Vec::new());

    // 1. The registry: ce-net-local-dev-sim, unchanged.
    let reg_port = port("PG_REGISTRY_PORT", 7979).to_string();
    kids.0.push(Command::new("python3").arg(sim_dir.join("cenet_mock.py")).arg(&reg_port).stdout(Stdio::null()).spawn().unwrap_or_else(|e| die(format!("python3: {e}"))));
    wait_for("the registry", || rpc("agent_join", json!({"name": "probe", "about": "readiness probe"})).is_ok());

    // 2. The printer twin: ce-net-printer-twin-cell, unchanged, with a secret only the door knows.
    let secret = hex::encode(random32());
    let grant = Command::new("python3").arg(twin_dir.join("printer_cell.py")).args(["grant", "printer.twin-door", "read,print"]).env("CELL_SECRET", &secret).output().unwrap_or_else(|e| die(e));
    let twin_token = String::from_utf8_lossy(&grant.stdout).trim().to_string();
    if twin_token.is_empty() {
        die("printer_cell.py grant gave no token");
    }
    kids.0.push(Command::new("python3").arg(twin_dir.join("printer_cell.py")).arg("serve").env("CELL_SECRET", &secret).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap_or_else(|e| die(e)));
    let twin = Twin { url: TWIN_URL.into(), token: twin_token };
    wait_for("the printer twin", || wire::post(&format!("{TWIN_URL}/status"), &json!({}), &[("Authorization", &format!("Bearer {}", twin.token))]).is_ok_and(|(c, _)| c == 200));

    // 3. Keys and the owner's one link to the guard.
    let owner = demo_key("person:printer-owner");
    let guard_key = demo_key("cell:printer.guard");
    let node = node_key();
    let held = owner_grant(&owner, guard_key.key(), &node, now() + 86_400, 1).unwrap_or_else(|e| die(e));
    let guard = Guard::new(policy.clone(), guard_key, demo_key("cell:printer.guard/caller"), node, held, random32());
    let door = Door::open(&run.join("door"), node, vec![owner.key()]).unwrap_or_else(|e| die(e));

    // 4. The cells, on one port.
    let state = Arc::new(Cells { guard: Mutex::new(guard), door: Mutex::new(door), twin, owner: owner.key() });
    let addr = format!("127.0.0.1:{}", port("PG_PORT", 7840));
    let s = state.clone();
    wire::serve(&addr, move |req, res| s.handle(req, res)).unwrap_or_else(|e| die(format!("{addr}: {e}")));

    // 5. Publish them so callers find them by name.
    let me = rpc("agent_join", json!({"name": "printer owner", "about": "runs printer-1 and its guard"})).unwrap_or_else(|e| die(e));
    let key = me["key"].as_str().unwrap_or_default().to_string();
    let base = cells_url();
    for (name, what) in [
        ("gcode.lint", "parse a G-code job: extents, temperatures, material, layers, time"),
        ("printer.guard", "print policy broker: checks a G-code job and forwards a single-use call to printer.twin"),
        ("printer.twin", "simulated 3D printer printer-1; start_print needs a chain rooted at the owner"),
    ] {
        rpc("app_publish", json!({"key": key, "name": name, "url": format!("{base}/{name}"), "what": what, "kind": "cell"})).unwrap_or_else(|e| die(e));
    }
    println!("up: registry {}  cells {base}  twin {TWIN_URL} (loopback, door only)", registry_url());
    println!("published: gcode.lint, printer.guard, printer.twin");
    println!("now run ./scripts/try-all.sh in another terminal (Ctrl-C here stops everything)");
    loop {
        std::thread::sleep(Duration::from_millis(500));
        for c in &mut kids.0 {
            if let Ok(Some(st)) = c.try_wait() {
                drop(kids);
                die(format!("a dependency process exited ({st})"));
            }
        }
    }
}

struct Cells {
    guard: Mutex<Guard>,
    door: Mutex<Door>,
    twin: Twin,
    owner: Key,
}

impl Cells {
    fn handle(&self, req: wire::Req, res: &mut wire::Res) {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        match req.path.as_str() {
            "/info" => res.send(200, &json!({"node": hex::encode(node_key()), "owner": key_str(&self.owner), "policy": self.guard.lock().unwrap().policy()})),
            "/gcode.lint" => match body["gcode"].as_str() {
                Some(g) => res.send(200, &serde_json::to_value(gcode_lint::lint(g)).unwrap()),
                None => res.send(400, &json!({"error": "need {gcode}"})),
            },
            "/printer.guard/print" => self.guard_print(&body, res),
            "/printer.twin/start_print" => self.door_print(&body, res),
            _ => res.send(404, &json!({"error": format!("no route {}", req.path)})),
        }
    }

    /// printer.guard: lint (through the registry), decide, forward, relay the twin's stream.
    fn guard_print(&self, body: &Value, res: &mut wire::Res) {
        let (Some(name), Some(gcode)) = (body["name"].as_str(), body["gcode"].as_str()) else {
            return res.send(400, &json!({"error": "need {name, gcode}"}));
        };
        let summary = find("gcode.lint").and_then(|u| wire::post(&u, &json!({"gcode": gcode}), &[])).and_then(|(_, v)| serde_json::from_value::<gcode_lint::Summary>(v).map_err(|e| e.to_string()));
        let summary = match summary {
            Ok(s) => s,
            Err(e) => return res.send(502, &json!({"error": format!("gcode.lint: {e}")})),
        };
        res.stream(200);
        res.line(&json!({"event": "lint", "summary": summary}));
        let (checks, decision) = self.guard.lock().unwrap().decide(name, gcode, &summary, now());
        res.line(&json!({"event": "checks", "checks": checks}));
        match decision {
            Decision::Refused { rule, reason } => res.line(&json!({"event": "refused", "by": "printer.guard", "rule": rule, "reason": reason})),
            Decision::Forward(env) => {
                res.line(&json!({"event": "forwarded", "to": "printer.twin", "envelope": env}));
                let out = find("printer.twin").and_then(|u| wire::post_lines(&format!("{u}/start_print"), &serde_json::to_value(&*env).unwrap(), |l| res.line(&l)));
                if let Err(e) = out {
                    res.line(&json!({"event": "error", "error": e}));
                }
            }
        }
    }

    /// The printer.twin door: admit, then print on the twin and stream the layers.
    fn door_print(&self, body: &Value, res: &mut wire::Res) {
        let env: Envelope = match serde_json::from_value(body.clone()) {
            Ok(e) => e,
            Err(e) => return res.send(400, &json!({"error": format!("not an envelope: {e}")})),
        };
        let admitted = self.door.lock().unwrap().admit(&env, now());
        match admitted {
            Err(r) => {
                res.stream(403);
                res.line(&json!({"event": "refused", "by": r.by, "rule": r.rule, "reason": r.reason}));
            }
            Ok(a) => {
                res.stream(200);
                res.line(&json!({"event": "admitted", "holder": a.holder}));
                match self.twin.print(&a.body, |l| res.line(&l)) {
                    Ok(st) => res.line(&json!({"event": "done", "twin": st})),
                    Err(e) => res.line(&json!({"event": "error", "error": e})),
                }
            }
        }
    }
}

// ---------------------------------------------------------------- try-all

fn read_job(p: &str) -> String {
    std::fs::read_to_string(root_dir().join(p)).unwrap_or_else(|e| die(format!("{p}: {e}")))
}

fn lines(url: &str, body: &Value) -> (u16, Vec<Value>) {
    let mut out = Vec::new();
    let code = wire::post_lines(url, body, |l| out.push(l)).unwrap_or_else(|e| die(e));
    (code, out)
}

fn event<'a>(ls: &'a [Value], name: &str) -> Option<&'a Value> {
    ls.iter().find(|l| l["event"] == name)
}

fn try_all(out: &Path) {
    let guard = find("printer.guard").unwrap_or_else(|e| die(e));
    let twin = find("printer.twin").unwrap_or_else(|e| die(e));
    let lint_url = find("gcode.lint").unwrap_or_else(|e| die(e));
    let (_, info) = wire::post(&format!("{}/info", cells_url()), &json!({}), &[]).unwrap_or_else(|e| die(e));
    let node: [u8; 32] = hex::decode(info["node"].as_str().unwrap_or("")).ok().and_then(|b| b.try_into().ok()).unwrap_or_else(|| die("bad /info"));
    let (safe_p, hot_p) = ("jobs/bracket-pla.gcode", "jobs/bracket-300c.gcode");
    let (safe, hot) = (read_job(safe_p), read_job(hot_p));
    let mut attempts = Vec::new();

    // 1. Direct to the twin, with a chain you issued yourself.
    let (_, s) = wire::post(&lint_url, &json!({"gcode": safe}), &[]).unwrap_or_else(|e| die(e));
    let summary: gcode_lint::Summary = serde_json::from_value(s).unwrap_or_else(|e| die(e));
    let you = demo_key("person:you");
    let mine = owner_grant(&you, you.key(), &node, now() + 3600, 1).unwrap_or_else(|e| die(e));
    let body = PrintBody { cell: CELL.into(), job: twin_job("bracket", &summary), gcode_sha256: gcode_sha256(&safe), layers: summary.layers.clone(), nonce: hex::encode(&random32()[..16]) };
    let direct = mint_call(&mine, &you, &you, &node, body, 7, now()).unwrap_or_else(|e| die(e));
    let (code, ls) = lines(&format!("{twin}/start_print"), &serde_json::to_value(&direct).unwrap());
    let r = event(&ls, "refused").cloned().unwrap_or(json!({}));
    attempts.push(json!({
        "n": 1, "attempt": "direct", "sent_to": "printer.twin", "job": safe_p, "at": now(),
        "asks": "start_print on the twin with a chain you signed yourself, skipping the guard",
        "http": code, "verdict": if event(&ls, "admitted").is_some() { "printed" } else { "refused" },
        "decided_by": format!("{} at the printer.twin door", r["by"].as_str().unwrap_or("?")),
        "rule": r["rule"], "reason": r["reason"], "chain_root": key_str(&you.key()),
    }));

    // 2 and 3. Through the guard.
    let mut forwarded: Option<Value> = None;
    for (n, label, path, src) in [(2, "over-temperature", hot_p, &hot), (3, "safe", safe_p, &safe)] {
        let (code, ls) = lines(&format!("{guard}/print"), &json!({"name": "bracket", "gcode": src}));
        let checks = event(&ls, "checks").map(|c| c["checks"].clone()).unwrap_or(Value::Null);
        let mut a = json!({"n": n, "attempt": label, "sent_to": "printer.guard", "job": path, "at": now(), "http": code, "checks": checks});
        if let Some(r) = event(&ls, "refused") {
            a["asks"] = json!("print a bracket with the hotend at 300 C");
            a["verdict"] = json!("refused");
            a["decided_by"] = json!(if r["by"] == "printer.guard" { "printer.guard".to_string() } else { format!("{} at the printer.twin door", r["by"].as_str().unwrap_or("?")) });
            a["rule"] = r["rule"].clone();
            a["reason"] = r["reason"].clone();
        } else {
            let layers: Vec<&Value> = ls.iter().filter(|l| l["event"] == "layer").collect();
            let done = event(&ls, "done").map(|d| d["twin"].clone()).unwrap_or(Value::Null);
            a["asks"] = json!("print the same bracket at 210 C nozzle, 60 C bed, PLA");
            a["verdict"] = json!(if done["state"] == "done" { "printed" } else { "failed" });
            a["decided_by"] = json!("printer.guard (policy), then authorize_v3 at the printer.twin door");
            a["rule"] = json!("every policy rule passed; the chain roots at the owner and allows this one job once");
            a["holder"] = event(&ls, "admitted").map(|x| x["holder"].clone()).unwrap_or(Value::Null);
            a["layers_streamed"] = json!(layers.len());
            a["first_layer"] = layers.first().map(|l| (*l).clone()).unwrap_or(Value::Null);
            a["last_layer"] = layers.last().map(|l| (*l).clone()).unwrap_or(Value::Null);
            a["twin_final"] = done;
            forwarded = event(&ls, "forwarded").map(|f| f["envelope"].clone());
        }
        attempts.push(a);
    }

    // 4. Replay the guard's forwarded call, byte for byte.
    let env = forwarded.unwrap_or_else(|| die("the safe job was not forwarded, nothing to replay"));
    let (code, ls) = lines(&format!("{twin}/start_print"), &env);
    let r = event(&ls, "refused").cloned().unwrap_or(json!({}));
    attempts.push(json!({
        "n": 4, "attempt": "replay", "sent_to": "printer.twin", "job": safe_p, "at": now(),
        "asks": "send the guard's forwarded call to the twin again, unchanged",
        "http": code, "verdict": if event(&ls, "admitted").is_some() { "printed" } else { "refused" },
        "decided_by": format!("{} at the printer.twin door", r["by"].as_str().unwrap_or("?")),
        "rule": r["rule"], "reason": r["reason"],
    }));

    let report = json!({
        "demo": "demo-printer-guard",
        "generated_at": now(),
        "cells": {"printer.guard": guard, "printer.twin": twin, "gcode.lint": lint_url},
        "printer_owner": info["owner"],
        "printer_node": info["node"],
        "policy": info["policy"],
        "attempts": attempts,
    });
    for a in report["attempts"].as_array().unwrap() {
        println!("{} {:<17} -> {:<14} {:<8} {} : {}", a["n"], a["attempt"].as_str().unwrap(), a["sent_to"].as_str().unwrap(), a["verdict"].as_str().unwrap(), a["rule"].as_str().unwrap_or(""), a["reason"].as_str().unwrap_or(""));
    }
    let mut text = serde_json::to_string_pretty(&report).unwrap();
    text.push('\n');
    std::fs::write(out, text).unwrap_or_else(|e| die(format!("{}: {e}", out.display())));
    println!("report: {}", out.display());
    let want = ["refused", "refused", "printed", "refused"];
    let got: Vec<&str> = report["attempts"].as_array().unwrap().iter().map(|a| a["verdict"].as_str().unwrap_or("")).collect();
    if got != want {
        die(format!("expected {want:?}, got {got:?}"));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("up") => up(),
        Some("try-all") => {
            let out = args.iter().position(|a| a == "--out").and_then(|i| args.get(i + 1)).map(PathBuf::from).unwrap_or_else(|| root_dir().join("proof/report.json"));
            try_all(&out)
        }
        Some("lint") => {
            let p = args.get(1).unwrap_or_else(|| die("usage: lint <file.gcode>"));
            let s = gcode_lint::lint(&std::fs::read_to_string(p).unwrap_or_else(|e| die(e)));
            println!("{}", serde_json::to_string_pretty(&s).unwrap());
        }
        _ => {
            eprintln!("usage: demo-printer-guard up | try-all [--out report.json] | lint <file.gcode>");
            std::process::exit(2);
        }
    }
}
