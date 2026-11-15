//! The front door of `printer.twin@1`: the only thing that holds the twin's own print token.
//!
//! The twin is the public `ce-net-printer-twin-cell`, run unchanged. It listens on loopback and
//! accepts `start_print` from whoever holds its HMAC token; this door is that holder. A call reaches
//! the twin only after [`Door::admit`] passes:
//!
//! 1. the call is signed by the key that holds the chain (`requester`);
//! 2. `authorize_v3`: the chain roots at the printer owner's key (the issuer check), every link is
//!    signed and inside its parent, the resource is this printer node, and the call is exactly step 0
//!    of the one program the leaf names, a `Call printer.twin start_print` pinned to the SHA-256 of
//!    this exact body, which carries the guard's nonce for this job;
//! 3. the counted-use burn log and the run log: the leaf allows one use, so the same call sent again
//!    is refused.
//!
//! Then the door starts the print on the twin and streams the layers as the simulation advances.
//!
//! This crate is also the cell's contract: [`PrintBody`] (what a capability pins) and [`Envelope`]
//! (one signed call), and [`mint_call`], how any caller builds one from a chain it holds.

use std::collections::HashSet;
use std::path::Path;

use ce_net_proto::cap::Caveats;
use ce_net_proto::program::{Hash, NodeKey, Program, ResourceV3, Step};
use ce_net_proto::v3::authorize::{Charge, Request, authorize_v3};
use ce_net_proto::v3::mint::{Grant, extend};
use ce_net_proto::v3::sign::{Signer, verify_bytes};
use ce_net_proto::v3::uses::BurnLog;
use ce_net_proto::v3::verify::{Node, Roots};
use ce_net_proto::v3::{Caveat, Key, Sig, TokenV3, UsePer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const API: &str = "printer.twin";
pub const OP_PRINT: &str = "start_print";
/// `printer.twin:start_print`, the ability a leaf must hold.
pub const ABILITY: &str = "printer.twin:start_print";
pub const CELL: &str = "printer.twin@1";
/// Domain of the bytes a requester signs to make a call.
pub const CALL_DOMAIN: &[u8] = b"printer-twin-call-v1";
/// How long a forwarded call stays valid.
pub const CALL_TTL_S: u64 = 120;

/// The twin's own `start_print` arguments (see `printer_cell.py`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwinJob {
    pub name: String,
    pub nozzle_c: f64,
    pub bed_c: f64,
    pub x_mm: f64,
    pub y_mm: f64,
    pub z_mm: f64,
    pub hours: f64,
}

/// The body of one call. Its canonical bytes are what a capability pins by SHA-256, so a chain
/// minted for this body authorizes this job, with this nonce, and nothing else.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrintBody {
    pub cell: String,
    pub job: TwinJob,
    /// `sha256:<hex>` of the G-code file the job came from.
    pub gcode_sha256: String,
    /// The Z of each layer, to report progress layer by layer.
    pub layers: Vec<f64>,
    /// Unique per forwarded job.
    pub nonce: String,
}

impl PrintBody {
    pub fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a plain struct always serializes")
    }

    pub fn sha256(&self) -> Hash {
        Sha256::digest(self.bytes()).into()
    }
}

/// One signed call to the door, as it travels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub token_hex: String,
    /// `ed25519:<hex>`, the key that holds the chain and signed this call.
    pub requester: String,
    pub run: u32,
    pub body: PrintBody,
    pub sig_hex: String,
}

pub fn key_str(k: &Key) -> String {
    match k {
        Key::Ed25519(b) => format!("ed25519:{}", hex::encode(b)),
        Key::P256(b) => format!("p256:{}", hex::encode(b)),
    }
}

fn parse_key(s: &str) -> Result<Key, String> {
    let h = s.strip_prefix("ed25519:").ok_or("requester must be ed25519:<hex>")?;
    let b: [u8; 32] = hex::decode(h).ok().and_then(|b| b.try_into().ok()).ok_or("requester key must be 32 bytes")?;
    Ok(Key::Ed25519(b))
}

/// The step a call is, as a program names it.
pub fn call_step(node: &NodeKey, body: &PrintBody) -> Step {
    Step::Call { on: *node, api: API.into(), op: OP_PRINT.into(), req_sha256: body.sha256() }
}

/// The exact bytes the requester signs.
pub fn call_message(token: &TokenV3, body: &PrintBody, run: u32) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&(CALL_DOMAIN.len() as u64).to_le_bytes());
    m.extend_from_slice(CALL_DOMAIN);
    m.extend_from_slice(&Sha256::digest(token.encode()));
    m.extend_from_slice(&body.sha256());
    m.extend_from_slice(&run.to_le_bytes());
    m
}

/// Build one call: extend `held` (a chain whose leaf lets `issuer` grant [`ABILITY`]) with a final
/// link to `caller` that allows one use of one program, `Call printer.twin start_print` of exactly
/// `body` on `node`, for [`CALL_TTL_S`]; then sign the call with `caller`.
pub fn mint_call(held: &TokenV3, issuer: &Signer, caller: &Signer, node: &NodeKey, body: PrintBody, link_nonce: u64, now: u64) -> Result<Envelope, String> {
    let program = Program::new(vec![call_step(node, &body)]);
    let leaf = Grant {
        audience: caller.key(),
        abilities: vec![ABILITY.into()],
        resource: ResourceV3::Node(*node),
        caveats: Caveats { not_after: now + CALL_TTL_S, ..Caveats::default() },
        ext: vec![Caveat::Uses { max: 1, per: UsePer::Link }, Caveat::Programs(vec![program.id()])],
        delegate: None,
        nonce: link_nonce,
    };
    let mut t = extend(held, issuer, leaf).map_err(|e| e.0)?;
    t.programs = vec![program];
    Ok(sign_call(t, caller, body, 0))
}

pub fn sign_call(t: TokenV3, caller: &Signer, body: PrintBody, run: u32) -> Envelope {
    let Sig::Ed25519(sig) = caller.sign_bytes(&call_message(&t, &body, run)) else { unreachable!("ed25519 signer") };
    Envelope { token_hex: t.to_hex(), requester: key_str(&caller.key()), run, body, sig_hex: hex::encode(sig) }
}

/// Why a call was refused: the check that said no, the rule it enforces, and its exact words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refusal {
    /// `printer.twin door` or `authorize_v3`.
    pub by: String,
    pub rule: String,
    pub reason: String,
}

/// The rule behind an `authorize_v3` refusal, in the words of this demo.
pub fn rule_of(reason: &str) -> &'static str {
    if reason.contains("accepted authority") {
        "issuer: only chains rooted at the printer owner, delegated through printer.guard"
    } else if reason.contains("used up") || reason.contains("already ran") {
        "single-use: uses 1 per link, bound to this job's nonce"
    } else if reason.contains("program") {
        "pinned job: the call must be the exact body the guard approved"
    } else if reason.contains("expired") {
        "expiry"
    } else {
        "capability"
    }
}

/// What passed the door.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub holder: String,
    pub body: PrintBody,
}

pub struct Door {
    node: NodeKey,
    roots: Vec<Key>,
    burn: BurnLog,
    /// `(leaf, program, run)` already executed.
    runs: HashSet<(Hash, Hash, u32)>,
}

impl Door {
    /// A door for printer node `node` that accepts chains rooted at `roots`, keeping its burn log
    /// in `dir`.
    pub fn open(dir: &Path, node: NodeKey, roots: Vec<Key>) -> Result<Door, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let burn = BurnLog::open(&dir.join("uses.log"))?;
        Ok(Door { node, roots, burn, runs: HashSet::new() })
    }

    pub fn node(&self) -> NodeKey {
        self.node
    }

    /// Every check, in order; the first that fails is the answer.
    pub fn admit(&mut self, env: &Envelope, now: u64) -> Result<Admitted, Refusal> {
        let door = |rule: &str, reason: String| Refusal { by: "printer.twin door".into(), rule: rule.into(), reason };
        let t = TokenV3::from_hex(env.token_hex.trim()).map_err(|e| door("capability", e.0))?;
        let requester = parse_key(&env.requester).map_err(|e| door("holder signature", e))?;
        let sig: [u8; 64] = hex::decode(env.sig_hex.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| door("holder signature", "signature must be 64 bytes of hex".into()))?;
        verify_bytes(&requester, &call_message(&t, &env.body, env.run), &Sig::Ed25519(sig))
            .map_err(|_| door("holder signature", "the call is not signed by the key it names".into()))?;
        let program = t.programs.first().map(|p| p.id()).ok_or_else(|| door("pinned job", "the token carries no program body".into()))?;
        let req = call_step(&self.node, &env.body);
        let node = Node { id: self.node, tags: &[], host: None };
        let roots = Roots { keys: &self.roots, owners: &[] };
        let self_id = self.node;
        let (burn, runs) = (&mut self.burn, &mut self.runs);
        let mut charge = |c: &Charge| -> Result<(), String> {
            let key = (c.leaf, c.program.map(|p| p.0).unwrap_or([0; 32]), c.program.map(|p| p.1).unwrap_or(0));
            if runs.contains(&key) {
                return Err("this step already ran in this run".into());
            }
            burn.charge(&self_id, now, c)?;
            runs.insert(key);
            Ok(())
        };
        let v = authorize_v3(&node, &roots, now, &requester, &Request::Execute { program, run: env.run, step: 0, req: &req }, &t, &|_, _| false, &mut charge)
            .map_err(|e| Refusal { by: "authorize_v3".into(), rule: rule_of(&e).into(), reason: e })?;
        if env.body.cell != CELL {
            return Err(door("cell", format!("this door is {CELL}, the body names {}", env.body.cell)));
        }
        Ok(Admitted { holder: key_str(&v.holder), body: env.body.clone() })
    }
}

/// The unchanged twin, reached over HTTP with its own token.
pub struct Twin {
    pub url: String,
    pub token: String,
}

impl Twin {
    fn call(&self, op: &str, minutes: u32, body: &serde_json::Value) -> Result<(u16, serde_json::Value), String> {
        let auth = format!("Bearer {}", self.token);
        let m = minutes.to_string();
        wire::post(&format!("{}/{op}", self.url.trim_end_matches('/')), body, &[("Authorization", &auth), ("X-Sim-Minutes", &m)])
    }

    /// Start `job` and advance the simulation one minute at a time, calling `each` with a layer
    /// event every time the print passes a layer, and a final event with the twin's last state.
    pub fn print(&self, body: &PrintBody, mut each: impl FnMut(serde_json::Value)) -> Result<serde_json::Value, String> {
        let (code, out) = self.call(OP_PRINT, 0, &serde_json::to_value(&body.job).unwrap())?;
        if code != 200 {
            return Err(format!("the twin refused: {}", out["error"].as_str().unwrap_or("?")));
        }
        each(serde_json::json!({"event": "started", "twin": out}));
        let of = body.layers.len();
        let mut done = 0usize;
        for _ in 0..24 * 60 {
            let (_, st) = self.call("status", 1, &serde_json::json!({}))?;
            let progress = st["progress"].as_f64().unwrap_or(0.0);
            let reached = ((progress * of as f64) + 1e-9).floor() as usize;
            while done < reached.min(of) {
                each(serde_json::json!({"event": "layer", "layer": done + 1, "of": of, "z_mm": body.layers[done], "progress": progress}));
                done += 1;
            }
            let state = st["state"].as_str().unwrap_or("");
            if state != "printing" {
                return Ok(st);
            }
        }
        Err("the print did not finish in a simulated day".into())
    }
}
