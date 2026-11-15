//! `printer.guard@1`: the policy broker in front of a printer.
//!
//! The printer owner gives the guard one link: "may grant `printer.twin:start_print`, one link
//! deep, on this printer". The guard never prints itself. For each job it gets the `gcode.lint`
//! summary, holds it to the [`Policy`] (bed bounds, hotend and bed temperature, material allowlist,
//! estimated time) and, only if every rule passes, mints a final link for that one job: one use, one
//! program pinned to the SHA-256 of the exact body (which carries a fresh nonce), two minutes to
//! live. The twin's door checks that link; nobody else's chain roots at the owner.

use ce_net_proto::cap::Caveats;
use ce_net_proto::program::{NodeKey, ResourceV3};
use ce_net_proto::v3::mint::{Grant, root_token};
use ce_net_proto::v3::sign::Signer;
use ce_net_proto::v3::{AudienceSet, Delegate, Key, TokenV3};
use gcode_lint::Summary;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use twin_door::{ABILITY, CELL, Envelope, PrintBody, TwinJob, mint_call};

pub const API: &str = "printer.guard";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Printable volume, X Y Z in mm, from the origin.
    pub bed_mm: [f64; 3],
    pub max_nozzle_c: f64,
    pub max_bed_c: f64,
    /// Upper case.
    pub materials: Vec<String>,
    pub max_minutes: f64,
}

/// One rule, held to one job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub rule: String,
    pub ok: bool,
    pub detail: String,
}

/// Every rule, in a fixed order. The first that fails decides.
pub fn evaluate(p: &Policy, s: &Summary) -> Vec<Check> {
    let c = |rule: &str, ok: bool, detail: String| Check { rule: rule.into(), ok, detail };
    let mut out = Vec::new();
    out.push(c("gcode.lint", s.errors.is_empty(), if s.errors.is_empty() { format!("{} lines, {} moves, {} layers", s.lines, s.moves, s.layers.len()) } else { s.errors.join("; ") }));
    out.push(match &s.extents {
        None => c("bed.bounds", false, "the job has no moves".into()),
        Some(x) => {
            let axis = ["X", "Y", "Z"];
            let bad: Vec<String> = (0..3)
                .filter_map(|k| {
                    if x.min[k] < 0.0 {
                        Some(format!("{} goes to {} mm, below 0", axis[k], x.min[k]))
                    } else if x.max[k] > p.bed_mm[k] {
                        Some(format!("{} goes to {} mm, past {} mm", axis[k], x.max[k], p.bed_mm[k]))
                    } else {
                        None
                    }
                })
                .collect();
            if bad.is_empty() {
                c("bed.bounds", true, format!("X 0..{} Y 0..{} Z 0..{} mm within {} x {} x {} mm", x.max[0], x.max[1], x.max[2], p.bed_mm[0], p.bed_mm[1], p.bed_mm[2]))
            } else {
                c("bed.bounds", false, bad.join("; "))
            }
        }
    });
    out.push(c("temp.nozzle", s.max_nozzle_c <= p.max_nozzle_c, format!("hotend up to {} C, max {} C", s.max_nozzle_c, p.max_nozzle_c)));
    out.push(c("temp.bed", s.max_bed_c <= p.max_bed_c, format!("bed up to {} C, max {} C", s.max_bed_c, p.max_bed_c)));
    out.push(match &s.material {
        None => c("material.allowlist", false, "the job declares no material (`; material: PLA`)".into()),
        Some(m) => c("material.allowlist", p.materials.contains(m), format!("{m}, allowed: {}", p.materials.join(", "))),
    });
    let minutes = s.est_seconds / 60.0;
    out.push(c("time.max", minutes <= p.max_minutes, format!("about {:.1} min, max {} min", minutes, p.max_minutes)));
    out
}

/// The owner's link to the guard: may grant `printer.twin:start_print` on `node`, one link deep.
pub fn owner_grant(owner: &Signer, guard: Key, node: &NodeKey, not_after: u64, nonce: u64) -> Result<TokenV3, String> {
    root_token(
        owner,
        Grant {
            audience: guard,
            abilities: vec![],
            resource: ResourceV3::Node(*node),
            caveats: Caveats { not_after, ..Caveats::default() },
            ext: vec![],
            delegate: Some(Delegate { abilities: vec![ABILITY.into()], audience: AudienceSet::Any, depth: 1 }),
            nonce,
        },
    )
    .map_err(|e| e.0)
}

/// What the twin is asked to do for a job that passed.
pub fn twin_job(name: &str, s: &Summary) -> TwinJob {
    let x = s.extents.clone().expect("a job that passed has moves");
    let hours = ((s.est_seconds / 3600.0) * 10_000.0).ceil() / 10_000.0;
    TwinJob { name: name.into(), nozzle_c: s.max_nozzle_c, bed_c: s.max_bed_c, x_mm: x.max[0], y_mm: x.max[1], z_mm: x.max[2], hours }
}

pub fn gcode_sha256(gcode: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(gcode.as_bytes())))
}

pub enum Decision {
    Refused { rule: String, reason: String },
    Forward(Box<Envelope>),
}

pub struct Guard {
    policy: Policy,
    signer: Signer,
    /// The key that makes the forwarded call (the leaf's holder).
    caller: Signer,
    node: NodeKey,
    held: TokenV3,
    secret: [u8; 32],
    seq: u64,
}

impl Guard {
    /// `held` is the owner's link to `signer`. Nonces are derived from `secret` and a counter.
    pub fn new(policy: Policy, signer: Signer, caller: Signer, node: NodeKey, held: TokenV3, secret: [u8; 32]) -> Guard {
        Guard { policy, signer, caller, node, held, secret, seq: 0 }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    fn next(&mut self, what: &str, gsha: &str) -> [u8; 32] {
        self.seq += 1;
        let mut h = Sha256::new();
        h.update(self.secret);
        h.update(what.as_bytes());
        h.update(gsha.as_bytes());
        h.update(self.seq.to_le_bytes());
        h.finalize().into()
    }

    /// Hold one job to the policy; forward it only if every rule passes.
    pub fn decide(&mut self, name: &str, gcode: &str, s: &Summary, now: u64) -> (Vec<Check>, Decision) {
        let checks = evaluate(&self.policy, s);
        if let Some(f) = checks.iter().find(|c| !c.ok) {
            let d = Decision::Refused { rule: f.rule.clone(), reason: f.detail.clone() };
            return (checks, d);
        }
        let gsha = gcode_sha256(gcode);
        let nonce = hex::encode(&self.next("body", &gsha)[..16]);
        let link_nonce = u64::from_le_bytes(self.next("link", &gsha)[..8].try_into().unwrap());
        let body = PrintBody { cell: CELL.into(), job: twin_job(name, s), gcode_sha256: gsha, layers: s.layers.clone(), nonce };
        match mint_call(&self.held, &self.signer, &self.caller, &self.node, body, link_nonce, now) {
            Ok(env) => (checks, Decision::Forward(Box::new(env))),
            Err(e) => (checks, Decision::Refused { rule: "mint".into(), reason: e }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twin_door::Door;

    fn seed(l: &str) -> [u8; 32] {
        Sha256::digest(l.as_bytes()).into()
    }

    fn policy() -> Policy {
        serde_json::from_str(include_str!("../../../policy.json")).unwrap()
    }

    #[test]
    fn the_story() {
        let now = 1_800_000_000;
        let owner = Signer::ed25519(&seed("owner"));
        let guard = Signer::ed25519(&seed("guard"));
        let you = Signer::ed25519(&seed("you"));
        let Key::Ed25519(node) = Signer::ed25519(&seed("node")).key() else { unreachable!() };
        let held = owner_grant(&owner, guard.key(), &node, now + 3600, 1).unwrap();
        let mut g = Guard::new(policy(), guard, Signer::ed25519(&seed("caller")), node, held, seed("secret"));
        let dir = std::env::temp_dir().join(format!("pg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut door = Door::open(&dir, node, vec![owner.key()]).unwrap();

        let safe_src = include_str!("../../../jobs/bracket-pla.gcode");
        let hot_src = include_str!("../../../jobs/bracket-300c.gcode");
        let safe = gcode_lint::lint(safe_src);
        let hot = gcode_lint::lint(hot_src);

        // Direct: your own chain, rooted at your key.
        let mine = owner_grant(&you, you.key(), &node, now + 3600, 2).unwrap();
        let body = PrintBody { cell: CELL.into(), job: twin_job("bracket", &safe), gcode_sha256: gcode_sha256(safe_src), layers: safe.layers.clone(), nonce: "00".into() };
        let direct = mint_call(&mine, &you, &you, &node, body, 3, now).unwrap();
        let r = door.admit(&direct, now).unwrap_err();
        assert!(r.rule.starts_with("issuer"), "{r:?}");

        // Over temperature: the guard refuses.
        let (_, d) = g.decide("bracket", hot_src, &hot, now);
        assert!(matches!(d, Decision::Refused { ref rule, .. } if rule == "temp.nozzle"));

        // Safe: forwarded, admitted once, refused on replay.
        let (_, d) = g.decide("bracket", safe_src, &safe, now);
        let Decision::Forward(env) = d else { panic!("refused") };
        door.admit(&env, now).unwrap();
        let r = door.admit(&env, now + 1).unwrap_err();
        assert!(r.rule.starts_with("single-use"), "{r:?}");
        let mut env2 = (*env).clone();
        env2.body.nonce = "ff".into();
        assert!(door.admit(&env2, now).is_err(), "an edited body is not the signed one");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
