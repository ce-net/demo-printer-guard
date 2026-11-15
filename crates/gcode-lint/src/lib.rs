//! `gcode.lint@1`: read a G-code job and say what it would make the printer do.
//!
//! It parses the moves and the heater commands and returns a [`Summary`]: the extents of every
//! move, the highest hotend and bed temperatures asked for, the declared material, the layers,
//! and an estimated print time from move lengths and feed rates. It does not decide anything;
//! `printer.guard` holds the summary to a policy.
//!
//! Supported: `G0`/`G1` (X Y Z E F), `G4` (P ms, S s), `G21`, `G28`, `G90`, `G92`, `M82`, `M83`,
//! `M84`, `M104`/`M109` (S), `M140`/`M190` (S), `M106`/`M107`. `G91` (relative moves) and `G20`
//! (inches) are errors, since the bounds could not be checked the same way. Anything else is a
//! warning and is ignored.

use serde::{Deserialize, Serialize};

pub const API: &str = "gcode.lint";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Extents {
    pub min: [f64; 3],
    pub max: [f64; 3],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    /// Lines in the file.
    pub lines: usize,
    /// `G0`/`G1` moves.
    pub moves: usize,
    /// Every position the head is sent to after homing, in mm. `None` if it never moves.
    pub extents: Option<Extents>,
    pub max_nozzle_c: f64,
    pub max_bed_c: f64,
    /// From a `; material: X` or `;FILAMENT_TYPE=X` header comment, upper case.
    pub material: Option<String>,
    /// The Z height of each layer that extrudes, in order.
    pub layers: Vec<f64>,
    /// Sum of move length over feed rate, plus dwells. Heating time is not counted.
    pub est_seconds: f64,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

fn round(v: f64, places: i32) -> f64 {
    let p = 10f64.powi(places);
    (v * p).round() / p
}

/// Lint one job.
pub fn lint(src: &str) -> Summary {
    let mut s = Summary {
        lines: 0,
        moves: 0,
        extents: None,
        max_nozzle_c: 0.0,
        max_bed_c: 0.0,
        material: None,
        layers: Vec::new(),
        est_seconds: 0.0,
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    let mut pos = [0.0f64; 3];
    let mut e = 0.0f64;
    let mut feed = 1500.0f64; // mm/min until the job sets one
    let mut abs_e = true;
    let mut homed = false;
    for (i, raw) in src.lines().enumerate() {
        s.lines += 1;
        let n = i + 1;
        let (code, comment) = match raw.split_once(';') {
            Some((c, m)) => (c.trim(), m.trim()),
            None => (raw.trim(), ""),
        };
        if let Some(m) = material_of(comment) {
            s.material = Some(m);
        }
        if code.is_empty() {
            continue;
        }
        let mut words = code.split_whitespace();
        let cmd = words.next().unwrap_or("").to_ascii_uppercase();
        let mut args: Vec<(char, f64)> = Vec::new();
        let mut bad = false;
        for w in words {
            let mut ch = w.chars();
            let l = ch.next().unwrap_or(' ').to_ascii_uppercase();
            match ch.as_str().parse::<f64>() {
                Ok(v) if v.is_finite() => args.push((l, v)),
                _ => bad = true,
            }
        }
        if bad {
            s.errors.push(format!("line {n}: cannot read the numbers in `{code}`"));
            continue;
        }
        let arg = |l: char| args.iter().find(|(k, _)| *k == l).map(|(_, v)| *v);
        match cmd.as_str() {
            "G0" | "G1" => {
                s.moves += 1;
                if let Some(f) = arg('F') {
                    if f <= 0.0 {
                        s.errors.push(format!("line {n}: feed rate F{f} must be positive"));
                        continue;
                    }
                    feed = f;
                }
                let mut to = pos;
                for (k, l) in ['X', 'Y', 'Z'].iter().enumerate() {
                    if let Some(v) = arg(*l) {
                        to[k] = v;
                    }
                }
                let extrudes = match arg('E') {
                    Some(v) => {
                        let d = if abs_e { v - e } else { v };
                        e = if abs_e { v } else { e + v };
                        d > 0.0
                    }
                    None => false,
                };
                let dist = ((to[0] - pos[0]).powi(2) + (to[1] - pos[1]).powi(2) + (to[2] - pos[2]).powi(2)).sqrt();
                s.est_seconds += dist / feed * 60.0;
                if !homed {
                    s.warnings.push(format!("line {n}: a move before G28 (home)"));
                }
                pos = to;
                let ext = s.extents.get_or_insert(Extents { min: pos, max: pos });
                for k in 0..3 {
                    ext.min[k] = ext.min[k].min(pos[k]);
                    ext.max[k] = ext.max[k].max(pos[k]);
                }
                if extrudes && s.layers.last().is_none_or(|z| (z - pos[2]).abs() > 1e-6) {
                    s.layers.push(pos[2]);
                }
            }
            "G4" => s.est_seconds += arg('P').map(|p| p / 1000.0).or(arg('S')).unwrap_or(0.0).max(0.0),
            "G28" => {
                homed = true;
                pos = [0.0; 3];
            }
            "G92" => {
                if let Some(v) = arg('E') {
                    e = v;
                }
                for (k, l) in ['X', 'Y', 'Z'].iter().enumerate() {
                    if let Some(v) = arg(*l) {
                        pos[k] = v;
                    }
                }
            }
            "G91" => s.errors.push(format!("line {n}: G91 relative positioning is not supported; bounds need absolute moves")),
            "G20" => s.errors.push(format!("line {n}: G20 inches are not supported; use G21 millimetres")),
            "G21" | "G90" | "M84" | "M106" | "M107" => {}
            "M82" => abs_e = true,
            "M83" => abs_e = false,
            "M104" | "M109" => s.max_nozzle_c = s.max_nozzle_c.max(arg('S').unwrap_or(0.0)),
            "M140" | "M190" => s.max_bed_c = s.max_bed_c.max(arg('S').unwrap_or(0.0)),
            other => s.warnings.push(format!("line {n}: `{other}` is not understood and was ignored")),
        }
    }
    s.est_seconds = round(s.est_seconds, 1);
    if let Some(x) = s.extents.as_mut() {
        for k in 0..3 {
            x.min[k] = round(x.min[k], 3);
            x.max[k] = round(x.max[k], 3);
        }
    }
    s.layers = s.layers.iter().map(|z| round(*z, 3)).collect();
    if s.moves == 0 {
        s.errors.push("the job has no moves".into());
    }
    if s.layers.is_empty() {
        s.errors.push("the job never extrudes".into());
    }
    s
}

fn material_of(comment: &str) -> Option<String> {
    let c = comment.trim();
    let lower = c.to_ascii_lowercase();
    let v = if let Some(r) = lower.strip_prefix("material:") {
        &c[c.len() - r.len()..]
    } else if let Some(r) = lower.strip_prefix("filament_type=") {
        &c[c.len() - r.len()..]
    } else {
        return None;
    };
    let v = v.trim().to_ascii_uppercase();
    (!v.is_empty()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_temps_bounds_layers_and_time() {
        let s = lint("; material: pla\nM104 S215\nM140 S60\nG28\nG1 Z0.2 F600\nG1 X10 Y0 E1 F600\nG1 Z0.4\nG1 X0 E2\nM109 S300\n");
        assert_eq!(s.material.as_deref(), Some("PLA"));
        assert_eq!(s.max_nozzle_c, 300.0);
        assert_eq!(s.max_bed_c, 60.0);
        assert_eq!(s.layers, vec![0.2, 0.4]);
        assert_eq!(s.extents.unwrap().max, [10.0, 0.0, 0.4]);
        // 0.2 + 10 + 0.2 + 10 mm at 600 mm/min = 2.04 s
        assert_eq!(s.est_seconds, 2.0);
        assert!(s.errors.is_empty(), "{:?}", s.errors);
    }

    #[test]
    fn refuses_relative_and_garbage() {
        let s = lint("G28\nG91\nG1 Xabc\n");
        assert_eq!(s.errors.len(), 4, "{:?}", s.errors);
    }

    #[test]
    fn the_committed_jobs() {
        let safe = lint(include_str!("../../../jobs/bracket-pla.gcode"));
        let hot = lint(include_str!("../../../jobs/bracket-300c.gcode"));
        assert!(safe.errors.is_empty() && hot.errors.is_empty());
        assert_eq!(safe.max_nozzle_c, 210.0);
        assert_eq!(hot.max_nozzle_c, 300.0);
        assert_eq!(safe.layers.len(), 40);
        assert_eq!(safe.extents, hot.extents);
    }
}
