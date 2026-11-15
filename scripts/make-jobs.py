#!/usr/bin/env python3
"""Write the two demo print jobs in jobs/: the same bracket, once at safe PLA temperatures and once
with the hotend set to 300 C. Deterministic: running it again gives the same bytes."""
import os

def bracket(nozzle, bed, name):
    x0, y0, w, d, h, lh = 90.0, 100.0, 40.0, 20.0, 10.0, 0.25
    out = [f"; {name}: a 40 x 20 x 10 mm bracket", "; material: PLA", "; layer_height: 0.25",
           "G21 ; millimetres", "G90 ; absolute positioning", "M82 ; absolute extrusion",
           f"M140 S{bed}", f"M104 S{nozzle}", "G28 ; home", f"M190 S{bed}", f"M109 S{nozzle}",
           "G92 E0", "G1 Z0.3 F600"]
    e = 0.0
    layers = int(round(h / lh))
    for n in range(layers):
        z = round((n + 1) * lh, 2)
        out.append(f";LAYER:{n}")
        out.append(f"G0 Z{z:.2f} F600")
        for inset in (0.0, 0.45):
            pts = [(x0 + inset, y0 + inset), (x0 + w - inset, y0 + inset), (x0 + w - inset, y0 + d - inset),
                   (x0 + inset, y0 + d - inset), (x0 + inset, y0 + inset)]
            out.append(f"G0 X{pts[0][0]:.2f} Y{pts[0][1]:.2f} F6000")
            for (ax, ay), (bx, by) in zip(pts, pts[1:]):
                e += (abs(bx - ax) + abs(by - ay)) * 0.033
                out.append(f"G1 X{bx:.2f} Y{by:.2f} E{e:.4f} F2400")
        y = y0 + 1.0
        flip = False
        while y < y0 + d - 1.0:
            xa, xb = (x0 + 1.0, x0 + w - 1.0) if not flip else (x0 + w - 1.0, x0 + 1.0)
            out.append(f"G0 X{xa:.2f} Y{y:.2f} F6000")
            e += (w - 2.0) * 0.033
            out.append(f"G1 X{xb:.2f} Y{y:.2f} E{e:.4f} F2400")
            y += 2.0
            flip = not flip
    out += ["M104 S0", "M140 S0", "G0 Z20 F600", "M84"]
    return "\n".join(out) + "\n"

here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "jobs")
for fname, nozzle, bed in (("bracket-pla.gcode", 210, 60), ("bracket-300c.gcode", 300, 60)):
    with open(os.path.join(here, fname), "w") as f:
        f.write(bracket(nozzle, bed, fname))
    print("wrote jobs/" + fname)
