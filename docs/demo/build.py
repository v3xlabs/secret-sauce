"""Compose the advancement demo from one VHS recording, the drawn scenes and a timeline.

Usage: python3 build.py RAW.mp4 OUT.gif   (run in the folder where art.py drew ./art; build.sh does both)

Order on screen: panel A (the declaration), the terminal (three recorded beats with the waits cut),
panel B (the padding comparison), the end card. Six advancement toasts come one after the other,
each with a chat line at the bottom left.
"""
import re
import subprocess
import sys

import art

CS = 5                      # GIF frame delay in centiseconds: 20 fps
STEP = CS / 100             # one output frame
FPS = f"100/{CS}"
COLORS = 256

# raw beats: the screen is cleared before each one; the terminal starts clean
HOLD_AFTER_ANSWER = [1.00, 0.70, 0.90]    # terminal time kept after the last answer of each beat
LEAD = 0.10                 # clean prompt kept before the first key
PROMPT_DWELL = [None, 0.42, 0.40]         # time the hidden prompt / the question stays before the next input
A_LEN = 1.65                # panel A, seconds
B_MIN = 1.80                # panel B, at least
CARD_TAIL = 0.10
TOAST1_START = 0.20
TOAST_DELAY = 0.05          # a toast starts this long after the answer
SLIDE_IN = [0.70, 0.34, 0.08]          # share of the toast still off screen, one entry per frame
SLIDE_OUT = SLIDE_IN[::-1]
HOLD_STEPS = 29             # frames with the toast fully in place: 1.45 s
TOAST_STEPS = len(SLIDE_IN) + HOLD_STEPS + len(SLIDE_OUT)
CHAT_LINES = 4

SH = lambda cmd: subprocess.run(cmd, check=True)  # noqa: E731


def q(t, grid=STEP):
    return round(t / grid) * grid


def analyze(raw):
    out = subprocess.run(
        ["ffmpeg", "-i", raw, "-vf", "signalstats,metadata=print:key=lavfi.signalstats.YDIF", "-f", "null", "-"],
        capture_output=True, text=True, check=True).stderr
    series, t = [], 0.0
    for line in out.splitlines():
        m = re.search(r"pts_time:([0-9.]+)", line)
        if m:
            t = float(m.group(1))
        m = re.search(r"YDIF=([0-9.e+-]+)", line)
        if m:
            series.append((t, float(m.group(1))))
    big = []
    for t, y in series:
        if y > 0.5:                       # answers, questions, clears
            if big and t - big[-1] < 0.12:
                big[-1] = t               # one answer can land over two frames
            else:
                big.append(t)
    typed = [t for t, y in series if 0.15 < y <= 0.5]   # one key; the cursor blink stays below 0.15
    return big, typed, series[-1][0]


def plan(big, typed, raw_end):
    """Cut list of raw segments and, per beat, the output time of its last answer.

    Raw events, in order: generate answer, clear, set prompt, set answer, clear, rotate question, rotate answer.
    """
    assert len(big) == 7, f"expected 7 screen changes in the recording, found {len(big)}: {big}"
    gen, clear1, set_prompt, set_answer, clear2, question, rotated = big
    beats = [
        (0.0, clear1, [(gen, None)], HOLD_AFTER_ANSWER[0]),
        (clear1, clear2, [(set_prompt, PROMPT_DWELL[1]), (set_answer, None)], HOLD_AFTER_ANSWER[1]),
        (clear2, raw_end + 0.04, [(question, PROMPT_DWELL[2]), (rotated, None)], HOLD_AFTER_ANSWER[2]),
    ]
    segments, answers, cursor = [], [], 0.0
    for i, (start, end, events, hold) in enumerate(beats):
        keys = [t for t in typed if start < t < end]
        first = keys[0]
        spans = [(first - LEAD, first)]
        spans += [(t - 0.06, t + 0.12) for t in keys]
        for t, dwell in events:
            spans.append((t - 0.08, t + (dwell if dwell else 0.3)))
        last = events[-1][0]
        spans.append((last, last + hold))
        spans = sorted((max(q(a), start + 0.04 if i else 0.0), q(b)) for a, b in spans)
        merged = [list(spans[0])]
        for a, b in spans[1:]:
            if a <= merged[-1][1] + 0.001:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        for a, b in merged:
            if a <= last <= b:
                answers.append(cursor + (last - a))
            segments.append((a, b))
            cursor += b - a
    return segments, answers, cursor


def layout(answers, d_term):
    """Start of every toast, and where panel B and the end card begin; all in output seconds."""
    span = TOAST_STEPS * STEP
    starts = [q(TOAST1_START)]
    for a in answers:
        starts.append(q(max(a + A_LEN + TOAST_DELAY, starts[-1] + span)))
    b_start = q(A_LEN + d_term)
    starts.append(q(max(b_start + TOAST_DELAY, starts[-1] + span)))
    card_start = q(max(b_start + B_MIN, starts[-1] + span - STEP))
    starts.append(q(max(card_start + 0.1, starts[-1] + span)))
    total = q(starts[-1] + span + CARD_TAIL)
    return starts, b_start, card_start, total


def steps_expr(points, default):
    """Piecewise constant value of t: points are (from_time, value), ascending."""
    expr = str(points[-1][1])
    for (t, _), (_, value) in zip(reversed(points[1:]), reversed(points[:-1])):
        expr = f"if(lt(t\\,{t - 0.005:.3f})\\,{value}\\,{expr})"
    first_t = points[0][0]
    return f"if(lt(t\\,{first_t - 0.005:.3f})\\,{default}\\,{expr})"


def between(a, b):
    return f"between(t\\,{a - 0.005:.3f}\\,{b - 0.005:.3f})"


def main(raw, out):
    big, typed, raw_end = analyze(raw)
    segments, answers, d_term = plan(big, typed, raw_end)
    starts, b_start, card_start, total = layout(answers, d_term)
    t_term = A_LEN
    print("answers", [round(A_LEN + a, 2) for a in answers], "toasts", [round(s, 2) for s in starts],
          "B", round(b_start, 2), "card", round(card_start, 2), "total", round(total, 2))
    assert total <= 12.0, f"total {total:.2f} s is over 12.0 s"

    x_final = art.W - 16 - art.TOAST_W
    travel = art.TOAST_W + 16
    chat_start = [s + STEP for s in starts]
    chat_x, chat_bottom, chat_pitch = 16, art.H - 16 - art.CHAT_H, art.CHAT_H

    inputs = ["-i", raw]
    rate = ["-loop", "1", "-framerate", FPS]
    for name, dur in (("scene-a", t_term), ("scene", d_term), ("scene-b", card_start - b_start),
                      ("scene-end", total - card_start)):
        inputs += rate + ["-t", f"{dur:.3f}", "-i", f"art/{name}.png"]
    for i in range(1, 7):
        inputs += rate + ["-t", f"{total:.3f}", "-i", f"art/t{i}.png"]
    for i in range(1, 7):
        inputs += rate + ["-t", f"{total:.3f}", "-i", f"art/c{i}.png"]
    for sprite in ("bottle", "spark", "spark"):
        inputs += rate + ["-t", f"{total:.3f}", "-i", f"art/{sprite}.png"]
    t_in, c_in, e_in = 5, 11, 17

    n = len(segments)
    parts = [f"[0:v]split={n}" + "".join(f"[r{i}]" for i in range(n))]
    for i, (a, b) in enumerate(segments):
        parts.append(f"[r{i}]trim=start={a:.3f}:end={b:.3f},setpts=PTS-STARTPTS[s{i}]")
    sx, sy, sw, sh = art.SCREEN
    parts.append("".join(f"[s{i}]" for i in range(n)) +
                 f"concat=n={n}:v=1:a=0,scale={sw}:{sh}:flags=area,fps={FPS},format=rgb24[term]")
    parts.append("".join(f"[{k}:v]format=rgb24[b{k}];" for k in range(1, 5)).rstrip(";"))
    parts.append("[b1][b2][b3][b4]concat=n=4:v=1:a=0[bg]")
    parts.append(f"[term]setpts=PTS+{t_term}/TB[termd]")
    parts.append(f"[bg][termd]overlay={sx}:{sy}:enable='{between(t_term, t_term + d_term)}':format=auto[v0]")
    last = "v0"
    for i, s in enumerate(starts):
        offsets = SLIDE_IN + [0.0] + SLIDE_OUT
        times = [s + k * STEP for k in range(len(SLIDE_IN))]
        times.append(s + len(SLIDE_IN) * STEP)
        times += [s + (len(SLIDE_IN) + HOLD_STEPS + k) * STEP for k in range(len(SLIDE_OUT))]
        end = s + TOAST_STEPS * STEP
        points = list(zip(times, [x_final + round(travel * f) for f in offsets]))
        parts.append(f"[{last}][{t_in + i}:v]overlay=x='{steps_expr(points, art.W)}':y=10:"
                     f"enable='{between(s, end)}':format=auto[v{i + 1}]")
        last = f"v{i + 1}"
    for i in range(6):
        newer = chat_start[i + 1:]
        points = [(chat_start[i], chat_bottom)]
        points += [(t, chat_bottom - chat_pitch * (k + 1)) for k, t in enumerate(newer)]
        gone = chat_start[i + CHAT_LINES] if i + CHAT_LINES < 6 else total + 1
        parts.append(f"[{last}][{c_in + i}:v]overlay=x={chat_x}:y='{steps_expr(points, chat_bottom)}':"
                     f"enable='{between(chat_start[i], gone)}':format=auto[c{i + 1}]")
        last = f"c{i + 1}"
    # end card: the bottle bobs and two sparkles blink, all in two stepped positions
    beat = f"floor((t-{card_start:.3f})/0.3)"
    on = f"gte(t\\,{card_start - 0.005:.3f})"
    parts.append(f"[{last}][{e_in}:v]overlay=x=140:y='242-8*mod({beat}\\,2)':enable='{on}':format=auto[e1]")
    parts.append(f"[e1][{e_in + 1}:v]overlay=x=118:y=236:enable='{on}*lt(mod({beat}\\,2)\\,1)':format=auto[e2]")
    parts.append(f"[e2][{e_in + 2}:v]overlay=x=1006:y=252:enable='{on}*gte(mod({beat}\\,2)\\,1)':format=auto[e3]")
    last = "e3"
    mkv = "build.mkv"
    graph = ";".join(p for p in parts if p)
    SH(["ffmpeg", "-loglevel", "error", "-y", *inputs, "-filter_complex", graph,
        "-map", f"[{last}]", "-c:v", "ffv1", mkv])
    encode(mkv, out)


def encode(mkv, out):
    palette = "build-palette.png"
    SH(["ffmpeg", "-loglevel", "error", "-y", "-i", mkv, "-vf",
        f"palettegen=max_colors={COLORS}:stats_mode=full", palette])
    SH(["ffmpeg", "-loglevel", "error", "-y", "-i", mkv, "-i", palette, "-lavfi",
        "paletteuse=dither=none:diff_mode=rectangle", "-loop", "0", "build-raw.gif"])
    SH(["gifsicle", "-O3", "--no-warnings", "build-raw.gif", "-o", out])


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
