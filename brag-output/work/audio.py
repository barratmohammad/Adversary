"""Soundtrack: 120 BPM, A minor, Am-F-C-G; effects on the same 8th-note grid. Writes brag_audio.wav (44.1k stereo)."""
import wave
import numpy as np

SR, DUR, BPM = 44100, 40.0, 120
BEAT = 60 / BPM
N = int(SR * DUR)
rng = np.random.default_rng(7)
L = np.zeros(N); R = np.zeros(N)


def env(n, a=0.005, r=0.2):
    t = np.arange(n) / SR
    e = np.minimum(1, t / max(a, 1e-4)) * np.exp(-t / r)
    return e


def add(sig, t0, gain=1.0, pan=0.0):
    i = int(t0 * SR)
    if i >= N:
        return
    sig = sig[: N - i] * gain
    L[i:i + len(sig)] += sig * (1 - max(0, pan))
    R[i:i + len(sig)] += sig * (1 + min(0, pan))


def hz(midi):
    return 440 * 2 ** ((midi - 69) / 12)


CHORDS = [[57, 60, 64], [53, 57, 60], [48, 52, 55], [55, 59, 62]]  # Am F C G
BASS = [45, 41, 48, 43]


def pad(freqs, dur, gain):
    n = int(dur * SR); t = np.arange(n) / SR
    s = sum(np.sin(2 * np.pi * f * t) + 0.3 * np.sin(2 * np.pi * 2 * f * t + 0.3) + 0.15 * np.sin(2 * np.pi * f * 1.003 * t) for f in freqs)
    a = np.minimum(1, t / 0.25) * np.minimum(1, (dur - t) / 0.3)
    return s * a * gain / len(freqs)


def kick():
    n = int(0.35 * SR); t = np.arange(n) / SR
    f = 50 + 90 * np.exp(-t * 28)
    return np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t * 9)


def hat():
    n = int(0.05 * SR)
    x = rng.standard_normal(n); x = np.diff(np.concatenate([[0], x]))
    return x * env(n, 0.001, 0.012)


def snare():
    n = int(0.22 * SR); t = np.arange(n) / SR
    return (rng.standard_normal(n) * 0.6 + np.sin(2 * np.pi * 190 * t) * 0.5) * np.exp(-t * 18)


def bass(midi, dur):
    n = int(dur * SR); t = np.arange(n) / SR
    f = hz(midi)
    s = np.sin(2 * np.pi * f * t) + 0.25 * np.sin(2 * np.pi * 2 * f * t)
    return s * np.minimum(1, t / 0.01) * np.exp(-t / 0.35)


def blip(midi, g=1.0):
    n = int(0.18 * SR); t = np.arange(n) / SR
    return (np.sin(2 * np.pi * hz(midi) * t) + 0.2 * np.sin(2 * np.pi * hz(midi + 12) * t)) * env(n, 0.002, 0.06) * g


def whoosh(dur=0.6):
    n = int(dur * SR); t = np.arange(n) / SR
    x = rng.standard_normal(n)
    # simple one-pole lowpass with rising cutoff
    y = np.zeros(n); a = 0.0
    for i in range(n):
        k = 0.02 + 0.25 * (t[i] / dur) ** 2
        a += k * (x[i] - a); y[i] = a
    return y * (t / dur) ** 2 * np.minimum(1, (dur - t) / 0.03)


def low_hit():
    n = int(0.8 * SR); t = np.arange(n) / SR
    return (np.sin(2 * np.pi * hz(33) * t) + 0.5 * np.sin(2 * np.pi * hz(45) * t)) * np.exp(-t * 4) * np.minimum(1, t / 0.004)


bars = int(DUR / (4 * BEAT))
for b in range(bars):
    t0 = b * 4 * BEAT
    ch = b % 4
    outro = t0 >= 36
    drums = 4 <= t0 < 36
    add(pad([hz(m) for m in CHORDS[ch]] + [hz(CHORDS[ch][0] + 12)], 4 * BEAT + (1.6 if outro else 0.05), 0.11 if not outro else 0.13), t0)
    for k in range(8):
        tt = t0 + k * BEAT / 2
        if drums:
            if k % 2 == 0:
                add(kick(), tt, 0.55)
            if k in (2, 6):
                add(snare(), tt, 0.13, pan=0.1)
            add(hat(), tt, 0.10 if k % 2 else 0.06, pan=-0.3)
            if k in (0, 3, 4, 6):
                add(bass(BASS[ch], BEAT * 0.9), tt, 0.24)
        elif t0 < 4:
            if k % 2 == 0:
                add(hat(), tt, 0.05, pan=-0.3)
    if outro:
        add(bass(BASS[0] - 12 + 12, 3.0), t0, 0.25)

# effects, all on the 8th-note grid
for cut in (4, 8, 16, 24, 28, 36):
    add(whoosh(0.5), cut - 0.5, 0.05)
for t in (0.25, 0.5, 0.75, 1.0):                   # typing ticks under line 1
    add(blip(81, 0.35), t)
add(blip(76, 0.6), 1.5); add(blip(81, 0.6), 1.75)  # green pill
add(low_hit(), 3.0, 0.45)                           # "It's still wrong."
add(low_hit(), 4.0, 0.25)                           # reveal
for i in range(6):                                  # pipeline nodes
    add(blip([69, 72, 76, 79, 76, 81][i], 0.45), 8.5 + i)
for i, tt in enumerate((16.5, 17.0, 17.5, 18.0)):   # green check rows
    add(blip([76, 79, 81, 84][i], 0.45), tt)
add(blip(64, 0.6), 20.0); add(blip(60, 0.6), 20.25)  # red row (falling)
add(low_hit(), 21.0, 0.55)                          # MERGE BLOCKED
add(low_hit(), 25.0, 0.35)                          # GitHub failing check
for tt in (28.5, 30.5, 32.5):                       # stat cards
    add(blip(81, 0.5), tt); add(blip(88, 0.3), tt + 0.25)

mix = np.stack([L, R], axis=1)
# gentle bus: soft clip + fade out
fade = np.ones(N); nf = int(1.2 * SR); fade[-nf:] = np.linspace(1, 0, nf)
mix *= fade[:, None]
mix = np.tanh(mix * 1.4) / np.tanh(1.4)
mix *= 0.85 / max(1e-9, np.max(np.abs(mix)))
pcm = (mix * 32767).astype("<i2")
with wave.open("brag_audio.wav", "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR); w.writeframes(pcm.tobytes())
print("wrote brag_audio.wav", DUR, "s")
