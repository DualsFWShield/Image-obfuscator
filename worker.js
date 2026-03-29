/**
 * Obscurify — Web Worker for heavy pixel algorithms
 * Offloads all math-intensive obfuscation to a background thread.
 */

// PRNG functions (duplicated here since workers have no access to main thread)
function xmur3(str) {
    let h = 1779033703 ^ str.length;
    for (let i = 0; i < str.length; i++) {
        h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
        h = h << 13 | h >>> 19;
    }
    return function () {
        h = Math.imul(h ^ (h >>> 16), 2246822507);
        h = Math.imul(h ^ (h >>> 13), 3266489909);
        return (h ^= h >>> 16) >>> 0;
    };
}
function mulberry32(a) {
    return function () {
        var t = a += 0x6D2B79F5;
        t = Math.imul(t ^ t >>> 15, t | 1);
        t ^= t + Math.imul(t ^ t >>> 7, t | 61);
        return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
}
function getPRNG(seedStr) { return mulberry32(xmur3(seedStr)()); }
function shuffleArray(arr, prng) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(prng() * (i + 1));
        const t = arr[i]; arr[i] = arr[j]; arr[j] = t;
    }
}
const mod = (n, m) => ((n % m) + m) % m;

// --- Algorithm implementations (same as main thread) ---
function applyXorShuffle(data, w, h, prng, rev) {
    const tp = w * h, xs = new Uint8Array(tp * 3);
    for (let i = 0; i < xs.length; i++) xs[i] = Math.floor(prng() * 256);
    const idx = new Int32Array(tp);
    for (let i = 0; i < tp; i++) idx[i] = i;
    shuffleArray(idx, prng);
    const src = new Uint8Array(data), dst = new Uint8Array(data.length);
    if (!rev) {
        for (let i = 0; i < tp; i++) { const j = idx[i]; dst[j*4]=src[i*4]^xs[i*3]; dst[j*4+1]=src[i*4+1]^xs[i*3+1]; dst[j*4+2]=src[i*4+2]^xs[i*3+2]; dst[j*4+3]=src[i*4+3]; }
    } else {
        for (let i = 0; i < tp; i++) { const j = idx[i]; dst[i*4]=src[j*4]^xs[i*3]; dst[i*4+1]=src[j*4+1]^xs[i*3+1]; dst[i*4+2]=src[j*4+2]^xs[i*3+2]; dst[i*4+3]=src[j*4+3]; }
    }
    return dst;
}

function applyLogisticXOR(data, w, h, prng, rev) {
    const tp = w * h, xs = new Uint8Array(tp * 3);
    let x = prng() * 0.5 + 0.2; const r = 3.99 + prng() * 0.009;
    for (let i = 0; i < xs.length; i++) { x = r * x * (1 - x); xs[i] = Math.floor(x * 256); }
    const src = new Uint8Array(data), dst = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
        if ((i + 1) % 4 === 0) dst[i] = src[i];
        else { const pIdx = Math.floor(i / 4), cIdx = i % 4; dst[i] = src[i] ^ xs[pIdx * 3 + cIdx]; }
    }
    return dst;
}

function applyCatMap(data, w, h, prng, rev) {
    const iter = 5 + Math.floor(prng() * 15);
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(w * h);
    const mapping = new Int32Array(w * h);
    for (let i = 0; i < w * h; i++) mapping[i] = i;
    for (let it = 0; it < iter; it++) {
        const next = new Int32Array(w * h);
        for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
            if (!rev) { const nx = (x + y) % w, ny = (nx + y) % h; next[ny * w + nx] = mapping[y * w + x]; }
            else { const py = mod(y - x, h), px = mod(x - py, w); next[py * w + px] = mapping[y * w + x]; }
        }
        mapping.set(next);
    }
    for (let i = 0; i < w * h; i++) dst32[i] = src32[mapping[i]];
    return new Uint8Array(dst32.buffer);
}

function applyBakerMap(data, w, h, prng, rev) {
    const total = w * h;
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(total);
    const iter = 10 + Math.floor(prng() * 10);
    const mapping = new Int32Array(total);
    for (let i = 0; i < total; i++) mapping[i] = i;
    for (let it = 0; it < iter; it++) {
        const next = new Int32Array(total);
        if (!rev) { let l = 0, r = Math.floor((total + 1) / 2); for (let i = 0; i < total; i++) { if (i % 2 === 0) next[l++] = mapping[i]; else next[r++] = mapping[i]; } }
        else { const half = Math.floor((total + 1) / 2); for (let i = 0; i < total; i++) { if (i < half) next[i * 2] = mapping[i]; else next[(i - half) * 2 + 1] = mapping[i]; } }
        mapping.set(next);
    }
    for (let i = 0; i < total; i++) dst32[i] = src32[mapping[i]];
    return new Uint8Array(dst32.buffer);
}

function applyAffineMap(data, w, h, prng, rev) {
    const b = Math.floor(prng() * 20) + 1, c = Math.floor(prng() * 20) + 1;
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(w * h);
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
        if (!rev) { const nx = mod(x + b * y, w), ny = mod(c * nx + y, h); dst32[ny * w + nx] = src32[y * w + x]; }
        else { const py = mod(y - c * x, h), px = mod(x - b * py, w); dst32[py * w + px] = src32[y * w + x]; }
    }
    return new Uint8Array(dst32.buffer);
}

function applyWaveShift(data, w, h, prng, rev) {
    const fX = 10 + prng() * 50, aX = 10 + prng() * 100, fY = 10 + prng() * 50, aY = 10 + prng() * 100;
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(w * h);
    if (!rev) {
        const tmp = new Uint32Array(w * h);
        for (let y = 0; y < h; y++) { const s = Math.floor(Math.sin(y / fY) * aX); for (let x = 0; x < w; x++) tmp[y * w + mod(x + s, w)] = src32[y * w + x]; }
        for (let x = 0; x < w; x++) { const s = Math.floor(Math.cos(x / fX) * aY); for (let y = 0; y < h; y++) dst32[mod(y + s, h) * w + x] = tmp[y * w + x]; }
    } else {
        const tmp = new Uint32Array(w * h);
        for (let x = 0; x < w; x++) { const s = Math.floor(Math.cos(x / fX) * aY); for (let y = 0; y < h; y++) tmp[mod(y - s, h) * w + x] = src32[y * w + x]; }
        for (let y = 0; y < h; y++) { const s = Math.floor(Math.sin(y / fY) * aX); for (let x = 0; x < w; x++) dst32[y * w + mod(x - s, w)] = tmp[y * w + x]; }
    }
    return new Uint8Array(dst32.buffer);
}

function applyPrimeScatter(data, w, h, prng, rev) {
    const N = BigInt(w * h); if (N === 0n) return new Uint8Array(data);
    let P = BigInt(Math.floor(prng() * 1000000) + 1000000);
    function gcd(a, b) { while (b !== 0n) { let t = b; b = a % b; a = t; } return a; }
    function modInverse(a, m) { let m0 = m, y = 0n, x = 1n; if (m === 1n) return 0n; while (a > 1n) { let q = a / m, t = m; m = a % m; a = t; t = y; y = x - q * y; x = t; } if (x < 0n) x += m0; return x; }
    while (gcd(P, N) !== 1n) P += 1n;
    const invP = modInverse(P, N), factor = rev ? invP : P;
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(w * h);
    for (let i = 0n; i < N; i++) dst32[Number((i * factor) % N)] = src32[Number(i)];
    return new Uint8Array(dst32.buffer);
}

function applyRgbShift(data, w, h, prng, rev) {
    const drx = Math.floor(prng() * w), dry = Math.floor(prng() * h);
    const dgx = Math.floor(prng() * w), dgy = Math.floor(prng() * h);
    const dbx = Math.floor(prng() * w), dby = Math.floor(prng() * h);
    const src = new Uint8Array(data), dst = new Uint8Array(data.length);
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
        const i = (y * w + x) * 4;
        const rx = mod(rev ? x - drx : x + drx, w), ry = mod(rev ? y - dry : y + dry, h);
        const gx = mod(rev ? x - dgx : x + dgx, w), gy = mod(rev ? y - dgy : y + dgy, h);
        const bx = mod(rev ? x - dbx : x + dbx, w), by = mod(rev ? y - dby : y + dby, h);
        if (!rev) { dst[(ry*w+rx)*4]=src[i]; dst[(gy*w+gx)*4+1]=src[i+1]; dst[(by*w+bx)*4+2]=src[i+2]; }
        else { dst[i]=src[(ry*w+rx)*4]; dst[i+1]=src[(gy*w+gx)*4+1]; dst[i+2]=src[(by*w+bx)*4+2]; }
        dst[i+3] = src[i+3];
    }
    return dst;
}

// --- 6 NEW ALGORITHMS ---

// Hilbert Curve — space-filling curve permutation
function hilbertD2XY(n, d) {
    let x = 0, y = 0, rx, ry, s, t = d;
    for (s = 1; s < n; s *= 2) {
        rx = 1 & (t / 2); ry = 1 & (t ^ rx);
        if (ry === 0) { if (rx === 1) { x = s - 1 - x; y = s - 1 - y; } const tmp = x; x = y; y = tmp; }
        x += s * rx; y += s * ry; t = Math.floor(t / 4);
    }
    return [x, y];
}
function applyHilbert(data, w, h, prng, rev) {
    const total = w * h;
    let n = 1; while (n * n < total) n *= 2;
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(total);
    const offset = Math.floor(prng() * 1000000);
    const mapping = new Int32Array(total);
    let idx = 0;
    for (let d = 0; d < n * n && idx < total; d++) {
        const [hx, hy] = hilbertD2XY(n, (d + offset) % (n * n));
        if (hx < w && hy < h) { mapping[idx] = hy * w + hx; idx++; }
    }
    while (idx < total) { mapping[idx] = idx; idx++; }
    if (!rev) { for (let i = 0; i < total; i++) dst32[mapping[i]] = src32[i]; }
    else { for (let i = 0; i < total; i++) dst32[i] = src32[mapping[i]]; }
    return new Uint8Array(dst32.buffer);
}

// Spiral Scan — rearrange pixels in a spiral from center
function applySpiral(data, w, h, prng, rev) {
    const total = w * h;
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(total);
    const spiral = [];
    let top = 0, bottom = h - 1, left = 0, right = w - 1;
    while (top <= bottom && left <= right) {
        for (let x = left; x <= right; x++) spiral.push(top * w + x); top++;
        for (let y = top; y <= bottom; y++) spiral.push(y * w + right); right--;
        if (top <= bottom) { for (let x = right; x >= left; x--) spiral.push(bottom * w + x); bottom--; }
        if (left <= right) { for (let y = bottom; y >= top; y--) spiral.push(y * w + left); left++; }
    }
    if (!rev) { for (let i = 0; i < total; i++) dst32[spiral[i]] = src32[i]; }
    else { for (let i = 0; i < total; i++) dst32[i] = src32[spiral[i]]; }
    return new Uint8Array(dst32.buffer);
}

// Zigzag Transform — diagonal zigzag scan (JPEG-style)
function applyZigzag(data, w, h, prng, rev) {
    const total = w * h;
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(total);
    const order = [];
    for (let sum = 0; sum < w + h - 1; sum++) {
        if (sum % 2 === 0) { for (let y = Math.min(sum, h - 1); y >= Math.max(0, sum - w + 1); y--) order.push(y * w + (sum - y)); }
        else { for (let y = Math.max(0, sum - w + 1); y <= Math.min(sum, h - 1); y++) order.push(y * w + (sum - y)); }
    }
    if (!rev) { for (let i = 0; i < total; i++) dst32[order[i]] = src32[i]; }
    else { for (let i = 0; i < total; i++) dst32[i] = src32[order[i]]; }
    return new Uint8Array(dst32.buffer);
}

// Chirikov Standard Map — area-preserving chaotic map from physics
function applyChirikov(data, w, h, prng, rev) {
    const K = 2 + prng() * 8;
    const iter = 3 + Math.floor(prng() * 7);
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(w * h);
    const mapping = new Int32Array(w * h);
    for (let i = 0; i < w * h; i++) mapping[i] = i;
    const TWO_PI = 2 * Math.PI;
    for (let it = 0; it < iter; it++) {
        const next = new Int32Array(w * h);
        for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
            if (!rev) {
                const pn = mod(y + Math.floor(K * w * Math.sin(TWO_PI * x / w) / TWO_PI), h);
                const qn = mod(x + pn, w);
                next[pn * w + qn] = mapping[y * w + x];
            } else {
                const qp = mod(x - y, w);
                const pp = mod(y - Math.floor(K * w * Math.sin(TWO_PI * qp / w) / TWO_PI), h);
                next[pp * w + qp] = mapping[y * w + x];
            }
        }
        mapping.set(next);
    }
    for (let i = 0; i < w * h; i++) dst32[i] = src32[mapping[i]];
    return new Uint8Array(dst32.buffer);
}

// Hénon Map — 2D chaotic attractor permutation
function applyHenon(data, w, h, prng, rev) {
    const a = 1.2 + prng() * 0.2, b = 0.2 + prng() * 0.1;
    const total = w * h;
    const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(total);
    // Generate chaotic sequence for permutation
    const seq = new Float64Array(total);
    let xh = prng() * 0.5, yh = prng() * 0.5;
    for (let i = 0; i < total; i++) {
        const newX = 1 - a * xh * xh + yh;
        yh = b * xh; xh = newX;
        seq[i] = xh;
    }
    // Create sort-based permutation from sequence
    const idx = new Int32Array(total);
    for (let i = 0; i < total; i++) idx[i] = i;
    idx.sort((a, b) => seq[a] - seq[b]);
    if (!rev) { for (let i = 0; i < total; i++) dst32[idx[i]] = src32[i]; }
    else { for (let i = 0; i < total; i++) dst32[i] = src32[idx[i]]; }
    return new Uint8Array(dst32.buffer);
}

// Rubik's Cube — treat R,G,B as 3 planes, rotate rows/columns
function applyRubik(data, w, h, prng, rev) {
    const src = new Uint8Array(data), dst = new Uint8Array(data.length);
    dst.set(src);
    const numMoves = 20 + Math.floor(prng() * 40);
    const moves = [];
    for (let i = 0; i < numMoves; i++) {
        moves.push({
            channel: Math.floor(prng() * 3),
            isRow: prng() < 0.5,
            index: Math.floor(prng() * Math.max(w, h)),
            shift: Math.floor(prng() * Math.max(w, h))
        });
    }
    if (rev) moves.reverse();
    for (const m of moves) {
        const ch = m.channel;
        if (m.isRow) {
            const y = m.index % h;
            const row = new Uint8Array(w);
            for (let x = 0; x < w; x++) row[x] = dst[(y * w + x) * 4 + ch];
            for (let x = 0; x < w; x++) {
                const src_x = rev ? mod(x + m.shift, w) : mod(x - m.shift, w);
                dst[(y * w + x) * 4 + ch] = row[src_x];
            }
        } else {
            const x = m.index % w;
            const col = new Uint8Array(h);
            for (let y = 0; y < h; y++) col[y] = dst[(y * w + x) * 4 + ch];
            for (let y = 0; y < h; y++) {
                const src_y = rev ? mod(y + m.shift, h) : mod(y - m.shift, h);
                dst[(y * w + x) * 4 + ch] = col[src_y];
            }
        }
    }
    return dst;
}

// Destructive wrappers
function applyQuantizeShuffle(data, w, h, prng, rev) {
    if (!rev) { const d = new Uint8Array(data); for (let y=0;y<h;y+=4) for(let x=0;x<w;x+=4) { const i=(y*w+x)*4; const r=Math.round(d[i]/48)*48,g=Math.round(d[i+1]/48)*48,b=Math.round(d[i+2]/48)*48; for(let dy=0;dy<4&&y+dy<h;dy++) for(let dx=0;dx<4&&x+dx<w;dx++) { const idx=((y+dy)*w+(x+dx))*4; d[idx]=r;d[idx+1]=g;d[idx+2]=b; } } data = d; }
    return applyXorShuffle(data, w, h, prng, rev);
}
function applyColorCrush(data, w, h, prng, rev) {
    if (!rev) { const d = new Uint8Array(data); for(let i=0;i<d.length;i+=4) { d[i]=Math.round(d[i]/64)*64; d[i+1]=Math.round(d[i+1]/64)*64; d[i+2]=Math.round(d[i+2]/64)*64; } data = d; }
    return applyCatMap(data, w, h, prng, rev);
}
function applyBlurNoise(data, w, h, prng, rev) {
    if (!rev) { const d = new Uint8Array(data); const tmp = new Uint8Array(d); for(let y=1;y<h-1;y++) for(let x=1;x<w-1;x++) { const i=(y*w+x)*4; for(let c=0;c<3;c++) d[i+c]=(tmp[i-4+c]+tmp[i+4+c]+tmp[i-w*4+c]+tmp[i+w*4+c])>>2; } for(let i=0;i<d.length;i+=4) { d[i]=Math.min(255,Math.max(0,d[i]+(prng()-0.5)*150)); d[i+1]=Math.min(255,Math.max(0,d[i+1]+(prng()-0.5)*150)); d[i+2]=Math.min(255,Math.max(0,d[i+2]+(prng()-0.5)*150)); } data = d; }
    return applyWaveShift(data, w, h, prng, rev);
}
function applySaltPepper(data, w, h, prng, rev) {
    if (!rev) { const d32 = new Uint32Array(new Uint8Array(data).buffer.slice(0)); for(let i=0;i<d32.length;i++) { const r=prng(); if(r<0.1) d32[i]=0xFF000000; else if(r<0.2) d32[i]=0xFFFFFFFF; } data = new Uint8Array(d32.buffer); }
    return applyAffineMap(data, w, h, prng, rev);
}

// --- Block Shuffle (compression-resistant) ---
function applyBlockShuffleWorker(data, width, height, prng, reverse, blockSize) {
    const bw = Math.floor(width / blockSize);
    const bh = Math.floor(height / blockSize);
    const numBlocks = bw * bh;
    if (numBlocks < 2) return data;
    const perm = Array.from({length: numBlocks}, (_, i) => i);
    const rands = [];
    for (let i = numBlocks - 1; i > 0; i--) rands.push(Math.floor(prng() * (i + 1)));
    for (let k = 0; k < rands.length; k++) {
        const i = numBlocks - 1 - k;
        [perm[i], perm[rands[k]]] = [perm[rands[k]], perm[i]];
    }
    const src = new Uint8Array(data);
    const dst = new Uint8Array(src.length);
    dst.set(src);
    for (let bi = 0; bi < numBlocks; bi++) {
        const srcIdx = reverse ? perm[bi] : bi;
        const dstIdx = reverse ? bi : perm[bi];
        const srcX = (srcIdx % bw) * blockSize;
        const srcY = Math.floor(srcIdx / bw) * blockSize;
        const dstX = (dstIdx % bw) * blockSize;
        const dstY = Math.floor(dstIdx / bw) * blockSize;
        for (let dy = 0; dy < blockSize; dy++) {
            const srcRow = ((srcY + dy) * width + srcX) * 4;
            const dstRow = ((dstY + dy) * width + dstX) * 4;
            for (let dx = 0; dx < blockSize; dx++) {
                const si = srcRow + dx * 4;
                const di = dstRow + dx * 4;
                dst[di] = src[si]; dst[di+1] = src[si+1];
                dst[di+2] = src[si+2]; dst[di+3] = src[si+3];
            }
        }
    }
    return dst;
}
function applyBlockShuffle8(data, w, h, prng, rev) { return applyBlockShuffleWorker(data, w, h, prng, rev, 8); }
function applyBlockShuffle16(data, w, h, prng, rev) { return applyBlockShuffleWorker(data, w, h, prng, rev, 16); }

function applyDFWSWorker(data, w, h, prng, reverse) {
    const BS = 16;
    const bw = Math.floor(w / BS), bh = Math.floor(h / BS);
    const numBlocks = bw * bh;
    if (numBlocks < 5) return data;

    // Sync Anchors: Corners (index 0, top-right, bottom-left, bottom-right)
    const anchorIndices = new Set([
        0,                      // Top-left
        bw - 1,                 // Top-right
        bw * (bh - 1),          // Bottom-left
        numBlocks - 1           // Bottom-right
    ]);

    const transforms = new Array(numBlocks);
    for (let i = 0; i < numBlocks; i++) {
        transforms[i] = {
            chanRot: Math.floor(prng() * 3),
            hFlip: prng() > 0.5,
            vFlip: prng() > 0.5,
            invert: prng() > 0.5
        };
    }
    
    // Create permutation excluding anchors
    const shuffledIndices = [];
    for (let i = 0; i < numBlocks; i++) if (!anchorIndices.has(i)) shuffledIndices.push(i);
    
    const perm = [...shuffledIndices];
    for (let i = perm.length - 1; i > 0; i--) {
        const j = Math.floor(prng() * (i + 1));
        [perm[i], perm[j]] = [perm[j], perm[i]];
    }

    const src = new Uint8Array(data);
    const dst = new Uint8Array(src.length);
    dst.set(src);

    function transformBlock(srcBuf, dstBuf, sx, sy, dx, dy, tf, rev, isAnchor) {
        for (let by = 0; by < BS; by++) {
            for (let bx = 0; bx < BS; bx++) {
                const si = ((sy + by) * w + (sx + bx)) * 4;
                // If it's an anchor, we could draw a pattern, but for now we just keep it fixed
                // to act as a reference for the normalization logic.
                if (isAnchor && !rev) {
                    // Draw a checkerboard pattern in anchors to resist compression
                    const pattern = ((Math.floor(bx/4) + Math.floor(by/4)) % 2 === 0) ? 255 : 0;
                    dstBuf[((dy + by) * w + (dx + bx)) * 4] = pattern;
                    dstBuf[((dy + by) * w + (dx + bx)) * 4 + 1] = pattern;
                    dstBuf[((dy + by) * w + (dx + bx)) * 4 + 2] = pattern;
                    dstBuf[((dy + by) * w + (dx + bx)) * 4 + 3] = 255;
                    continue;
                }

                let rx = rev ? (tf.hFlip ? BS - 1 - bx : bx) : bx;
                let ry = rev ? (tf.vFlip ? BS - 1 - by : by) : by;
                let ox = !rev ? (tf.hFlip ? BS - 1 - bx : bx) : bx;
                let oy = !rev ? (tf.vFlip ? BS - 1 - by : by) : by;
                
                const cur_si = ((sy + ry) * w + (sx + rx)) * 4;
                const di = ((dy + oy) * w + (dx + ox)) * 4;
                
                let r = srcBuf[cur_si], g = srcBuf[cur_si + 1], b = srcBuf[cur_si + 2];
                if (!rev) {
                    if (tf.chanRot === 1) { const t = r; r = g; g = b; b = t; }
                    else if (tf.chanRot === 2) { const t = r; r = b; b = g; g = t; }
                    if (tf.invert) { r = 255 - r; g = 255 - g; b = 255 - b; }
                } else {
                    if (tf.invert) { r = 255 - r; g = 255 - g; b = 255 - b; }
                    if (tf.chanRot === 1) { const t = b; b = g; g = r; r = t; }
                    else if (tf.chanRot === 2) { const t = g; g = b; b = r; r = t; }
                }
                dstBuf[di] = r; dstBuf[di+1] = g; dstBuf[di+2] = b; dstBuf[di+3] = srcBuf[si+3];
            }
        }
    }

    // Process Anchors
    anchorIndices.forEach(idx => {
        const x = (idx % bw) * BS, y = Math.floor(idx / bw) * BS;
        transformBlock(src, dst, x, y, x, y, null, reverse, true);
    });

    // Process Permutable Blocks
    if (!reverse) {
        for (let i = 0; i < shuffledIndices.length; i++) {
            const srcIdx = shuffledIndices[i];
            const dstIdx = perm[i];
            const sx = (srcIdx % bw) * BS, sy = Math.floor(srcIdx / bw) * BS;
            const dx = (dstIdx % bw) * BS, dy = Math.floor(dstIdx / bw) * BS;
            transformBlock(src, dst, sx, sy, dx, dy, transforms[srcIdx], false, false);
        }
    } else {
        for (let i = 0; i < shuffledIndices.length; i++) {
            const dstIdx = shuffledIndices[i];
            const srcIdx = perm[i];
            const sx = (srcIdx % bw) * BS, sy = Math.floor(srcIdx / bw) * BS;
            const dx = (dstIdx % bw) * BS, dy = Math.floor(dstIdx / bw) * BS;
            transformBlock(src, dst, sx, sy, dx, dy, transforms[dstIdx], true, false);
        }
    }
    return dst;
}

const ALGOS = {
    'none': (data) => new Uint8Array(data), // stego-only: identity
    'xor-shuffle': applyXorShuffle, 'logistic-xor': applyLogisticXOR, 'cat-map': applyCatMap,
    'baker-map': applyBakerMap, 'affine-map': applyAffineMap, 'wave-shift': applyWaveShift,
    'prime-scatter': applyPrimeScatter, 'rgb-shift': applyRgbShift,
    'hilbert': applyHilbert, 'spiral': applySpiral, 'zigzag': applyZigzag,
    'chirikov': applyChirikov, 'henon': applyHenon, 'rubik': applyRubik,
    'block-shuffle-8': applyBlockShuffle8, 'block-shuffle-16': applyBlockShuffle16,
    'dfws': applyDFWSWorker,
    'quantize-shuffle': applyQuantizeShuffle, 'color-crush': applyColorCrush,
    'blur-noise': applyBlurNoise, 'salt-pepper': applySaltPepper
};

self.onmessage = function (e) {
    const { id, algo, data, width, height, seed, reverse, intensity } = e.data;
    const prng = getPRNG(seed);
    const fn = ALGOS[algo];
    if (!fn) { self.postMessage({ id, error: 'Unknown algo: ' + algo }); return; }

    let result = fn(new Uint8Array(data), width, height, prng, reverse);

    // Art Glitch: blend original with result by intensity (0-1)
    if (typeof intensity === 'number' && intensity < 1 && !reverse) {
        const orig = new Uint8Array(data);
        const blended = new Uint8Array(result.length);
        for (let i = 0; i < result.length; i++) {
            if ((i + 1) % 4 === 0) blended[i] = orig[i]; // keep alpha
            else blended[i] = Math.round(orig[i] * (1 - intensity) + result[i] * intensity);
        }
        result = blended;
    }

    self.postMessage({ id, result: result.buffer }, [result.buffer]);
};
