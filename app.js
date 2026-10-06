/**
 * Obscurify Pro — Enterprise Client-Side Visual Cryptography Suite
 * Clean ES6+ Architecture: Zero Network Leaks · Web Crypto API · Multi-Threaded Workers
 */

const MAGIC_V4 = '_OBFS_PRO_v4_';
const LEGACY_MAGIC = '_OBFS_SAAS_';

// ============================================================================
// 1. CRYPTO ENGINE (Web Crypto API · AES-256-GCM · PBKDF2 · SHA-256)
// ============================================================================
const CryptoEngine = {
    /**
     * Derive AES-GCM 256-bit key from password using PBKDF2 (SHA-256, 250k rounds)
     */
    async deriveKey(password, saltUint8) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            enc.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltUint8,
                iterations: 250000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    },

    /**
     * Authenticated AES-GCM encryption with 128-bit random salt and 96-bit IV
     */
    async encryptData(buffer, password) {
        if (!password) return { encrypted: buffer, salt: null, iv: null };
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await this.deriveKey(password, salt);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            buffer
        );
        return {
            encrypted,
            salt: Array.from(salt),
            iv: Array.from(iv)
        };
    },

    /**
     * Authenticated AES-GCM decryption
     */
    async decryptData(encryptedBuffer, password, saltArr, ivArr) {
        if (!password || !saltArr || !ivArr) return encryptedBuffer;
        const salt = new Uint8Array(saltArr);
        const iv = new Uint8Array(ivArr);
        const key = await this.deriveKey(password, salt);
        return await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            encryptedBuffer
        );
    },

    /**
     * Compute SHA-256 / SHA-512 hex digest of any Blob or ArrayBuffer
     */
    async hashBuffer(buffer, algo = 'SHA-256') {
        const buf = buffer instanceof Blob ? await buffer.arrayBuffer() : buffer;
        const hash = await crypto.subtle.digest(algo, buf);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * Generate deterministic salt from password for robust recovery mode
     */
    async getDeterministicSalt(password) {
        const hash = await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(password + 'OBSCURIFY_PRO_CANONICAL_SALT_v4')
        );
        return Array.from(new Uint8Array(hash).slice(0, 16))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * Calculate password entropy bits & estimated crack time
     */
    evaluateEntropy(password) {
        if (!password) return { bits: 0, text: 'Vide (Mode Public)', crackTime: 'Immédiat', level: 0 };
        let pool = 0;
        if (/[a-z]/.test(password)) pool += 26;
        if (/[A-Z]/.test(password)) pool += 26;
        if (/[0-9]/.test(password)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

        const entropy = Math.round(password.length * Math.log2(Math.max(1, pool)));
        let level = 1;
        let crackTime = 'Quelques secondes';

        if (entropy >= 80) {
            level = 4;
            crackTime = '> 1 000 ans (Niveau Militaire)';
        } else if (entropy >= 55) {
            level = 3;
            crackTime = 'Plusieurs mois / années';
        } else if (entropy >= 35) {
            level = 2;
            crackTime = 'Quelques jours / semaines';
        }

        return { bits: entropy, text: `${entropy} bits d'entropie`, crackTime, level };
    },

    bufferToBase64(buf) {
        let binary = '';
        const bytes = new Uint8Array(buf);
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    },

    base64ToBuffer(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    },

    async compress(buffer) {
        if (typeof CompressionStream === 'undefined') return buffer;
        const stream = new Blob([buffer]).stream().pipeThrough(new CompressionStream('deflate-raw'));
        return await new Response(stream).arrayBuffer();
    },

    async decompress(buffer) {
        if (typeof DecompressionStream === 'undefined') return buffer;
        try {
            const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
            return await new Response(stream).arrayBuffer();
        } catch {
            return buffer;
        }
    }
};

// ============================================================================
// 2. EXIF & METADATA INSPECTOR & STRIPPER
// ============================================================================
const EXIFCleaner = {
    /**
     * Inspect file headers for metadata tags (JPEG EXIF, PNG tEXt, WebP)
     */
    async inspect(file) {
        const buffer = await file.arrayBuffer();
        const view = new DataView(buffer);
        const metadata = {
            'Nom du fichier': file.name,
            'Format détecté': file.type || 'Inconnu',
            'Taille': `${(file.size / 1024).toFixed(1)} KB`,
            'Horodatage local': new Date(file.lastModified).toLocaleString('fr-FR'),
            'Métadonnées EXIF': 'Non détectées'
        };

        // JPEG EXIF check (Marker 0xFFE1)
        if (view.getUint16(0) === 0xFFD8) {
            let offset = 2;
            while (offset < view.byteLength) {
                const marker = view.getUint16(offset);
                offset += 2;
                if (marker === 0xFFE1) {
                    metadata['Métadonnées EXIF'] = '⚠️ Détectées (GPS, appareil photo, date de prise)';
                    metadata['Segment APP1'] = 'Présent (Contient potentiellement la géolocalisation)';
                    break;
                } else if ((marker & 0xFF00) !== 0xFF00) break;
                else {
                    const len = view.getUint16(offset);
                    offset += len;
                }
            }
        } else if (file.type === 'image/png') {
            metadata['Métadonnées EXIF'] = 'Format PNG (Chunks d\'en-tête natifs)';
        }

        return metadata;
    },

    /**
     * Strip EXIF and telemetry chunks by redrawing image on a pure memory canvas
     */
    async sanitizeImage(imgElement, format = 'image/png') {
        const canvas = document.createElement('canvas');
        canvas.width = imgElement.naturalWidth || imgElement.width;
        canvas.height = imgElement.naturalHeight || imgElement.height;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(imgElement, 0, 0);
        return await new Promise(resolve => canvas.toBlob(resolve, format));
    }
};

// ============================================================================
// 3. IN-THREAD ALGORITHM ENGINE & WORKER BRIDGE (Zero-Fail Hybrid Execution)
// ============================================================================
const InThreadExecutor = (() => {
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
            let t = a += 0x6D2B79F5;
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

    function applyXorShuffle(data, w, h, prng, rev) {
        const tp = w * h;
        const xs = new Uint8Array(tp * 3);
        for (let i = 0; i < xs.length; i++) xs[i] = Math.floor(prng() * 256);
        const idx = new Int32Array(tp);
        for (let i = 0; i < tp; i++) idx[i] = i;
        shuffleArray(idx, prng);
        const src = new Uint8Array(data);
        const dst = new Uint8Array(data.length);
        if (!rev) {
            for (let i = 0; i < tp; i++) {
                const j = idx[i];
                dst[j * 4]     = src[i * 4]     ^ xs[i * 3];
                dst[j * 4 + 1] = src[i * 4 + 1] ^ xs[i * 3 + 1];
                dst[j * 4 + 2] = src[i * 4 + 2] ^ xs[i * 3 + 2];
                dst[j * 4 + 3] = src[i * 4 + 3];
            }
        } else {
            for (let i = 0; i < tp; i++) {
                const j = idx[i];
                dst[i * 4]     = src[j * 4]     ^ xs[i * 3];
                dst[i * 4 + 1] = src[j * 4 + 1] ^ xs[i * 3 + 1];
                dst[i * 4 + 2] = src[j * 4 + 2] ^ xs[i * 3 + 2];
                dst[i * 4 + 3] = src[j * 4 + 3];
            }
        }
        return dst;
    }

    function applyLogisticXOR(data, w, h, prng, rev) {
        const tp = w * h;
        const xs = new Uint8Array(tp * 3);
        let x = prng() * 0.5 + 0.2;
        const r = 3.99 + prng() * 0.009;
        for (let i = 0; i < xs.length; i++) {
            x = r * x * (1 - x);
            xs[i] = Math.floor(x * 256);
        }
        const src = new Uint8Array(data);
        const dst = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            if ((i + 1) % 4 === 0) dst[i] = src[i];
            else {
                const pIdx = Math.floor(i / 4);
                const cIdx = i % 4;
                dst[i] = src[i] ^ xs[pIdx * 3 + cIdx];
            }
        }
        return dst;
    }

    function applyCatMap(data, w, h, prng, rev) {
        const iter = 5 + Math.floor(prng() * 15);
        const src32 = new Uint32Array(data.buffer.slice(0));
        const dst32 = new Uint32Array(w * h);
        const mapping = new Int32Array(w * h);
        for (let i = 0; i < w * h; i++) mapping[i] = i;
        for (let it = 0; it < iter; it++) {
            const next = new Int32Array(w * h);
            for (let y = 0; y < h; y++) {
                for (let x = 0; x < w; x++) {
                    if (!rev) {
                        const nx = (x + y) % w;
                        const ny = (nx + y) % h;
                        next[ny * w + nx] = mapping[y * w + x];
                    } else {
                        const py = mod(y - x, h);
                        const px = mod(x - py, w);
                        next[py * w + px] = mapping[y * w + x];
                    }
                }
            }
            mapping.set(next);
        }
        for (let i = 0; i < w * h; i++) dst32[i] = src32[mapping[i]];
        return new Uint8Array(dst32.buffer);
    }

    function applyBakerMap(data, w, h, prng, rev) {
        const total = w * h;
        const src32 = new Uint32Array(data.buffer.slice(0));
        const dst32 = new Uint32Array(total);
        const iter = 10 + Math.floor(prng() * 10);
        const mapping = new Int32Array(total);
        for (let i = 0; i < total; i++) mapping[i] = i;
        for (let it = 0; it < iter; it++) {
            const next = new Int32Array(total);
            if (!rev) {
                let l = 0, r = Math.floor((total + 1) / 2);
                for (let i = 0; i < total; i++) {
                    if (i % 2 === 0) next[l++] = mapping[i];
                    else next[r++] = mapping[i];
                }
            } else {
                const half = Math.floor((total + 1) / 2);
                for (let i = 0; i < total; i++) {
                    if (i < half) next[i * 2] = mapping[i];
                    else next[(i - half) * 2 + 1] = mapping[i];
                }
            }
            mapping.set(next);
        }
        for (let i = 0; i < total; i++) dst32[i] = src32[mapping[i]];
        return new Uint8Array(dst32.buffer);
    }

    function applyAffineMap(data, w, h, prng, rev) {
        const b = Math.floor(prng() * 20) + 1, c = Math.floor(prng() * 20) + 1;
        const src32 = new Uint32Array(data.buffer.slice(0));
        const dst32 = new Uint32Array(w * h);
        for (let y = 0; y < h; y++) {
            for (let x = 0; x < w; x++) {
                if (!rev) {
                    const nx = mod(x + b * y, w), ny = mod(c * nx + y, h);
                    dst32[ny * w + nx] = src32[y * w + x];
                } else {
                    const py = mod(y - c * x, h), px = mod(x - b * py, w);
                    dst32[py * w + px] = src32[y * w + x];
                }
            }
        }
        return new Uint8Array(dst32.buffer);
    }

    function applyWaveShift(data, w, h, prng, rev) {
        const fX = 10 + prng() * 50, aX = 10 + prng() * 100;
        const fY = 10 + prng() * 50, aY = 10 + prng() * 100;
        const src32 = new Uint32Array(data.buffer.slice(0));
        const dst32 = new Uint32Array(w * h);
        if (!rev) {
            const tmp = new Uint32Array(w * h);
            for (let y = 0; y < h; y++) {
                const s = Math.floor(Math.sin(y / fY) * aX);
                for (let x = 0; x < w; x++) tmp[y * w + mod(x + s, w)] = src32[y * w + x];
            }
            for (let x = 0; x < w; x++) {
                const s = Math.floor(Math.cos(x / fX) * aY);
                for (let y = 0; y < h; y++) dst32[mod(y + s, h) * w + x] = tmp[y * w + x];
            }
        } else {
            const tmp = new Uint32Array(w * h);
            for (let x = 0; x < w; x++) {
                const s = Math.floor(Math.cos(x / fX) * aY);
                for (let y = 0; y < h; y++) tmp[mod(y - s, h) * w + x] = src32[y * w + x];
            }
            for (let y = 0; y < h; y++) {
                const s = Math.floor(Math.sin(y / fY) * aX);
                for (let x = 0; x < w; x++) dst32[y * w + mod(x - s, w)] = tmp[y * w + x];
            }
        }
        return new Uint8Array(dst32.buffer);
    }

    function applyPrimeScatter(data, w, h, prng, rev) {
        const N = BigInt(w * h);
        if (N === 0n) return new Uint8Array(data);
        let P = BigInt(Math.floor(prng() * 1000000) + 1000000);
        function gcd(a, b) { while (b !== 0n) { let t = b; b = a % b; a = t; } return a; }
        function modInverse(a, m) {
            let m0 = m, y = 0n, x = 1n;
            if (m === 1n) return 0n;
            while (a > 1n) { let q = a / m, t = m; m = a % m; a = t; t = y; y = x - q * y; x = t; }
            if (x < 0n) x += m0;
            return x;
        }
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
        for (let y = 0; y < h; y++) {
            for (let x = 0; x < w; x++) {
                const i = (y * w + x) * 4;
                const rx = mod(rev ? x - drx : x + drx, w), ry = mod(rev ? y - dry : y + dry, h);
                const gx = mod(rev ? x - dgx : x + dgx, w), gy = mod(rev ? y - dgy : y + dgy, h);
                const bx = mod(rev ? x - dbx : x + dbx, w), by = mod(rev ? y - dby : y + dby, h);
                if (!rev) {
                    dst[(ry * w + rx) * 4]     = src[i];
                    dst[(gy * w + gx) * 4 + 1] = src[i + 1];
                    dst[(by * w + bx) * 4 + 2] = src[i + 2];
                } else {
                    dst[i]     = src[(ry * w + rx) * 4];
                    dst[i + 1] = src[(gy * w + gx) * 4 + 1];
                    dst[i + 2] = src[(by * w + bx) * 4 + 2];
                }
                dst[i + 3] = src[i + 3];
            }
        }
        return dst;
    }

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
        const offset = Math.floor(prng() * 1000000), mapping = new Int32Array(total);
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

    function applyChirikov(data, w, h, prng, rev) {
        const K = 2 + prng() * 8, iter = 3 + Math.floor(prng() * 7);
        const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(w * h);
        const mapping = new Int32Array(w * h); for (let i = 0; i < w * h; i++) mapping[i] = i;
        const TWO_PI = 2 * Math.PI;
        for (let it = 0; it < iter; it++) {
            const next = new Int32Array(w * h);
            for (let y = 0; y < h; y++) {
                for (let x = 0; x < w; x++) {
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
            }
            mapping.set(next);
        }
        for (let i = 0; i < w * h; i++) dst32[i] = src32[mapping[i]];
        return new Uint8Array(dst32.buffer);
    }

    function applyHenon(data, w, h, prng, rev) {
        const a = 1.2 + prng() * 0.2, b = 0.2 + prng() * 0.1, total = w * h;
        const src32 = new Uint32Array(data.buffer.slice(0)), dst32 = new Uint32Array(total);
        const seq = new Float64Array(total);
        let xh = prng() * 0.5, yh = prng() * 0.5;
        for (let i = 0; i < total; i++) {
            const newX = 1 - a * xh * xh + yh; yh = b * xh; xh = newX; seq[i] = xh;
        }
        const idx = new Int32Array(total);
        for (let i = 0; i < total; i++) idx[i] = i;
        idx.sort((i1, i2) => seq[i1] - seq[i2]);
        if (!rev) { for (let i = 0; i < total; i++) dst32[idx[i]] = src32[i]; }
        else { for (let i = 0; i < total; i++) dst32[i] = src32[idx[i]]; }
        return new Uint8Array(dst32.buffer);
    }

    function applyRubik(data, w, h, prng, rev) {
        const src = new Uint8Array(data), dst = new Uint8Array(data.length); dst.set(src);
        const numMoves = 20 + Math.floor(prng() * 40), moves = [];
        for (let i = 0; i < numMoves; i++) {
            moves.push({ channel: Math.floor(prng() * 3), isRow: prng() < 0.5, index: Math.floor(prng() * Math.max(w, h)), shift: Math.floor(prng() * Math.max(w, h)) });
        }
        if (rev) moves.reverse();
        for (const m of moves) {
            const ch = m.channel;
            if (m.isRow) {
                const y = m.index % h, row = new Uint8Array(w);
                for (let x = 0; x < w; x++) row[x] = dst[(y * w + x) * 4 + ch];
                for (let x = 0; x < w; x++) dst[(y * w + x) * 4 + ch] = row[rev ? mod(x + m.shift, w) : mod(x - m.shift, w)];
            } else {
                const x = m.index % w, col = new Uint8Array(h);
                for (let y = 0; y < h; y++) col[y] = dst[(y * w + x) * 4 + ch];
                for (let y = 0; y < h; y++) dst[(y * w + x) * 4 + ch] = col[rev ? mod(y + m.shift, h) : mod(y - m.shift, h)];
            }
        }
        return dst;
    }

    function applyBlockShuffleWorker(data, width, height, prng, reverse, blockSize) {
        const bw = Math.floor(width / blockSize), bh = Math.floor(height / blockSize), numBlocks = bw * bh;
        if (numBlocks < 2) return data;
        const perm = Array.from({ length: numBlocks }, (_, i) => i), rands = [];
        for (let i = numBlocks - 1; i > 0; i--) rands.push(Math.floor(prng() * (i + 1)));
        for (let k = 0; k < rands.length; k++) { const i = numBlocks - 1 - k; [perm[i], perm[rands[k]]] = [perm[rands[k]], perm[i]]; }
        const src = new Uint8Array(data), dst = new Uint8Array(src.length); dst.set(src);
        for (let bi = 0; bi < numBlocks; bi++) {
            const srcIdx = reverse ? perm[bi] : bi, dstIdx = reverse ? bi : perm[bi];
            const srcX = (srcIdx % bw) * blockSize, srcY = Math.floor(srcIdx / bw) * blockSize;
            const dstX = (dstIdx % bw) * blockSize, dstY = Math.floor(dstIdx / bw) * blockSize;
            for (let dy = 0; dy < blockSize; dy++) {
                const srcRow = ((srcY + dy) * width + srcX) * 4, dstRow = ((dstY + dy) * width + dstX) * 4;
                for (let dx = 0; dx < blockSize; dx++) {
                    const si = srcRow + dx * 4, di = dstRow + dx * 4;
                    dst[di] = src[si]; dst[di + 1] = src[si + 1]; dst[di + 2] = src[si + 2]; dst[di + 3] = src[si + 3];
                }
            }
        }
        return dst;
    }

    function applyDFWSWorker(data, w, h, prng, reverse) {
        const BS = 16, bw = Math.floor(w / BS), bh = Math.floor(h / BS), numBlocks = bw * bh;
        if (numBlocks < 5) return data;
        const anchorIndices = new Set([0, bw - 1, bw * (bh - 1), numBlocks - 1]);
        const transforms = new Array(numBlocks);
        for (let i = 0; i < numBlocks; i++) transforms[i] = { chanRot: Math.floor(prng() * 3), hFlip: prng() > 0.5, vFlip: prng() > 0.5, invert: prng() > 0.5 };
        const shuffledIndices = [];
        for (let i = 0; i < numBlocks; i++) if (!anchorIndices.has(i)) shuffledIndices.push(i);
        const perm = [...shuffledIndices];
        for (let i = perm.length - 1; i > 0; i--) { const j = Math.floor(prng() * (i + 1)); [perm[i], perm[j]] = [perm[j], perm[i]]; }
        const src = new Uint8Array(data), dst = new Uint8Array(src.length); dst.set(src);

        function transformBlock(srcBuf, dstBuf, sx, sy, dx, dy, tf, rev, isAnchor) {
            for (let by = 0; by < BS; by++) {
                for (let bx = 0; bx < BS; bx++) {
                    const si = ((sy + by) * w + (sx + bx)) * 4;
                    if (isAnchor) {
                        const di = ((dy + by) * w + (dx + bx)) * 4;
                        dstBuf[di]     = 255 - srcBuf[si];
                        dstBuf[di + 1] = 255 - srcBuf[si + 1];
                        dstBuf[di + 2] = 255 - srcBuf[si + 2];
                        dstBuf[di + 3] = srcBuf[si + 3];
                        continue;
                    }
                    const rx = rev ? (tf.hFlip ? BS - 1 - bx : bx) : bx, ry = rev ? (tf.vFlip ? BS - 1 - by : by) : by;
                    const ox = !rev ? (tf.hFlip ? BS - 1 - bx : bx) : bx, oy = !rev ? (tf.vFlip ? BS - 1 - by : by) : by;
                    const cur_si = ((sy + ry) * w + (sx + rx)) * 4, di = ((dy + oy) * w + (dx + ox)) * 4;
                    let r = srcBuf[cur_si], g = srcBuf[cur_si + 1], b = srcBuf[cur_si + 2];
                    if (!rev) {
                        if (tf.chanRot === 1) { const t = r; r = g; g = b; b = t; } else if (tf.chanRot === 2) { const t = r; r = b; b = g; g = t; }
                        if (tf.invert) { r = 255 - r; g = 255 - g; b = 255 - b; }
                    } else {
                        if (tf.invert) { r = 255 - r; g = 255 - g; b = 255 - b; }
                        if (tf.chanRot === 1) { const t = b; b = g; g = r; r = t; } else if (tf.chanRot === 2) { const t = g; g = b; b = r; r = t; }
                    }
                    dstBuf[di] = r; dstBuf[di + 1] = g; dstBuf[di + 2] = b; dstBuf[di + 3] = srcBuf[si + 3];
                }
            }
        }
        anchorIndices.forEach(idx => transformBlock(src, dst, (idx % bw) * BS, Math.floor(idx / bw) * BS, (idx % bw) * BS, Math.floor(idx / bw) * BS, null, reverse, true));
        if (!reverse) {
            for (let i = 0; i < shuffledIndices.length; i++) {
                const sIdx = shuffledIndices[i], dIdx = perm[i];
                transformBlock(src, dst, (sIdx % bw) * BS, Math.floor(sIdx / bw) * BS, (dIdx % bw) * BS, Math.floor(dIdx / bw) * BS, transforms[sIdx], false, false);
            }
        } else {
            for (let i = 0; i < shuffledIndices.length; i++) {
                const dIdx = shuffledIndices[i], sIdx = perm[i];
                transformBlock(src, dst, (sIdx % bw) * BS, Math.floor(sIdx / bw) * BS, (dIdx % bw) * BS, Math.floor(dIdx / bw) * BS, transforms[dIdx], true, false);
            }
        }
        const coveredW = bw * BS, coveredH = bh * BS;
        for (let y = 0; y < h; y++) {
            for (let x = coveredW; x < w; x++) {
                const i = (y * w + x) * 4, xorVal = (prng() * 255) | 0;
                dst[i] ^= xorVal; dst[i + 1] ^= xorVal; dst[i + 2] ^= xorVal; dst[i + 3] = src[i + 3];
            }
        }
        for (let y = coveredH; y < h; y++) {
            for (let x = 0; x < coveredW; x++) {
                const i = (y * w + x) * 4, xorVal = (prng() * 255) | 0;
                dst[i] ^= xorVal; dst[i + 1] ^= xorVal; dst[i + 2] ^= xorVal; dst[i + 3] = src[i + 3];
            }
        }
        return dst;
    }

    function applyRobustDctScramble(data, w, h, prng, rev) {
        const BS = 16, bw = Math.floor(w / BS), bh = Math.floor(h / BS), numBlocks = bw * bh;
        if (numBlocks < 2) return data;
        const perm = Array.from({ length: numBlocks }, (_, i) => i);
        shuffleArray(perm, prng);
        const blockOffsets = new Uint8Array(numBlocks);
        for (let i = 0; i < numBlocks; i++) blockOffsets[i] = (Math.floor(prng() * 15) + 1) * 16;
        const src = new Uint8Array(data), dst = new Uint8Array(src.length);
        dst.set(src);
        for (let bi = 0; bi < numBlocks; bi++) {
            const srcIdx = rev ? perm[bi] : bi, dstIdx = rev ? bi : perm[bi];
            const offset = blockOffsets[rev ? dstIdx : srcIdx];
            const sx = (srcIdx % bw) * BS, sy = Math.floor(srcIdx / bw) * BS;
            const dx = (dstIdx % bw) * BS, dy = Math.floor(dstIdx / bw) * BS;
            for (let dyi = 0; dyi < BS; dyi++) {
                const sRow = ((sy + dyi) * w + sx) * 4, dRow = ((dy + dyi) * w + dx) * 4;
                for (let dxi = 0; dxi < BS; dxi++) {
                    const si = sRow + dxi * 4, di = dRow + dxi * 4;
                    if (!rev) {
                        dst[di]     = (src[si] + offset) & 0xFF;
                        dst[di + 1] = (src[si + 1] + offset) & 0xFF;
                        dst[di + 2] = (src[si + 2] + offset) & 0xFF;
                        dst[di + 3] = src[si + 3];
                    } else {
                        dst[di]     = (src[si] - offset) & 0xFF;
                        dst[di + 1] = (src[si + 1] - offset) & 0xFF;
                        dst[di + 2] = (src[si + 2] - offset) & 0xFF;
                        dst[di + 3] = src[si + 3];
                    }
                }
            }
        }
        return dst;
    }

    function applyQuantizeShuffle(data, w, h, prng, rev) {
        if (!rev) {
            const d = new Uint8Array(data);
            for (let y = 0; y < h; y += 4) {
                for (let x = 0; x < w; x += 4) {
                    const i = (y * w + x) * 4, r = Math.round(d[i] / 48) * 48, g = Math.round(d[i + 1] / 48) * 48, b = Math.round(d[i + 2] / 48) * 48;
                    for (let dy = 0; dy < 4 && y + dy < h; dy++) {
                        for (let dx = 0; dx < 4 && x + dx < w; dx++) {
                            const idx = ((y + dy) * w + (x + dx)) * 4; d[idx] = r; d[idx + 1] = g; d[idx + 2] = b;
                        }
                    }
                }
            }
            data = d;
        }
        return applyXorShuffle(data, w, h, prng, rev);
    }
    function applyColorCrush(data, w, h, prng, rev) {
        if (!rev) {
            const d = new Uint8Array(data);
            for (let i = 0; i < d.length; i += 4) { d[i] = Math.round(d[i] / 64) * 64; d[i + 1] = Math.round(d[i + 1] / 64) * 64; d[i + 2] = Math.round(d[i + 2] / 64) * 64; }
            data = d;
        }
        return applyCatMap(data, w, h, prng, rev);
    }
    function applyBlurNoise(data, w, h, prng, rev) {
        if (!rev) {
            const d = new Uint8Array(data), tmp = new Uint8Array(d);
            for (let y = 1; y < h - 1; y++) {
                for (let x = 1; x < w - 1; x++) {
                    const i = (y * w + x) * 4;
                    for (let c = 0; c < 3; c++) d[i + c] = (tmp[i - 4 + c] + tmp[i + 4 + c] + tmp[i - w * 4 + c] + tmp[i + w * 4 + c]) >> 2;
                }
            }
            for (let i = 0; i < d.length; i += 4) {
                d[i] = Math.min(255, Math.max(0, d[i] + (prng() - 0.5) * 150));
                d[i + 1] = Math.min(255, Math.max(0, d[i + 1] + (prng() - 0.5) * 150));
                d[i + 2] = Math.min(255, Math.max(0, d[i + 2] + (prng() - 0.5) * 150));
            }
            data = d;
        }
        return applyWaveShift(data, w, h, prng, rev);
    }
    function applySaltPepper(data, w, h, prng, rev) {
        if (!rev) {
            const d32 = new Uint32Array(new Uint8Array(data).buffer.slice(0));
            for (let i = 0; i < d32.length; i++) { const r = prng(); if (r < 0.1) d32[i] = 0xFF000000; else if (r < 0.2) d32[i] = 0xFFFFFFFF; }
            data = new Uint8Array(d32.buffer);
        }
        return applyAffineMap(data, w, h, prng, rev);
    }

    function extractBitPlane(data, w, h, channel, bitIndex) {
        const src = new Uint8Array(data), dst = new Uint8Array(w * h * 4), mask = 1 << bitIndex;
        for (let i = 0; i < w * h; i++) {
            const si = i * 4;
            let bitVal = 0;
            if (channel === 'r') {
                bitVal = (src[si] & mask) ? 255 : 0; dst[si] = bitVal; dst[si + 1] = 0; dst[si + 2] = 0;
            } else if (channel === 'g') {
                bitVal = (src[si + 1] & mask) ? 255 : 0; dst[si] = 0; dst[si + 1] = bitVal; dst[si + 2] = 0;
            } else if (channel === 'b') {
                bitVal = (src[si + 2] & mask) ? 255 : 0; dst[si] = 0; dst[si + 1] = 0; dst[si + 2] = bitVal;
            } else if (channel === 'gray') {
                const gray = Math.round(0.299 * src[si] + 0.587 * src[si + 1] + 0.114 * src[si + 2]);
                bitVal = (gray & mask) ? 255 : 0; dst[si] = bitVal; dst[si + 1] = bitVal; dst[si + 2] = bitVal;
            } else {
                dst[si] = (src[si] & mask) ? 255 : 0;
                dst[si + 1] = (src[si + 1] & mask) ? 255 : 0;
                dst[si + 2] = (src[si + 2] & mask) ? 255 : 0;
            }
            dst[si + 3] = 255;
        }
        return dst;
    }

    function stegoDct8(block) {
        const N = 8, out = new Float64Array(N);
        for (let k = 0; k < N; k++) {
            let sum = 0;
            for (let n = 0; n < N; n++) sum += block[n] * Math.cos(Math.PI * (2 * n + 1) * k / (2 * N));
            out[k] = sum * (k === 0 ? Math.sqrt(1 / N) : Math.sqrt(2 / N));
        }
        return out;
    }
    function stegoIdct8(coef) {
        const N = 8, out = new Float64Array(N);
        for (let n = 0; n < N; n++) {
            let sum = 0;
            for (let k = 0; k < N; k++) sum += coef[k] * Math.cos(Math.PI * (2 * n + 1) * k / (2 * N)) * (k === 0 ? Math.sqrt(1 / N) : Math.sqrt(2 / N));
            out[n] = sum;
        }
        return out;
    }
    function stegoDct2d(block) {
        const tmp = new Float64Array(64);
        for (let r = 0; r < 8; r++) {
            const row = stegoDct8(block.subarray(r * 8, r * 8 + 8));
            for (let c = 0; c < 8; c++) tmp[r * 8 + c] = row[c];
        }
        for (let c = 0; c < 8; c++) {
            const col = new Float64Array(8);
            for (let r = 0; r < 8; r++) col[r] = tmp[r * 8 + c];
            const res = stegoDct8(col);
            for (let r = 0; r < 8; r++) tmp[r * 8 + c] = res[r];
        }
        return tmp;
    }
    function stegoIdct2d(coef) {
        const tmp = new Float64Array(64);
        for (let c = 0; c < 8; c++) {
            const col = new Float64Array(8);
            for (let r = 0; r < 8; r++) col[r] = coef[r * 8 + c];
            const res = stegoIdct8(col);
            for (let r = 0; r < 8; r++) tmp[r * 8 + c] = res[r];
        }
        for (let r = 0; r < 8; r++) {
            const row = stegoIdct8(tmp.subarray(r * 8, r * 8 + 8));
            for (let c = 0; c < 8; c++) tmp[r * 8 + c] = row[c];
        }
        return tmp;
    }

    const DCT_STEGO = {
        MID_FREQ: [[1, 2], [2, 1], [2, 3], [3, 2], [3, 3], [4, 4]],
        QUANT_STEP: 60,
        MAGIC_IMG: 0xDF,
        MAGIC_FILE_0: 0x4F,
        MAGIC_FILE_1: 0x42,

        rgbToY(r, g, b) { return 0.299 * r + 0.587 * g + 0.114 * b; },

        embedFile(hostPixels, hostW, hostH, fileBytes, fileName = 'secret.bin', mimeType = 'application/octet-stream', isEncrypted = false) {
            const enc = new TextEncoder();
            const safeName = (fileName || 'secret.bin').slice(0, 64);
            const safeMime = (mimeType || 'application/octet-stream').slice(0, 32);
            const nameBytes = enc.encode(safeName);
            const mimeBytes = enc.encode(safeMime);
            const nameLen = nameBytes.length, mimeLen = mimeBytes.length, fileLen = fileBytes.length;
            let sum1 = 0, sum2 = 0;
            for (let i = 0; i < fileLen; i++) { sum1 = (sum1 + fileBytes[i]) % 255; sum2 = (sum2 + sum1) % 255; }
            const checksum = (sum2 << 8) | sum1;

            const hdr = new Uint8Array(16);
            hdr[0] = this.MAGIC_FILE_0; hdr[1] = this.MAGIC_FILE_1;
            hdr[2] = nameLen; hdr[3] = mimeLen;
            hdr[4] = fileLen & 0xFF; hdr[5] = (fileLen >> 8) & 0xFF;
            hdr[6] = (fileLen >> 16) & 0xFF; hdr[7] = (fileLen >> 24) & 0xFF;
            hdr[8] = checksum & 0xFF; hdr[9] = (checksum >> 8) & 0xFF;
            hdr[10] = isEncrypted ? 0x02 : 0x01; hdr[11] = 0;
            const hdrCheck = (nameLen * 31 + mimeLen * 17 + (fileLen & 0xFFFF) + 0x7E) & 0xFFFF;
            hdr[12] = hdrCheck & 0xFF; hdr[13] = (hdrCheck >> 8) & 0xFF;
            hdr[14] = 0x5A; hdr[15] = 0xA5;

            const payload = new Uint8Array(nameLen + mimeLen + fileLen);
            payload.set(nameBytes, 0); payload.set(mimeBytes, nameLen); payload.set(fileBytes, nameLen + mimeLen);

            const hdrBits = [];
            for (let i = 0; i < 16; i++) { for (let b = 0; b < 8; b++) hdrBits.push((hdr[i] >> b) & 1); }
            const payBits = [];
            for (let i = 0; i < payload.length; i++) { for (let b = 0; b < 8; b++) payBits.push((payload[i] >> b) & 1); }

            const bw = Math.floor(hostW / 8), bh = Math.floor(hostH / 8);
            const totalPositions = bw * bh * this.MID_FREQ.length;
            const HDR_SLOTS = 2048;
            if (totalPositions < HDR_SLOTS + 64) return false;

            const availPaySlots = totalPositions - HDR_SLOTS;
            const payRedundancy = Math.max(1, Math.floor(availPaySlots / Math.max(1, payBits.length)));

            let posIdx = 0;
            for (let by = 0; by + 8 <= hostH; by += 8) {
                for (let bx = 0; bx + 8 <= hostW; bx += 8) {
                    const block = new Float64Array(64);
                    let avgY = 0;
                    for (let r = 0; r < 8; r++) {
                        for (let c = 0; c < 8; c++) {
                            const idx = ((by + r) * hostW + (bx + c)) * 4;
                            block[r * 8 + c] = this.rgbToY(hostPixels[idx], hostPixels[idx + 1], hostPixels[idx + 2]);
                            avgY += block[r * 8 + c];
                        }
                    }
                    avgY /= 64;
                    const Q = this.QUANT_STEP * (0.6 + (avgY / 255) * 0.5);
                    const dct = stegoDct2d(block);

                    for (let fi = 0; fi < this.MID_FREQ.length; fi++) {
                        let bit = 0;
                        if (posIdx < HDR_SLOTS) {
                            bit = hdrBits[posIdx % 128];
                        } else {
                            const pOffset = posIdx - HDR_SLOTS;
                            if (payBits.length > 0) {
                                const pBitIdx = Math.floor(pOffset / payRedundancy) % payBits.length;
                                bit = payBits[pBitIdx];
                            }
                        }
                        const [fr, fc] = this.MID_FREQ[fi];
                        const coef = dct[fr * 8 + fc];
                        const quantized = Math.round(coef / Q) * Q;
                        dct[fr * 8 + fc] = quantized + (bit ? Q / 3 : -Q / 3);
                        posIdx++;
                    }

                    const spatial = stegoIdct2d(dct);
                    for (let r = 0; r < 8; r++) {
                        for (let c = 0; c < 8; c++) {
                            const idx = ((by + r) * hostW + (bx + c)) * 4;
                            const oldY = this.rgbToY(hostPixels[idx], hostPixels[idx + 1], hostPixels[idx + 2]);
                            const dy = spatial[r * 8 + c] - oldY;
                            hostPixels[idx]     = Math.max(0, Math.min(255, Math.round(hostPixels[idx] + dy)));
                            hostPixels[idx + 1] = Math.max(0, Math.min(255, Math.round(hostPixels[idx + 1] + dy)));
                            hostPixels[idx + 2] = Math.max(0, Math.min(255, Math.round(hostPixels[idx + 2] + dy)));
                        }
                    }
                }
            }
            return true;
        },

        embed(hostPixels, hostW, hostH, secretPixels, secretW, secretH) {
            const bits = [];
            const checksum = (secretW * secretH + 0x5A) & 0xFF;
            for (let i = 0; i < 8; i++) bits.push((this.MAGIC_IMG >> i) & 1);
            for (let i = 0; i < 8; i++) bits.push((secretW >> i) & 1);
            for (let i = 0; i < 8; i++) bits.push((secretH >> i) & 1);
            for (let i = 0; i < 8; i++) bits.push((checksum >> i) & 1);
            for (let p = 0; p < secretW * secretH; p++) {
                const r4 = secretPixels[p * 4] >> 4, g4 = secretPixels[p * 4 + 1] >> 4, b4 = secretPixels[p * 4 + 2] >> 4;
                for (let i = 0; i < 4; i++) bits.push((r4 >> i) & 1);
                for (let i = 0; i < 4; i++) bits.push((g4 >> i) & 1);
                for (let i = 0; i < 4; i++) bits.push((b4 >> i) & 1);
            }
            const totalBits = bits.length;
            let posIdx = 0;
            for (let by = 0; by + 8 <= hostH; by += 8) {
                for (let bx = 0; bx + 8 <= hostW; bx += 8) {
                    const block = new Float64Array(64);
                    let avgY = 0;
                    for (let r = 0; r < 8; r++) {
                        for (let c = 0; c < 8; c++) {
                            const idx = ((by + r) * hostW + (bx + c)) * 4;
                            block[r * 8 + c] = this.rgbToY(hostPixels[idx], hostPixels[idx + 1], hostPixels[idx + 2]);
                            avgY += block[r * 8 + c];
                        }
                    }
                    avgY /= 64;
                    const Q = this.QUANT_STEP * (0.5 + (avgY / 255) * 0.6);
                    const dct = stegoDct2d(block);
                    for (let fi = 0; fi < this.MID_FREQ.length; fi++) {
                        const bitIdx = posIdx % totalBits, [fr, fc] = this.MID_FREQ[fi], bit = bits[bitIdx];
                        const coef = dct[fr * 8 + fc], quantized = Math.round(coef / Q) * Q;
                        dct[fr * 8 + fc] = quantized + (bit ? Q / 3 : -Q / 3);
                        posIdx++;
                    }
                    const spatial = stegoIdct2d(dct);
                    for (let r = 0; r < 8; r++) {
                        for (let c = 0; c < 8; c++) {
                            const idx = ((by + r) * hostW + (bx + c)) * 4;
                            const oldY = this.rgbToY(hostPixels[idx], hostPixels[idx + 1], hostPixels[idx + 2]);
                            const dy = spatial[r * 8 + c] - oldY;
                            hostPixels[idx]     = Math.max(0, Math.min(255, Math.round(hostPixels[idx] + dy)));
                            hostPixels[idx + 1] = Math.max(0, Math.min(255, Math.round(hostPixels[idx + 1] + dy)));
                            hostPixels[idx + 2] = Math.max(0, Math.min(255, Math.round(hostPixels[idx + 2] + dy)));
                        }
                    }
                }
            }
        },

        extract(hostPixels, hostW, hostH) {
            const bw = Math.floor(hostW / 8), bh = Math.floor(hostH / 8);
            const numFreqs = this.MID_FREQ.length;
            const totalPositions = bw * bh * numFreqs;
            if (totalPositions < 64) return null;

            const allBits = new Uint8Array(totalPositions);
            let posIdx = 0;
            for (let by = 0; by + 8 <= hostH; by += 8) {
                for (let bx = 0; bx + 8 <= hostW; bx += 8) {
                    const block = new Float64Array(64);
                    let avgY = 0;
                    for (let r = 0; r < 8; r++) {
                        for (let c = 0; c < 8; c++) {
                            const idx = ((by + r) * hostW + (bx + c)) * 4;
                            block[r * 8 + c] = this.rgbToY(hostPixels[idx], hostPixels[idx + 1], hostPixels[idx + 2]);
                            avgY += block[r * 8 + c];
                        }
                    }
                    avgY /= 64;
                    const Q = this.QUANT_STEP * (0.6 + (avgY / 255) * 0.5);
                    const dct = stegoDct2d(block);
                    for (let fi = 0; fi < numFreqs; fi++) {
                        const [fr, fc] = this.MID_FREQ[fi];
                        const coef = dct[fr * 8 + fc];
                        const quantized = Math.round(coef / Q) * Q;
                        allBits[posIdx++] = (coef - quantized) > 0 ? 1 : 0;
                    }
                }
            }

            // CHECK 1: File Format 'OB'
            const HDR_SLOTS = 2048;
            if (totalPositions >= HDR_SLOTS + 64) {
                const hdr = new Uint8Array(16);
                for (let bi = 0; bi < 128; bi++) {
                    let ones = 0, zeros = 0;
                    for (let rep = 0; rep < 16; rep++) {
                        const pos = rep * 128 + bi;
                        if (pos < HDR_SLOTS && pos < totalPositions) {
                            if (allBits[pos]) ones++; else zeros++;
                        }
                    }
                    const bitVal = ones > zeros ? 1 : 0;
                    hdr[Math.floor(bi / 8)] |= (bitVal << (bi % 8));
                }

                if (hdr[0] === this.MAGIC_FILE_0 && hdr[1] === this.MAGIC_FILE_1 && hdr[14] === 0x5A && hdr[15] === 0xA5) {
                    const nameLen = hdr[2], mimeLen = hdr[3];
                    const fileLen = (hdr[4]) | (hdr[5] << 8) | (hdr[6] << 16) | (hdr[7] << 24);
                    const expectedCs = (hdr[8]) | (hdr[9] << 8);
                    const isEncrypted = (hdr[10] & 0x02) !== 0;
                    const hdrCheck = (hdr[12]) | (hdr[13] << 8);
                    const calcHdrCheck = (nameLen * 31 + mimeLen * 17 + (fileLen & 0xFFFF) + 0x7E) & 0xFFFF;

                    if (hdrCheck === calcHdrCheck && fileLen >= 0 && fileLen < 50000000) {
                        const totalPayBytes = nameLen + mimeLen + fileLen;
                        const totalPayBits = totalPayBytes * 8;
                        const availPaySlots = totalPositions - HDR_SLOTS;
                        const payRedundancy = Math.max(1, Math.floor(availPaySlots / Math.max(1, totalPayBits)));

                        const payBytes = new Uint8Array(totalPayBytes);
                        for (let pbi = 0; pbi < totalPayBits; pbi++) {
                            let ones = 0, zeros = 0;
                            for (let rep = 0; rep < payRedundancy; rep++) {
                                const pos = HDR_SLOTS + pbi * payRedundancy + rep;
                                if (pos < totalPositions) {
                                    if (allBits[pos]) ones++; else zeros++;
                                }
                            }
                            const bitVal = ones > zeros ? 1 : 0;
                            payBytes[Math.floor(pbi / 8)] |= (bitVal << (pbi % 8));
                        }

                        const dec = new TextDecoder();
                        const fileName = dec.decode(payBytes.subarray(0, nameLen)) || 'secret.bin';
                        const mimeType = dec.decode(payBytes.subarray(nameLen, nameLen + mimeLen)) || 'application/octet-stream';
                        const fileData = payBytes.subarray(nameLen + mimeLen);

                        let sum1 = 0, sum2 = 0;
                        for (let i = 0; i < fileData.length; i++) { sum1 = (sum1 + fileData[i]) % 255; sum2 = (sum2 + sum1) % 255; }
                        const calcCs = (sum2 << 8) | sum1;

                        return {
                            type: 'file',
                            fileName,
                            mimeType,
                            size: fileLen,
                            data: fileData.buffer.slice(fileData.byteOffset, fileData.byteOffset + fileData.byteLength),
                            encrypted: isEncrypted,
                            checksumValid: (calcCs === expectedCs)
                        };
                    }
                }
            }

            // CHECK 2: Thumbnail format
            for (let side = 4; side <= 255; side++) {
                const sw = side, sh = side, totalBits = 32 + sw * sh * 12;
                const redundancy = Math.floor(totalPositions / totalBits);
                if (redundancy < 2) break;

                const hdr = new Uint8Array(32);
                for (let bi = 0; bi < 32; bi++) {
                    let ones = 0, zeros = 0;
                    for (let rep = 0; rep < redundancy; rep++) {
                        const pos = bi + rep * totalBits;
                        if (pos < totalPositions) { if (allBits[pos]) ones++; else zeros++; }
                    }
                    hdr[bi] = ones > zeros ? 1 : 0;
                }
                let magic = 0;
                for (let i = 0; i < 8; i++) magic |= hdr[i] << i;
                if (magic !== this.MAGIC_IMG) continue;

                let rsw = 0, rsh = 0, cs = 0;
                for (let i = 0; i < 8; i++) rsw |= hdr[8 + i] << i;
                for (let i = 0; i < 8; i++) rsh |= hdr[16 + i] << i;
                for (let i = 0; i < 8; i++) cs  |= hdr[24 + i] << i;
                if (rsw !== sw || rsh !== sh || cs !== ((sw * sh + 0x5A) & 0xFF)) continue;

                const secretPixels = new Uint8Array(sw * sh * 4);
                for (let pbi = 0; pbi < sw * sh * 12; pbi++) {
                    const bi = 32 + pbi;
                    let ones = 0, zeros = 0;
                    for (let rep = 0; rep < redundancy; rep++) {
                        const pos = bi + rep * totalBits;
                        if (pos < totalPositions) { if (allBits[pos]) ones++; else zeros++; }
                    }
                    const pixelIdx = Math.floor(pbi / 12), channelBit = pbi % 12, channel = Math.floor(channelBit / 4), bitPos = channelBit % 4;
                    secretPixels[pixelIdx * 4 + channel] |= (ones > zeros ? 1 : 0) << bitPos;
                }
                for (let p = 0; p < sw * sh; p++) {
                    for (let ch = 0; ch < 3; ch++) { const v = secretPixels[p * 4 + ch]; secretPixels[p * 4 + ch] = (v << 4) | v; }
                    secretPixels[p * 4 + 3] = 255;
                }
                return { type: 'image', data: secretPixels.buffer, width: sw, height: sh };
            }
            return null;
        }
    };

    const ALGOS = {
        'none': (d) => new Uint8Array(d),
        'xor-shuffle': applyXorShuffle, 'logistic-xor': applyLogisticXOR, 'cat-map': applyCatMap,
        'baker-map': applyBakerMap, 'affine-map': applyAffineMap, 'wave-shift': applyWaveShift,
        'prime-scatter': applyPrimeScatter, 'rgb-shift': applyRgbShift, 'hilbert': applyHilbert,
        'spiral': applySpiral, 'zigzag': applyZigzag, 'chirikov': applyChirikov,
        'henon': applyHenon, 'rubik': applyRubik,
        'block-shuffle-8': (d, w, h, p, r) => applyBlockShuffleWorker(d, w, h, p, r, 8),
        'block-shuffle-16': (d, w, h, p, r) => applyBlockShuffleWorker(d, w, h, p, r, 16),
        'robust-dct-scramble': applyRobustDctScramble,
        'dfws': applyDFWSWorker, 'quantize-shuffle': applyQuantizeShuffle,
        'color-crush': applyColorCrush, 'blur-noise': applyBlurNoise, 'salt-pepper': applySaltPepper
    };

    return {
        run(params) {
            const { type, algo, data, width, height, seed, reverse, intensity, secretImage, secretFile, extractSecret, channel, bitIndex } = params;
            if (type === 'bit-plane' || algo === 'bit-plane') {
                const res = extractBitPlane(data, width, height, channel || 'gray', typeof bitIndex === 'number' ? bitIndex : 0);
                return { result: res.buffer };
            }
            if (algo === 'dct-extract') {
                const extracted = DCT_STEGO.extract(new Uint8Array(data), width, height);
                return { result: data, extractedSecret: extracted };
            }
            const fn = ALGOS[algo] || ALGOS['none'];
            const prng = getPRNG(seed || 'public');
            let result;
            let extracted = null;
            if (reverse && extractSecret) {
                const pixels = new Uint8Array(data);
                extracted = DCT_STEGO.extract(pixels, width, height);
                result = fn(pixels, width, height, prng, true);
            } else {
                result = fn(new Uint8Array(data), width, height, prng, reverse);
            }
            if (!reverse && secretFile) {
                DCT_STEGO.embedFile(result, width, height, new Uint8Array(secretFile.data), secretFile.name, secretFile.mime, secretFile.encrypted);
            } else if (!reverse && secretImage) {
                DCT_STEGO.embed(result, width, height, new Uint8Array(secretImage.data), secretImage.width, secretImage.height);
            }
            if (typeof intensity === 'number' && intensity < 1 && !reverse) {
                const orig = new Uint8Array(data), blended = new Uint8Array(result.length);
                for (let i = 0; i < result.length; i++) {
                    if ((i + 1) % 4 === 0) blended[i] = orig[i];
                    else blended[i] = Math.round(orig[i] * (1 - intensity) + result[i] * intensity);
                }
                result = blended;
            }
            const resObj = { result: result.buffer };
            if (extracted) resObj.extractedSecret = extracted;
            return resObj;
        }
    };
})();

class WorkerBridge {
    constructor() {
        this.worker = null;
        this.pending = new Map();
        this.reqId = 0;
        this.init();
    }

    init() {
        try {
            if (location.protocol === 'file:') {
                this.worker = null;
                console.info('Protocole local file:// : moteur d\'exécution in-thread actif.');
                return;
            }
            this.worker = new Worker('worker.js');
            this.worker.onmessage = (e) => {
                const { id, result, extractedSecret, error } = e.data;
                const resolver = this.pending.get(id);
                if (!resolver) return;
                this.pending.delete(id);
                if (error) resolver.reject(new Error(error));
                else resolver.resolve({ result, extractedSecret });
            };
            this.worker.onerror = () => {
                this.worker = null;
            };
        } catch {
            this.worker = null;
        }
    }

    async send(params, transfers = []) {
        if (!this.worker) {
            return InThreadExecutor.run(params);
        }
        return new Promise((resolve, reject) => {
            const id = ++this.reqId;
            this.pending.set(id, { resolve, reject });
            try {
                this.worker.postMessage({ id, ...params }, transfers);
            } catch {
                this.pending.delete(id);
                try {
                    resolve(InThreadExecutor.run(params));
                } catch (e2) {
                    reject(e2);
                }
            }
        });
    }
}

// ============================================================================
// 4. AUDIO CHIMES (Synthesized Gentle Feedback)
// ============================================================================
const SoundManager = {
    enabled: true,
    ctx: null,

    play(type = 'success') {
        if (!this.enabled) return;
        try {
            if (!this.ctx) this.ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.connect(gain);
            gain.connect(this.ctx.destination);

            const now = this.ctx.currentTime;
            if (type === 'success') {
                osc.type = 'sine';
                osc.frequency.setValueAtTime(523.25, now); // C5
                osc.frequency.exponentialRampToValueAtTime(783.99, now + 0.14); // G5
                gain.gain.setValueAtTime(0.08, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.28);
                osc.start(now);
                osc.stop(now + 0.28);
            } else {
                osc.type = 'triangle';
                osc.frequency.setValueAtTime(329.63, now); // E4
                osc.frequency.exponentialRampToValueAtTime(220.00, now + 0.18); // A3
                gain.gain.setValueAtTime(0.1, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
                osc.start(now);
                osc.stop(now + 0.25);
            }
        } catch {
            // Audio policy blocked
        }
    }
};

// ============================================================================
// 5. STEGANOGRAPHY & WATERMARK ENGINES (LSB & Frequency SynthID)
// ============================================================================
const StegoEngine = {
    encodeLSB(imgData, payloadBytes) {
        const bits = [];
        const len = payloadBytes.length;
        for (let i = 0; i < 32; i++) bits.push((len >> i) & 1);
        for (let i = 0; i < len; i++) {
            const b = payloadBytes[i];
            for (let j = 0; j < 8; j++) bits.push((b >> j) & 1);
        }
        const maxBits = (imgData.data.length / 4) * 3;
        if (bits.length > maxBits) throw new Error('Contenu trop volumineux pour la stéganographie LSB.');

        let bitIndex = 0;
        for (let i = 0; i < imgData.data.length && bitIndex < bits.length; i++) {
            if ((i + 1) % 4 === 0) continue; // skip alpha
            imgData.data[i] = (imgData.data[i] & ~1) | bits[bitIndex];
            bitIndex++;
        }
    },

    decodeLSB(imgData) {
        let len = 0;
        let dataIndex = 0;
        for (let i = 0; i < 32; i++) {
            while ((dataIndex + 1) % 4 === 0) dataIndex++;
            if (dataIndex >= imgData.data.length) return null;
            const bit = imgData.data[dataIndex] & 1;
            len |= (bit << i);
            dataIndex++;
        }
        if (len <= 0 || len > 10000000) return null;

        const payload = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            let b = 0;
            for (let j = 0; j < 8; j++) {
                while ((dataIndex + 1) % 4 === 0) dataIndex++;
                if (dataIndex >= imgData.data.length) return null;
                const bit = imgData.data[dataIndex] & 1;
                b |= (bit << j);
                dataIndex++;
            }
            payload[i] = b;
        }
        return payload;
    }
};

// ============================================================================
// 6. MAIN APPLICATION CONTROLLER
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
    const worker = new WorkerBridge();

    // DOM Elements
    const tabs = document.querySelectorAll('.tab-btn');
    const viewPanels = document.querySelectorAll('.view-panel');

    // Tab 1: Obfuscation
    const obfDropZone = document.getElementById('obf-dropzone');
    const obfFileInput = document.getElementById('obf-file-input');
    const dropEmptyUI = document.getElementById('drop-empty-ui');
    const previewViewport = document.getElementById('preview-viewport');
    const mainPreviewImg = document.getElementById('main-preview-img');
    const viewportToolbar = document.getElementById('viewport-toolbar');

    const compareSliderBox = document.getElementById('compare-slider-box');
    const compareCanvas = document.getElementById('compare-canvas');
    const compareHandle = document.getElementById('compare-handle');

    const algoSelect = document.getElementById('algo-select');
    const algoGallery = document.getElementById('algo-gallery');
    const algoTypeTag = document.getElementById('algo-type-tag');

    const obfPwd = document.getElementById('obf-pwd');
    const togglePwdVisibility = document.getElementById('toggle-pwd-visibility');
    const robustModeCb = document.getElementById('robust-mode');

    const advAccordion = document.getElementById('adv-accordion');
    const advTrigger = document.getElementById('adv-trigger');
    const stripExifCb = document.getElementById('strip-exif');
    const embedOriginalCb = document.getElementById('embed-original-cb');
    const dctPixelCb = document.getElementById('dct-pixel-cb');
    const embedSecretFile = document.getElementById('embed-secret-file');

    const watermarkToggle = document.getElementById('watermark-toggle');
    const watermarkBox = document.getElementById('watermark-box');
    const watermarkText = document.getElementById('watermark-text');

    const glitchIntensity = document.getElementById('glitch-intensity');
    const glitchValText = document.getElementById('glitch-val-text');

    const gaugeCircle = document.getElementById('gauge-circle');
    const gaugePercent = document.getElementById('gauge-percent');
    const gaugeStatusTitle = document.getElementById('gauge-status-title');
    const gaugeStatusDesc = document.getElementById('gauge-status-desc');

    const btnRunObfuscate = document.getElementById('btn-run-obfuscate');
    const exportFormatSelect = document.getElementById('export-format');
    const integrityCard = document.getElementById('integrity-card');
    const hashValue = document.getElementById('hash-value');
    const btnCopyHash = document.getElementById('btn-copy-hash');

    const batchTray = document.getElementById('batch-tray');
    const batchCounter = document.getElementById('batch-counter');
    const batchStrip = document.getElementById('batch-strip');
    const btnClearBatch = document.getElementById('btn-clear-batch');

    // Tab 1 Secret File UI
    const secretFileDropzone = document.getElementById('secret-file-dropzone');
    const secretFileNameLabel = document.getElementById('secret-file-name-label');
    const secretFileSizeLabel = document.getElementById('secret-file-size-label');
    const btnClearSecret = document.getElementById('btn-clear-secret');

    // Tab 2: Revert
    const revertDropZone = document.getElementById('revert-dropzone');
    const revertFileInput = document.getElementById('revert-file-input');
    const revertEmptyUI = document.getElementById('revert-empty-ui');
    const revertViewport = document.getElementById('revert-viewport');
    const revertPreviewImg = document.getElementById('revert-preview-img');
    const revertAlgoSelect = document.getElementById('revert-algo-select');
    const revertContainerBadge = document.getElementById('revert-container-badge');
    const revertPwd = document.getElementById('revert-pwd');
    const toggleRevPwd = document.getElementById('toggle-rev-pwd-visibility');
    const btnRunRevert = document.getElementById('btn-run-revert');
    const btnBruteForce = document.getElementById('btn-brute-force');
    const revertMetaCard = document.getElementById('revert-meta-card');
    const detectedAlgoInfo = document.getElementById('detected-algo-info');
    const detectedWmInfo = document.getElementById('detected-wm-info');
    const detectedSigInfo = document.getElementById('detected-sig-info');
    const extractedPayloadCard = document.getElementById('extracted-payload-card');
    const btnDownloadSecret = document.getElementById('btn-download-secret');
    const payloadThumbPreview = document.getElementById('payload-thumb-preview');
    const payloadFilenameText = document.getElementById('payload-filename-text');
    const payloadMetaText = document.getElementById('payload-meta-text');
    const payloadSourceTag = document.getElementById('payload-source-tag');
    const payloadTypeBadge = document.getElementById('payload-type-badge');

    // Tab 3: Forensic Lab
    const bitPlaneCanvas = document.getElementById('bit-plane-canvas');
    const bitChips = document.querySelectorAll('[data-bit]');
    const channelChips = document.querySelectorAll('[data-channel]');
    const exifTableBody = document.getElementById('exif-table-body');
    const btnStripAndSave = document.getElementById('btn-strip-and-save');
    const forensicSha256 = document.getElementById('forensic-sha256');
    const forensicSha512 = document.getElementById('forensic-sha512');

    // Tab 4: History & Header Tools
    const historyContainer = document.getElementById('history-container');
    const historyEmptyState = document.getElementById('history-empty-state');
    const btnExportHistory = document.getElementById('btn-export-history');
    const btnClearHistory = document.getElementById('btn-clear-history');

    const themeToggle = document.getElementById('theme-toggle');
    const audioToggle = document.getElementById('audio-toggle');
    const helpToggle = document.getElementById('help-toggle');
    const helpModal = document.getElementById('help-modal');
    const btnCloseHelp = document.getElementById('btn-close-help');
    const toastContainer = document.getElementById('toast-container');

    // App State
    let activeFiles = [];
    let currentImage = new Image();
    let currentImageFile = null;

    let targetRevertFile = null;
    let targetRevertImage = new Image();

    let originalPixels = null;
    let obfuscatedPixels = null;
    let imageWidth = 0;
    let imageHeight = 0;

    let compareSplit = 0.5;
    let isDraggingSlider = false;

    let currentSecretPayloadBlob = null;
    let currentRestoredBlobUrl = null;
    let selectedSecretFile = null;

    let forensicChannel = 'gray';
    let forensicBit = 0;

    // Zoom & Pan State
    let zoomScale = 1;
    let panX = 0;
    let panY = 0;
    let isPanning = false;
    let panStartX = 0;
    let panStartY = 0;

    // ========================================================================
    // UI UTILITIES & TOASTS
    // ========================================================================
    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';
        toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
        toastContainer.appendChild(toast);
        void toast.offsetWidth;
        toast.classList.add('visible');
        setTimeout(() => {
            toast.classList.remove('visible');
            setTimeout(() => toast.remove(), 250);
        }, 3200);
    }

    // Tab Switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            viewPanels.forEach(p => p.classList.remove('active'));
            tab.classList.add('active');
            const target = document.getElementById(tab.dataset.target);
            if (target) target.classList.add('active');
            if (tab.dataset.target === 'forensic-panel') updateForensics();
            if (tab.dataset.target === 'history-panel') renderHistory();
        });
    });

    // Theme Toggle
    themeToggle.addEventListener('click', () => {
        document.body.classList.toggle('light-mode');
        const isLight = document.body.classList.contains('light-mode');
        themeToggle.textContent = isLight ? '☀️' : '🌙';
        localStorage.setItem('obscurify_theme', isLight ? 'light' : 'dark');
    });
    if (localStorage.getItem('obscurify_theme') === 'light') {
        document.body.classList.add('light-mode');
        themeToggle.textContent = '☀️';
    }

    // Audio Toggle
    audioToggle.addEventListener('click', () => {
        SoundManager.enabled = !SoundManager.enabled;
        audioToggle.textContent = SoundManager.enabled ? '🔊' : '🔇';
        audioToggle.title = SoundManager.enabled ? 'Effets sonores (Activé)' : 'Effets sonores (Muet)';
    });

    // Help Modal
    helpToggle.addEventListener('click', () => helpModal.classList.add('active'));
    btnCloseHelp.addEventListener('click', () => helpModal.classList.remove('active'));
    helpModal.addEventListener('click', (e) => { if (e.target === helpModal) helpModal.classList.remove('active'); });

    // Accordion
    advTrigger.addEventListener('click', () => advAccordion.classList.toggle('open'));

    // Secret File Dropzone & External Payload Handler
    if (secretFileDropzone && embedSecretFile) {
        secretFileDropzone.addEventListener('click', (e) => {
            if (e.target.closest('#btn-clear-secret')) return;
            embedSecretFile.click();
        });

        ['dragenter', 'dragover'].forEach(ev => {
            secretFileDropzone.addEventListener(ev, (e) => {
                e.preventDefault();
                e.stopPropagation();
                secretFileDropzone.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(ev => {
            secretFileDropzone.addEventListener(ev, (e) => {
                e.preventDefault();
                e.stopPropagation();
                secretFileDropzone.classList.remove('dragover');
            });
        });

        secretFileDropzone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files.length) {
                handleSecretFileChosen(e.dataTransfer.files[0]);
            }
        });

        embedSecretFile.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length) {
                handleSecretFileChosen(e.target.files[0]);
            }
        });

        if (btnClearSecret) {
            btnClearSecret.addEventListener('click', (e) => {
                e.stopPropagation();
                selectedSecretFile = null;
                embedSecretFile.value = '';
                secretFileNameLabel.textContent = 'Cliquez pour choisir un document secret';
                secretFileSizeLabel.textContent = 'Modulation DCT : survit au réencodage JPG et conversion';
                btnClearSecret.classList.add('hidden');
                secretFileDropzone.classList.remove('has-file');
                updateSecurityScore();
                showToast('Document secret retiré.', 'info');
            });
        }
    }

    function handleSecretFileChosen(file) {
        selectedSecretFile = file;
        secretFileNameLabel.textContent = file.name;
        const sizeKb = (file.size / 1024).toFixed(1);
        secretFileSizeLabel.textContent = `${sizeKb} KB · ${file.type || 'Fichier binaire'} · Prêt pour modulation DCT`;
        if (btnClearSecret) btnClearSecret.classList.remove('hidden');
        if (secretFileDropzone) secretFileDropzone.classList.add('has-file');
        dctPixelCb.checked = true;
        updateSecurityScore();
        SoundManager.play('click');
        showToast(`Document secret chargé : ${file.name} (${sizeKb} KB)`, 'success');
    }

    // Watermark toggle
    watermarkToggle.addEventListener('change', () => {
        watermarkBox.classList.toggle('hidden', !watermarkToggle.checked);
        updateSecurityScore();
    });

    // Password Visibility Toggles
    togglePwdVisibility.addEventListener('click', () => {
        obfPwd.type = obfPwd.type === 'password' ? 'text' : 'password';
        togglePwdVisibility.textContent = obfPwd.type === 'password' ? '👁️' : '🔒';
    });
    toggleRevPwd.addEventListener('click', () => {
        revertPwd.type = revertPwd.type === 'password' ? 'text' : 'password';
        toggleRevPwd.textContent = revertPwd.type === 'password' ? '👁️' : '🔒';
    });

    // Copy Buttons
    document.querySelectorAll('[data-copy]').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetEl = document.getElementById(btn.dataset.copy);
            if (targetEl && targetEl.textContent) {
                navigator.clipboard.writeText(targetEl.textContent.trim());
                showToast('Empreinte copiée dans le presse-papier !', 'success');
            }
        });
    });
    btnCopyHash.addEventListener('click', () => {
        if (hashValue.textContent) {
            navigator.clipboard.writeText(hashValue.textContent.trim());
            showToast('Hash SHA-256 copié !', 'success');
        }
    });

    // Glitch Slider
    glitchIntensity.addEventListener('input', () => {
        glitchValText.textContent = `${glitchIntensity.value}%`;
        updateSecurityScore();
    });

    // ========================================================================
    // PASSWORD STRENGTH & SECURITY GAUGE EVALUATION
    // ========================================================================
    obfPwd.addEventListener('input', () => {
        const evalRes = CryptoEngine.evaluateEntropy(obfPwd.value);
        document.getElementById('pwd-entropy-text').textContent = evalRes.text;
        document.getElementById('pwd-crack-time').textContent = `Estimation : ${evalRes.crackTime}`;

        const colors = ['', 'var(--accent-rose)', 'var(--accent-amber)', 'var(--primary)', 'var(--accent-emerald)'];
        for (let i = 1; i <= 4; i++) {
            const seg = document.getElementById(`pwd-seg-${i}`);
            seg.style.backgroundColor = (i <= evalRes.level && evalRes.level > 0) ? colors[evalRes.level] : 'rgba(255,255,255,0.08)';
        }
        updateSecurityScore();
    });

    function updateSecurityScore() {
        let score = 0;
        const algo = algoSelect.value;
        const pwd = obfPwd.value;
        const evalRes = CryptoEngine.evaluateEntropy(pwd);

        // 1. Algorithm strength (0-35 pts)
        if (algo === 'xor-shuffle' || algo === 'cat-map' || algo === 'dfws' || algo === 'robust-dct-scramble') score += 35;
        else if (algo.startsWith('block-shuffle') || algo === 'logistic-xor' || algo === 'baker-map') score += 30;
        else if (algo === 'none') score += 20;
        else if (['affine-map', 'wave-shift', 'prime-scatter'].includes(algo)) score += 25;
        else score += 15; // destructive

        // 2. Password & Key Derivation (0-35 pts)
        if (pwd) {
            score += Math.min(35, evalRes.level * 8 + (robustModeCb.checked ? 5 : 0));
        }

        // 3. Metadata & Privacy hygiene (0-15 pts)
        if (stripExifCb.checked) score += 10;
        if (embedOriginalCb.checked) score += 5;

        // 4. Advanced Watermark / DCT & Hidden File (0-15 pts)
        if (watermarkToggle.checked && watermarkText.value.trim()) score += 8;
        if (dctPixelCb.checked) score += 7;
        if (selectedSecretFile) score += 10;

        // Glitch penalty if < 100%
        const intensity = parseInt(glitchIntensity.value, 10);
        if (intensity < 100) score = Math.round(score * (intensity / 100));

        score = Math.max(5, Math.min(100, score));

        // Update Gauge UI
        const circumference = 264; // 2 * PI * 42
        const offset = circumference - (score / 100) * circumference;
        gaugeCircle.style.strokeDashoffset = offset;
        gaugePercent.textContent = `${score}%`;

        if (score >= 85) {
            gaugeCircle.style.stroke = 'var(--accent-emerald)';
            gaugeStatusTitle.textContent = 'Protection Maximale';
            gaugeStatusDesc.textContent = 'Chiffrement robuste, réversibilité intégrale et métadonnées nettoyées.';
        } else if (score >= 60) {
            gaugeCircle.style.stroke = 'var(--primary)';
            gaugeStatusTitle.textContent = 'Protection Élevée';
            gaugeStatusDesc.textContent = 'Bonne résistance. Ajoutez un mot de passe plus long pour un niveau militaire.';
        } else if (score >= 35) {
            gaugeCircle.style.stroke = 'var(--accent-amber)';
            gaugeStatusTitle.textContent = 'Protection Modérée';
            gaugeStatusDesc.textContent = 'L\'image est obfusquée visuellement mais peut être restaurée publiquement.';
        } else {
            gaugeCircle.style.stroke = 'var(--accent-rose)';
            gaugeStatusTitle.textContent = 'Protection Basique';
            gaugeStatusDesc.textContent = 'Transformation visuelle simple ou perte de données irréversible.';
        }
    }

    // ========================================================================
    // PRESETS MANAGEMENT
    // ========================================================================
    document.querySelectorAll('[data-preset]').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('[data-preset]').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            const preset = chip.dataset.preset;

            if (preset === 'max-sec') {
                algoSelect.value = 'robust-dct-scramble';
                stripExifCb.checked = true;
                embedOriginalCb.checked = true;
                dctPixelCb.checked = true;
                robustModeCb.checked = true;
                glitchIntensity.value = 100;
                glitchValText.textContent = '100%';
            } else if (preset === 'anti-social') {
                algoSelect.value = 'dfws';
                stripExifCb.checked = true;
                embedOriginalCb.checked = true;
                dctPixelCb.checked = true;
                robustModeCb.checked = true;
                glitchIntensity.value = 100;
                glitchValText.textContent = '100%';
            } else if (preset === 'stealth-stego') {
                algoSelect.value = 'none';
                stripExifCb.checked = true;
                embedOriginalCb.checked = false;
                dctPixelCb.checked = true;
                glitchIntensity.value = 100;
                glitchValText.textContent = '100%';
            } else if (preset === 'art-glitch') {
                algoSelect.value = 'cat-map';
                stripExifCb.checked = false;
                embedOriginalCb.checked = true;
                glitchIntensity.value = 75;
                glitchValText.textContent = '75%';
            }

            updateAlgoTag();
            updateSecurityScore();
            showToast(`Profil "${chip.querySelector('strong').textContent}" appliqué`, 'info');
        });
    });

    function updateAlgoTag() {
        const val = algoSelect.value;
        if (['quantize-shuffle', 'color-crush', 'blur-noise', 'salt-pepper'].includes(val)) {
            algoTypeTag.textContent = '⚠️ Destructif';
            algoTypeTag.style.color = 'var(--accent-rose)';
            algoTypeTag.style.borderColor = 'rgba(244,63,94,0.3)';
        } else if (['dfws', 'block-shuffle-8', 'block-shuffle-16', 'robust-dct-scramble'].includes(val)) {
            algoTypeTag.textContent = '🛡️ Résistant WhatsApp & JPEG';
            algoTypeTag.style.color = 'var(--accent-emerald)';
            algoTypeTag.style.borderColor = 'rgba(16,185,129,0.3)';
        } else if (val === 'none') {
            algoTypeTag.textContent = '🔒 Stégano Pure';
            algoTypeTag.style.color = 'var(--primary-light)';
            algoTypeTag.style.borderColor = 'rgba(99,102,241,0.3)';
        } else {
            algoTypeTag.textContent = '100% Réversible';
            algoTypeTag.style.color = 'var(--accent-emerald)';
            algoTypeTag.style.borderColor = 'rgba(16,185,129,0.3)';
        }
    }
    algoSelect.addEventListener('change', () => {
        updateAlgoTag();
        updateSecurityScore();
    });

    // ========================================================================
    // FILE DRAG & DROP & PREVIEW LOADING
    // ========================================================================
    function setupDropZone(dropZone, fileInput, onFileSelected) {
        dropZone.addEventListener('click', (e) => {
            if (e.target.closest('.viewport-floating-bar') || e.target.closest('#compare-handle')) return;
            fileInput.click();
        });
        ['dragenter', 'dragover'].forEach(ev => {
            dropZone.addEventListener(ev, (e) => {
                e.preventDefault();
                dropZone.classList.add('dragover');
            });
        });
        ['dragleave', 'drop'].forEach(ev => {
            dropZone.addEventListener(ev, (e) => {
                e.preventDefault();
                dropZone.classList.remove('dragover');
            });
        });
        dropZone.addEventListener('drop', (e) => {
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                onFileSelected(Array.from(e.dataTransfer.files));
            }
        });
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length) {
                onFileSelected(Array.from(e.target.files));
            }
        });
    }

    setupDropZone(obfDropZone, obfFileInput, (files) => {
        activeFiles = files;
        if (files.length === 1) {
            loadSingleImage(files[0]);
            batchTray.classList.add('hidden');
        } else if (files.length > 1) {
            loadBatchImages(files);
        }
    });

    const btnLoadDemo = document.getElementById('btn-load-demo');
    if (btnLoadDemo) {
        btnLoadDemo.addEventListener('click', (e) => {
            e.stopPropagation();
            showToast('Chargement de l\'image démo...', 'info');

            const demoImg = new Image();
            demoImg.onload = () => {
                try {
                    const c = document.createElement('canvas');
                    c.width = demoImg.naturalWidth || 640;
                    c.height = demoImg.naturalHeight || 480;
                    const ctx = c.getContext('2d');
                    ctx.drawImage(demoImg, 0, 0);
                    c.toBlob((blob) => {
                        if (blob) {
                            const demoFile = new File([blob], 'testimg.jpg', { type: 'image/jpeg', lastModified: Date.now() });
                            activeFiles = [demoFile];
                            loadSingleImage(demoFile);
                        } else {
                            createSyntheticDemoImage();
                        }
                    }, 'image/jpeg');
                } catch {
                    createSyntheticDemoImage();
                }
            };
            demoImg.onerror = () => {
                createSyntheticDemoImage();
            };
            demoImg.src = 'testimg.jpg';
        });
    }

    function createSyntheticDemoImage() {
        const c = document.createElement('canvas');
        c.width = 640;
        c.height = 480;
        const ctx = c.getContext('2d');
        const grad = ctx.createLinearGradient(0, 0, 640, 480);
        grad.addColorStop(0, '#1e1b4b');
        grad.addColorStop(0.5, '#4338ca');
        grad.addColorStop(1, '#06b6d4');
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, 640, 480);

        for (let i = 0; i < 30; i++) {
            ctx.strokeStyle = `rgba(255, 255, 255, ${0.1 + (i % 4) * 0.05})`;
            ctx.lineWidth = 2;
            ctx.strokeRect(i * 14, i * 10, 640 - i * 28, 480 - i * 20);
        }

        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 32px Outfit, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('OBSCURIFY PRO — CRYPTO CARD', 320, 220);
        ctx.font = '16px monospace';
        ctx.fillStyle = '#a5b4fc';
        ctx.fillText('640×480 · Visual Cryptography & DCT Steganography', 320, 260);

        c.toBlob((blob) => {
            const demoFile = new File([blob], 'demo_crypto_card.jpg', { type: 'image/jpeg', lastModified: Date.now() });
            activeFiles = [demoFile];
            loadSingleImage(demoFile);
        }, 'image/jpeg');
    }

    async function loadSingleImage(file) {
        currentImageFile = file;
        const objectUrl = URL.createObjectURL(file);
        currentImage = new Image();
        currentImage.onload = () => {
            imageWidth = currentImage.naturalWidth;
            imageHeight = currentImage.naturalHeight;

            dropEmptyUI.classList.add('hidden');
            compareSliderBox.classList.add('hidden');
            previewViewport.classList.remove('hidden');
            viewportToolbar.classList.remove('hidden');

            mainPreviewImg.src = objectUrl;
            resetZoom();
            buildLiveGallery();
            updateSecurityScore();
            updateForensics();

            showToast(`Image chargée : ${file.name} (${imageWidth}×${imageHeight})`, 'success');
        };
        currentImage.src = objectUrl;
    }

    function loadBatchImages(files) {
        batchCounter.textContent = files.length;
        batchStrip.innerHTML = '';
        files.forEach((file, idx) => {
            const item = document.createElement('div');
            item.className = 'batch-thumb-item';
            const img = document.createElement('img');
            img.src = URL.createObjectURL(file);
            const badge = document.createElement('span');
            badge.className = 'batch-num';
            badge.textContent = idx + 1;
            item.appendChild(img);
            item.appendChild(badge);
            item.addEventListener('click', (e) => {
                e.stopPropagation();
                loadSingleImage(file);
            });
            batchStrip.appendChild(item);
        });
        batchTray.classList.remove('hidden');
        loadSingleImage(files[0]);
    }

    btnClearBatch.addEventListener('click', () => {
        activeFiles = [];
        batchTray.classList.add('hidden');
        batchStrip.innerHTML = '';
    });

    // ========================================================================
    // LIVE ALGORITHM GALLERY MINI-PREVIEWS
    // ========================================================================
    async function buildLiveGallery() {
        algoGallery.innerHTML = '';
        const previewCanvas = document.createElement('canvas');
        const previewSize = 72;
        previewCanvas.width = previewSize;
        previewCanvas.height = previewSize;
        const pCtx = previewCanvas.getContext('2d');
        pCtx.drawImage(currentImage, 0, 0, previewSize, previewSize);
        const baseData = pCtx.getImageData(0, 0, previewSize, previewSize);

        const algosToPreview = [
            { id: 'xor-shuffle', name: 'XOR Chaos' },
            { id: 'cat-map', name: 'Chat Arnold' },
            { id: 'logistic-xor', name: 'Logistique' },
            { id: 'baker-map', name: 'Baker Map' },
            { id: 'chirikov', name: 'Chirikov' },
            { id: 'henon', name: 'Hénon' },
            { id: 'hilbert', name: 'Hilbert' },
            { id: 'spiral', name: 'Spirale' },
            { id: 'zigzag', name: 'Zigzag' },
            { id: 'dfws', name: 'DFWS' },
            { id: 'robust-dct-scramble', name: 'Scramble DCT' },
            { id: 'block-shuffle-16', name: 'Bloc 16×16' },
            { id: 'quantize-shuffle', name: 'Pixélisé' },
            { id: 'color-crush', name: 'Color Crush' }
        ];

        for (const item of algosToPreview) {
            const card = document.createElement('div');
            card.className = `gallery-card ${algoSelect.value === item.id ? 'active' : ''}`;
            card.dataset.algo = item.id;

            const cardCanvas = document.createElement('canvas');
            cardCanvas.width = previewSize;
            cardCanvas.height = previewSize;
            const cCtx = cardCanvas.getContext('2d');

            try {
                const sampleBuffer = baseData.data.buffer.slice(0);
                const { result } = await worker.send({
                    algo: item.id,
                    data: sampleBuffer,
                    width: previewSize,
                    height: previewSize,
                    seed: 'gallery_preview_sample',
                    reverse: false
                }, [sampleBuffer]);

                const outImgData = new ImageData(new Uint8ClampedArray(result), previewSize, previewSize);
                cCtx.putImageData(outImgData, 0, 0);
            } catch {
                cCtx.drawImage(previewCanvas, 0, 0);
            }

            const label = document.createElement('div');
            label.className = 'gallery-label';
            label.textContent = item.name;

            card.appendChild(cardCanvas);
            card.appendChild(label);
            card.addEventListener('click', () => {
                algoSelect.value = item.id;
                document.querySelectorAll('.gallery-card').forEach(c => c.classList.remove('active'));
                card.classList.add('active');
                updateAlgoTag();
                updateSecurityScore();
            });

            algoGallery.appendChild(card);
        }
    }

    // ========================================================================
    // OBFUSCATION & EXPORT WORKFLOW
    // ========================================================================
    btnRunObfuscate.addEventListener('click', async () => {
        const filesToProcess = activeFiles.length > 1 ? activeFiles : (currentImageFile ? [currentImageFile] : []);
        if (!filesToProcess.length) {
            showToast('Veuillez d\'abord charger une image.', 'error');
            return;
        }

        btnRunObfuscate.disabled = true;
        btnRunObfuscate.innerHTML = `
            <svg class="spinner" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle><path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"></path></svg>
            <span>Calculs Cryptographiques...</span>
        `;

        try {
            const pwd = obfPwd.value.trim();
            const algo = algoSelect.value;
            const isRobust = robustModeCb.checked;
            const intensity = parseInt(glitchIntensity.value, 10) / 100;
            const wmActive = watermarkToggle.checked && watermarkText.value.trim();
            const wmText = wmActive ? watermarkText.value.trim() : '';
            const wmMode = document.querySelector('input[name="wm-mode"]:checked')?.value || 'lsb';

            let salt = crypto.randomUUID();
            if (isRobust && pwd) {
                salt = await CryptoEngine.getDeterministicSalt(pwd);
            }
            const seed = pwd ? pwd + salt : 'public' + salt;

            // Process First Image for Live Viewport & Comparison
            const primaryFile = filesToProcess[0];
            const primaryImg = new Image();
            primaryImg.src = URL.createObjectURL(primaryFile);
            await new Promise(r => primaryImg.onload = r);

            const canvas = document.createElement('canvas');
            canvas.width = primaryImg.naturalWidth;
            canvas.height = primaryImg.naturalHeight;
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(primaryImg, 0, 0);

            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            originalPixels = new Uint8Array(imgData.data);
            imageWidth = canvas.width;
            imageHeight = canvas.height;

            // Determine Hidden File / Document Payload
            let fileToEmbed = selectedSecretFile;
            if (!fileToEmbed && embedSecretFile.files && embedSecretFile.files.length) {
                fileToEmbed = embedSecretFile.files[0];
            }

            let secretFilePayloadForDct = null;
            let secretThumbPayload = null;

            if (dctPixelCb.checked) {
                if (fileToEmbed) {
                    // Embed Document in DCT Coefficients (Compression-Resistant & Format-Conversion Resistant)
                    const rawBuf = await fileToEmbed.arrayBuffer();
                    const compBuf = await CryptoEngine.compress(rawBuf);
                    let finalBuf = compBuf;
                    if (pwd) {
                        const dctSalt = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pwd + 'OBSCURIFY_DCT_SALT'))).slice(0, 16);
                        const dctIv = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pwd + 'OBSCURIFY_DCT_IV'))).slice(0, 12);
                        const key = await CryptoEngine.deriveKey(pwd, dctSalt);
                        finalBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: dctIv }, key, compBuf);
                    }
                    secretFilePayloadForDct = {
                        data: finalBuf,
                        name: fileToEmbed.name,
                        mime: fileToEmbed.type || 'application/octet-stream',
                        encrypted: !!pwd
                    };
                } else if (embedOriginalCb.checked) {
                    // Embed Downscaled Original Image in DCT
                    const secretThumb = downscaleImage(primaryImg, 64);
                    secretThumbPayload = {
                        data: secretThumb.data.buffer,
                        width: secretThumb.width,
                        height: secretThumb.height
                    };
                }
            }

            // Run Cryptographic Algorithm & DCT Pixel Embedding in a single unified step
            const bufferToTransfer = imgData.data.buffer.slice(0);
            const transferList = [bufferToTransfer];
            if (secretFilePayloadForDct && secretFilePayloadForDct.data instanceof ArrayBuffer) {
                transferList.push(secretFilePayloadForDct.data);
            }
            if (secretThumbPayload && secretThumbPayload.data instanceof ArrayBuffer) {
                transferList.push(secretThumbPayload.data);
            }

            const { result } = await worker.send({
                algo,
                data: bufferToTransfer,
                width: canvas.width,
                height: canvas.height,
                seed,
                reverse: false,
                intensity,
                secretFile: secretFilePayloadForDct,
                secretImage: secretThumbPayload
            }, transferList);

            imgData.data.set(new Uint8Array(result));

            // Watermark embedding (LSB)
            if (wmActive && wmMode === 'lsb') {
                try {
                    StegoEngine.encodeLSB(imgData, new TextEncoder().encode(`WM:${wmText}`));
                } catch (e) {
                    console.warn('LSB Watermark warning:', e);
                }
            }

            obfuscatedPixels = new Uint8Array(imgData.data);
            ctx.putImageData(imgData, 0, 0);

            // Container Metadata Assembly
            const metadata = {
                v: 4,
                alg: algo,
                pwd: !!pwd,
                salt,
                robust: isRobust,
                mime: primaryFile.type || 'image/png',
                wm: wmActive ? { text: wmText, mode: wmMode } : null
            };

            // Also embed in metadata trailer for dual redundancy (lossless PNG)
            const metaFile = fileToEmbed || (embedOriginalCb.checked ? primaryFile : null);
            if (metaFile) {
                const rawBuf = await metaFile.arrayBuffer();
                const compressedBuf = await CryptoEngine.compress(rawBuf);
                const { encrypted, salt: pSalt, iv: pIv } = await CryptoEngine.encryptData(compressedBuf, pwd);
                metadata.payload = {
                    data: CryptoEngine.bufferToBase64(encrypted),
                    salt: pSalt ? CryptoEngine.bufferToBase64(pSalt) : null,
                    iv: pIv ? CryptoEngine.bufferToBase64(pIv) : null,
                    mime: metaFile.type || 'application/octet-stream',
                    filename: metaFile.name || 'document.bin'
                };
            }

            // Export blob with container trailer
            const exportMime = exportFormatSelect.value;
            const visualBlob = await new Promise(r => canvas.toBlob(r, exportMime, 0.95));
            const metaPayload = new TextEncoder().encode(JSON.stringify(metadata) + MAGIC_V4);
            const finalBlob = new Blob([visualBlob, metaPayload], { type: exportMime });

            // Calculate SHA-256 integrity hash
            const sha256 = await CryptoEngine.hashBuffer(finalBlob, 'SHA-256');
            hashValue.textContent = sha256;
            integrityCard.classList.remove('hidden');

            // Trigger Download
            const ext = exportMime.split('/')[1] || 'png';
            const dlLink = document.createElement('a');
            dlLink.href = URL.createObjectURL(finalBlob);
            dlLink.download = `obscurify_${Date.now()}.${ext}`;
            dlLink.click();
            URL.revokeObjectURL(dlLink.href);

            // Switch Viewport to Interactive Comparison Slider
            initCompareSlider();

            // Store in Audit History
            addHistoryRecord({
                filename: primaryFile.name,
                algo,
                date: Date.now(),
                sha256,
                thumbUrl: createThumbnailDataUrl(canvas, 64)
            });

            SoundManager.play('success');
            showToast('Image obfusquée et sécurisée avec succès !', 'success');

        } catch (err) {
            console.error(err);
            SoundManager.play('error');
            showToast(`Erreur : ${err.message}`, 'error');
        } finally {
            btnRunObfuscate.disabled = false;
            btnRunObfuscate.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <span>Offusquer & Télécharger</span>
            `;
        }
    });

    function downscaleImage(img, targetWidth) {
        const c = document.createElement('canvas');
        const targetHeight = Math.round(targetWidth * (img.naturalHeight / img.naturalWidth));
        c.width = targetWidth;
        c.height = targetHeight;
        const cx = c.getContext('2d');
        cx.drawImage(img, 0, 0, targetWidth, targetHeight);
        return cx.getImageData(0, 0, targetWidth, targetHeight);
    }

    function createThumbnailDataUrl(sourceCanvas, size = 64) {
        const c = document.createElement('canvas');
        c.width = size;
        c.height = size;
        const cx = c.getContext('2d');
        cx.drawImage(sourceCanvas, 0, 0, size, size);
        return c.toDataURL('image/png');
    }

    // ========================================================================
    // INTERACTIVE SPLIT COMPARE SLIDER
    // ========================================================================
    function initCompareSlider() {
        if (!originalPixels || !obfuscatedPixels) return;

        previewViewport.classList.add('hidden');
        compareSliderBox.classList.remove('hidden');

        compareCanvas.width = imageWidth;
        compareCanvas.height = imageHeight;
        renderCompareCanvas();

        compareSliderBox.onmousedown = (e) => {
            isDraggingSlider = true;
            updateSliderPos(e);
        };
        window.addEventListener('mousemove', (e) => {
            if (isDraggingSlider) updateSliderPos(e);
        });
        window.addEventListener('mouseup', () => { isDraggingSlider = false; });

        // Touch support
        compareSliderBox.ontouchstart = (e) => {
            isDraggingSlider = true;
            if (e.touches[0]) updateSliderPos(e.touches[0]);
        };
        window.addEventListener('touchmove', (e) => {
            if (isDraggingSlider && e.touches[0]) updateSliderPos(e.touches[0]);
        });
        window.addEventListener('touchend', () => { isDraggingSlider = false; });
    }

    function updateSliderPos(e) {
        const rect = compareSliderBox.getBoundingClientRect();
        const clientX = e.clientX || (e.touches && e.touches[0] ? e.touches[0].clientX : rect.left);
        const relX = Math.max(0, Math.min(rect.width, clientX - rect.left));
        compareSplit = relX / rect.width;
        compareHandle.style.left = `${compareSplit * 100}%`;
        renderCompareCanvas();
    }

    function renderCompareCanvas() {
        const ctx = compareCanvas.getContext('2d');
        const splitPixelX = Math.round(imageWidth * compareSplit);

        const combinedData = ctx.createImageData(imageWidth, imageHeight);
        const cData = combinedData.data;

        for (let y = 0; y < imageHeight; y++) {
            const rowOffset = y * imageWidth * 4;
            // Left slice: original
            for (let x = 0; x < splitPixelX; x++) {
                const idx = rowOffset + x * 4;
                cData[idx]     = originalPixels[idx];
                cData[idx + 1] = originalPixels[idx + 1];
                cData[idx + 2] = originalPixels[idx + 2];
                cData[idx + 3] = originalPixels[idx + 3];
            }
            // Right slice: obfuscated
            for (let x = splitPixelX; x < imageWidth; x++) {
                const idx = rowOffset + x * 4;
                cData[idx]     = obfuscatedPixels[idx];
                cData[idx + 1] = obfuscatedPixels[idx + 1];
                cData[idx + 2] = obfuscatedPixels[idx + 2];
                cData[idx + 3] = obfuscatedPixels[idx + 3];
            }
        }
        ctx.putImageData(combinedData, 0, 0);
    }

    // Zoom and Pan Controls
    document.getElementById('btn-zoom-in')?.addEventListener('click', () => applyZoom(0.2));
    document.getElementById('btn-zoom-out')?.addEventListener('click', () => applyZoom(-0.2));
    document.getElementById('btn-zoom-reset')?.addEventListener('click', resetZoom);

    document.getElementById('btn-export-comparison-gif')?.addEventListener('click', async () => {
        if (!originalPixels || !obfuscatedPixels) {
            return showToast('Offusquez d\'abord une image pour exporter le comparatif.', 'info');
        }
        showToast('Génération de l\'animation comparative...', 'info');
        try {
            const animCanvas = document.createElement('canvas');
            const maxDim = 600;
            const scale = Math.min(1, maxDim / Math.max(imageWidth, imageHeight));
            animCanvas.width = Math.round(imageWidth * scale);
            animCanvas.height = Math.round(imageHeight * scale);
            const aCtx = animCanvas.getContext('2d');

            const origCanvas = document.createElement('canvas');
            origCanvas.width = imageWidth; origCanvas.height = imageHeight;
            origCanvas.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(originalPixels), imageWidth, imageHeight), 0, 0);

            const obfCanvas = document.createElement('canvas');
            obfCanvas.width = imageWidth; obfCanvas.height = imageHeight;
            obfCanvas.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(obfuscatedPixels), imageWidth, imageHeight), 0, 0);

            if (window.MediaRecorder && animCanvas.captureStream) {
                const stream = animCanvas.captureStream(30);
                const recorder = new MediaRecorder(stream, { mimeType: 'video/webm' });
                const chunks = [];
                recorder.ondataavailable = e => chunks.push(e.data);
                recorder.onstop = () => {
                    const blob = new Blob(chunks, { type: 'video/webm' });
                    const a = document.createElement('a');
                    a.href = URL.createObjectURL(blob);
                    a.download = `obscurify_comparatif_${Date.now()}.webm`;
                    a.click();
                    URL.revokeObjectURL(a.href);
                    showToast('Animation comparative (WebM) téléchargée !', 'success');
                };
                recorder.start();

                let step = 0;
                const totalSteps = 90;
                const animInterval = setInterval(() => {
                    step++;
                    const progress = (step % 45) / 45;
                    const split = step < 45 ? progress : (1 - progress);
                    aCtx.clearRect(0, 0, animCanvas.width, animCanvas.height);
                    aCtx.drawImage(origCanvas, 0, 0, animCanvas.width, animCanvas.height);
                    aCtx.save();
                    aCtx.beginPath();
                    aCtx.rect(animCanvas.width * split, 0, animCanvas.width * (1 - split), animCanvas.height);
                    aCtx.clip();
                    aCtx.drawImage(obfCanvas, 0, 0, animCanvas.width, animCanvas.height);
                    aCtx.restore();

                    // Split line
                    aCtx.fillStyle = '#ffffff';
                    aCtx.fillRect(animCanvas.width * split - 1, 0, 2, animCanvas.height);

                    if (step >= totalSteps) {
                        clearInterval(animInterval);
                        recorder.stop();
                    }
                }, 33);
            } else {
                showToast('MediaRecorder non supporté sur ce navigateur.', 'info');
            }
        } catch (err) {
            console.error(err);
            showToast('Erreur génération vidéo comparative.', 'error');
        }
    });

    function applyZoom(delta) {
        zoomScale = Math.max(0.5, Math.min(5, zoomScale + delta));
        mainPreviewImg.style.transform = `translate(${panX}px, ${panY}px) scale(${zoomScale})`;
    }

    function resetZoom() {
        zoomScale = 1;
        panX = 0;
        panY = 0;
        mainPreviewImg.style.transform = 'translate(0px, 0px) scale(1)';
    }

    // Viewport Pan
    previewViewport.addEventListener('mousedown', (e) => {
        if (zoomScale <= 1) return;
        isPanning = true;
        panStartX = e.clientX - panX;
        panStartY = e.clientY - panY;
    });
    window.addEventListener('mousemove', (e) => {
        if (!isPanning) return;
        panX = e.clientX - panStartX;
        panY = e.clientY - panStartY;
        mainPreviewImg.style.transform = `translate(${panX}px, ${panY}px) scale(${zoomScale})`;
    });
    window.addEventListener('mouseup', () => { isPanning = false; });
    previewViewport.addEventListener('dblclick', resetZoom);

    // ========================================================================
    // TAB 2: REVERT & RESTORATION WORKFLOW
    // ========================================================================
    setupDropZone(revertDropZone, revertFileInput, async (files) => {
        if (files.length) {
            targetRevertFile = files[0];
            const objUrl = URL.createObjectURL(targetRevertFile);
            targetRevertImage = new Image();
            targetRevertImage.onload = async () => {
                revertEmptyUI.classList.add('hidden');
                revertViewport.classList.remove('hidden');
                revertPreviewImg.src = objUrl;

                // Inspect image trailer for container tags
                try {
                    const buffer = await targetRevertFile.arrayBuffer();
                    const dec = new TextDecoder();
                    const tailSlice = dec.decode(buffer.slice(Math.max(0, buffer.byteLength - 15000000)));

                    let magicIdx = tailSlice.lastIndexOf(MAGIC_V4);
                    let isLegacy = false;
                    if (magicIdx === -1) {
                        magicIdx = tailSlice.lastIndexOf(LEGACY_MAGIC);
                        isLegacy = true;
                    }

                    if (magicIdx !== -1) {
                        const searchVer = isLegacy ? '{"v":5' : '{"v":4';
                        const jStart = tailSlice.substring(0, magicIdx).lastIndexOf(searchVer);
                        if (jStart !== -1) {
                            const metaFound = JSON.parse(tailSlice.substring(jStart, magicIdx));
                            if (revertContainerBadge) {
                                revertContainerBadge.textContent = '📦 Conteneur Détecté (v4)';
                                revertContainerBadge.style.background = 'rgba(16,185,129,0.15)';
                                revertContainerBadge.style.color = 'var(--accent-emerald)';
                                revertContainerBadge.style.borderColor = 'rgba(16,185,129,0.3)';
                            }
                            if (metaFound.alg && revertAlgoSelect) {
                                revertAlgoSelect.value = metaFound.alg;
                            }
                            showToast(`Image reconnue : algorithme ${metaFound.alg.toUpperCase()}`, 'success');
                            return;
                        }
                    }
                } catch (e) {
                    console.warn('Trailer inspect warning:', e);
                }

                // If no metadata trailer was found (JPEG / converted image)
                if (revertContainerBadge) {
                    revertContainerBadge.textContent = '🛡️ Mode JPEG / Sans Métadonnées';
                    revertContainerBadge.style.background = 'rgba(245,158,11,0.15)';
                    revertContainerBadge.style.color = 'var(--accent-amber)';
                    revertContainerBadge.style.borderColor = 'rgba(245,158,11,0.3)';
                }
                if (revertAlgoSelect && revertAlgoSelect.value === 'auto') {
                    revertAlgoSelect.value = 'robust-dct-scramble';
                }
                showToast('Image JPEG / sans métadonnées : Détection fréquentielle DCT & choix d\'algorithme activé.', 'info');
            };
            targetRevertImage.src = objUrl;
        }
    });

    btnRunRevert.addEventListener('click', async () => {
        if (!targetRevertFile) {
            showToast('Sélectionnez d\'abord l\'image à restaurer.', 'error');
            return;
        }

        btnRunRevert.disabled = true;
        btnRunRevert.textContent = 'Déchiffrement en cours...';

        try {
            const buffer = await targetRevertFile.arrayBuffer();
            const dec = new TextDecoder();
            const tailSlice = dec.decode(buffer.slice(Math.max(0, buffer.byteLength - 15000000)));

            // Find magic trailer (v4 or legacy)
            let magicIdx = tailSlice.lastIndexOf(MAGIC_V4);
            let isLegacy = false;
            if (magicIdx === -1) {
                magicIdx = tailSlice.lastIndexOf(LEGACY_MAGIC);
                isLegacy = true;
            }

            let meta = null;
            if (magicIdx !== -1) {
                const searchVersion = isLegacy ? '{"v":5' : '{"v":4';
                const jsonStart = tailSlice.substring(0, magicIdx).lastIndexOf(searchVersion);
                if (jsonStart !== -1) {
                    try {
                        const jsonStr = tailSlice.substring(jsonStart, magicIdx);
                        meta = JSON.parse(jsonStr);
                    } catch {}
                }
            }

            // Determine effective algorithm (honor manual selector override)
            let chosenAlgo = 'robust-dct-scramble';
            if (revertAlgoSelect && revertAlgoSelect.value !== 'auto') {
                chosenAlgo = revertAlgoSelect.value;
            } else if (meta && meta.alg) {
                chosenAlgo = meta.alg;
            }

            const pwd = revertPwd.value.trim();

            // Fallback: If metadata was stripped (JPEG or conversion)
            if (!meta) {
                meta = {
                    v: 4,
                    alg: chosenAlgo,
                    pwd: !!pwd,
                    robust: true,
                    salt: 'public'
                };
                showToast('Mode de secours engagé (Survit au JPEG & Recompression).', 'info');
            } else {
                meta.alg = chosenAlgo;
            }

            let saltToUse = meta.salt || 'public';
            if (meta.robust && pwd) {
                saltToUse = await CryptoEngine.getDeterministicSalt(pwd);
            }
            const seed = meta.pwd ? pwd + saltToUse : 'public' + saltToUse;

            const canvas = document.createElement('canvas');
            canvas.width = targetRevertImage.naturalWidth || targetRevertImage.width;
            canvas.height = targetRevertImage.naturalHeight || targetRevertImage.height;
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(targetRevertImage, 0, 0);

            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

            // Watermark detection (LSB)
            const lsbBytes = StegoEngine.decodeLSB(imgData);
            if (lsbBytes) {
                const txt = new TextDecoder().decode(lsbBytes);
                if (txt.startsWith('WM:')) {
                    detectedWmInfo.textContent = `🔖 Filigrane LSB : "${txt.substring(3)}"`;
                    revertMetaCard.classList.remove('hidden');
                }
            }

            // Mathematical inverse transformation & DCT pixel steganography extraction
            let extractedSecret = null;
            if (meta.alg && meta.alg !== 'none') {
                const bufferToTransfer = imgData.data.buffer.slice(0);
                const sendRes = await worker.send({
                    algo: meta.alg,
                    data: bufferToTransfer,
                    width: canvas.width,
                    height: canvas.height,
                    seed,
                    reverse: true,
                    extractSecret: true
                }, [bufferToTransfer]);

                imgData.data.set(new Uint8Array(sendRes.result));
                extractedSecret = sendRes.extractedSecret;
            } else {
                // Algo 'none' — pure steganography extraction
                const bufferToTransfer = imgData.data.buffer.slice(0);
                const sendRes = await worker.send({
                    algo: 'dct-extract',
                    data: bufferToTransfer,
                    width: canvas.width,
                    height: canvas.height
                }, [bufferToTransfer]);
                extractedSecret = sendRes.extractedSecret;
            }

            ctx.putImageData(imgData, 0, 0);

            // Revert display
            const mathBlob = await new Promise(r => canvas.toBlob(r, meta.mime || 'image/png'));
            if (currentRestoredBlobUrl) URL.revokeObjectURL(currentRestoredBlobUrl);
            currentRestoredBlobUrl = URL.createObjectURL(mathBlob);
            revertPreviewImg.src = currentRestoredBlobUrl;

            let payloadResolved = false;

            // 1. Process DCT-Extracted Secret (Survives JPEG compression and conversions!)
            if (extractedSecret) {
                try {
                    if (extractedSecret.type === 'file') {
                        let fileBuffer = extractedSecret.data;
                        if (extractedSecret.encrypted) {
                            if (!pwd) {
                                showToast('Document secret DCT chiffré détecté. Saisissez le mot de passe pour le déchiffrer.', 'info');
                            } else {
                                const dctSalt = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pwd + 'OBSCURIFY_DCT_SALT'))).slice(0, 16);
                                const dctIv = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pwd + 'OBSCURIFY_DCT_IV'))).slice(0, 12);
                                const key = await CryptoEngine.deriveKey(pwd, dctSalt);
                                fileBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: dctIv }, key, fileBuffer);
                            }
                        }
                        if (fileBuffer) {
                            const decompressed = await CryptoEngine.decompress(fileBuffer);
                            displayExtractedFilePayload({
                                data: decompressed,
                                name: extractedSecret.fileName || 'document_secret.bin',
                                mime: extractedSecret.mimeType || 'application/octet-stream',
                                source: 'dct'
                            });
                            payloadResolved = true;
                        }
                    } else if (extractedSecret.type === 'image') {
                        displayExtractedImageThumbnail(extractedSecret);
                        payloadResolved = true;
                    }
                } catch (e) {
                    console.warn('DCT secret decryption/decompression error:', e);
                    showToast('Erreur déchiffrement DCT : mot de passe incorrect ?', 'error');
                }
            }

            // 2. Fallback: Process Metadata Container Payload if DCT didn't resolve
            if (!payloadResolved && meta && meta.payload) {
                try {
                    const encBuf = CryptoEngine.base64ToBuffer(meta.payload.data);
                    const sSalt = meta.payload.salt ? CryptoEngine.base64ToBuffer(meta.payload.salt) : null;
                    const sIv = meta.payload.iv ? CryptoEngine.base64ToBuffer(meta.payload.iv) : null;

                    const decBuffer = await CryptoEngine.decryptData(encBuf, pwd, sSalt, sIv);
                    const decompressed = await CryptoEngine.decompress(decBuffer);

                    displayExtractedFilePayload({
                        data: decompressed,
                        name: meta.payload.filename || 'document_secret.bin',
                        mime: meta.payload.mime || 'application/octet-stream',
                        source: 'metadata'
                    });
                    payloadResolved = true;
                } catch (e) {
                    console.warn('Metadata trailer payload decryption error:', e);
                    showToast('Payload conteneur détecté mais mot de passe incorrect.', 'error');
                }
            }

            detectedAlgoInfo.textContent = meta.alg ? meta.alg.toUpperCase() : 'INCONNU';
            detectedSigInfo.textContent = magicIdx !== -1 ? 'Conteneur Intact (v4)' : 'Mode Fréquentiel (Sans Métadonnées)';
            revertMetaCard.classList.remove('hidden');

            SoundManager.play('success');
            showToast('Restauration et analyse achevées avec succès !', 'success');

        } catch (err) {
            console.error(err);
            SoundManager.play('error');
            showToast(`Erreur : ${err.message}`, 'error');
        } finally {
            btnRunRevert.disabled = false;
            btnRunRevert.textContent = 'Déchiffrer & Restaurer';
        }
    });

    btnDownloadSecret.addEventListener('click', () => {
        if (!currentSecretPayloadBlob) return;
        const dlLink = document.createElement('a');
        dlLink.href = URL.createObjectURL(currentSecretPayloadBlob);
        dlLink.download = payloadFilenameText.textContent || 'secret_file';
        dlLink.click();
        URL.revokeObjectURL(dlLink.href);
    });

    function displayExtractedFilePayload({ data, name, mime, source }) {
        const payloadBlob = new Blob([data], { type: mime || 'application/octet-stream' });
        currentSecretPayloadBlob = payloadBlob;

        payloadFilenameText.textContent = name;
        payloadMetaText.textContent = `${(payloadBlob.size / 1024).toFixed(1)} KB · ${payloadBlob.type || 'Fichier binaire'}`;

        if (source === 'dct') {
            payloadSourceTag.textContent = '🛡️ Extrait des fréquences DCT (Survit au JPEG & Recompression)';
            payloadSourceTag.className = 'payload-source-tag robust';
        } else {
            payloadSourceTag.textContent = '📦 Extrait du conteneur de métadonnées (PNG)';
            payloadSourceTag.className = 'payload-source-tag metadata';
        }

        const ext = (name.split('.').pop() || 'bin').toUpperCase().slice(0, 4);
        payloadTypeBadge.textContent = ext;

        if (payloadBlob.type.startsWith('image/')) {
            payloadThumbPreview.src = URL.createObjectURL(payloadBlob);
        } else {
            let emoji = '📄';
            let bg = '%234f46e5';
            if (mime.includes('pdf') || ext === 'PDF') { emoji = '📕'; bg = '%23e11d48'; }
            else if (mime.includes('zip') || mime.includes('compressed') || ext === 'ZIP') { emoji = '🗜️'; bg = '%230891b2'; }
            else if (mime.includes('text') || ext === 'TXT') { emoji = '📝'; bg = '%23059669'; }
            else if (mime.includes('word') || ext === 'DOC' || ext === 'DOCX') { emoji = '📘'; bg = '%232563eb'; }
            else if (mime.includes('audio')) { emoji = '🎵'; bg = '%237c3aed'; }
            payloadThumbPreview.src = `data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" rx="16" fill="${bg}"/><text x="50" y="62" text-anchor="middle" font-size="42">${emoji}</text></svg>`;
        }

        extractedPayloadCard.classList.remove('hidden');
        showToast(`Document secret "${name}" récupéré avec succès !`, 'success');
    }

    function displayExtractedImageThumbnail(secret) {
        const secretCanvas = document.createElement('canvas');
        secretCanvas.width = secret.width;
        secretCanvas.height = secret.height;
        secretCanvas.getContext('2d').putImageData(
            new ImageData(new Uint8ClampedArray(secret.data), secret.width, secret.height),
            0,
            0
        );
        secretCanvas.toBlob((blob) => {
            currentSecretPayloadBlob = blob;
            payloadThumbPreview.src = secretCanvas.toDataURL();
            payloadFilenameText.textContent = `originale_recuperee_${secret.width}x${secret.height}.png`;
            payloadMetaText.textContent = `${secret.width}×${secret.height} px · Image miniature originale`;
            payloadTypeBadge.textContent = 'PNG';
            payloadSourceTag.textContent = '🛡️ Extrait des coefficients DCT (Survit au JPEG)';
            payloadSourceTag.className = 'payload-source-tag robust';
            extractedPayloadCard.classList.remove('hidden');
            showToast('Image secrète originale extraite des fréquences DCT !', 'success');
        }, 'image/png');
    }

    // Brute Force Scan
    btnBruteForce.addEventListener('click', async () => {
        if (!targetRevertFile) return showToast('Sélectionnez d\'abord une image.', 'error');
        btnBruteForce.disabled = true;
        btnBruteForce.textContent = 'Scan en cours...';

        try {
            const zip = new JSZip();
            const pwd = revertPwd.value.trim();
            const w = targetRevertImage.naturalWidth || targetRevertImage.width;
            const h = targetRevertImage.naturalHeight || targetRevertImage.height;

            const tempCanvas = document.createElement('canvas');
            tempCanvas.width = w;
            tempCanvas.height = h;
            const tCtx = tempCanvas.getContext('2d');
            tCtx.drawImage(targetRevertImage, 0, 0);

            const algos = ['xor-shuffle', 'cat-map', 'logistic-xor', 'dfws', 'baker-map', 'block-shuffle-16', 'henon'];
            const robustSalt = await CryptoEngine.getDeterministicSalt(pwd);

            for (const algo of algos) {
                const imgData = tCtx.getImageData(0, 0, w, h);
                const buf = imgData.data.buffer.slice(0);
                const seed = (pwd || 'public') + robustSalt;

                const { result } = await worker.send({
                    algo,
                    data: buf,
                    width: w,
                    height: h,
                    seed,
                    reverse: true
                }, [buf]);

                const outCanvas = document.createElement('canvas');
                outCanvas.width = w;
                outCanvas.height = h;
                outCanvas.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(result), w, h), 0, 0);

                const blob = await new Promise(r => outCanvas.toBlob(r, 'image/png'));
                zip.file(`${algo}_restored.png`, blob);
            }

            const zipBlob = await zip.generateAsync({ type: 'blob' });
            const dl = document.createElement('a');
            dl.href = URL.createObjectURL(zipBlob);
            dl.download = `obscurify_scan_${Date.now()}.zip`;
            dl.click();
            URL.revokeObjectURL(dl.href);

            SoundManager.play('success');
            showToast('Scan complet achevé ! Archive ZIP générée.', 'success');
        } catch (e) {
            SoundManager.play('error');
            showToast(`Erreur brute-force : ${e.message}`, 'error');
        } finally {
            btnBruteForce.disabled = false;
            btnBruteForce.textContent = '🚀 Scan Multi-Algorithmes (Brute Force)';
        }
    });

    // ========================================================================
    // TAB 3: FORENSIC LAB & BIT-PLANE VISUALIZER
    // ========================================================================
    bitChips.forEach(chip => {
        chip.addEventListener('click', () => {
            bitChips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            forensicBit = parseInt(chip.dataset.bit, 10);
            renderBitPlane();
        });
    });

    channelChips.forEach(chip => {
        chip.addEventListener('click', () => {
            channelChips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            forensicChannel = chip.dataset.channel;
            renderBitPlane();
        });
    });

    async function updateForensics() {
        if (!currentImage || !currentImage.src) return;

        // Render Bit Plane
        renderBitPlane();

        // Render EXIF Table
        if (currentImageFile) {
            const meta = await EXIFCleaner.inspect(currentImageFile);
            exifTableBody.innerHTML = '';
            for (const [key, val] of Object.entries(meta)) {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td><strong>${key}</strong></td><td>${val}</td>`;
                exifTableBody.appendChild(tr);
            }

            // Cryptographic Hashes
            CryptoEngine.hashBuffer(currentImageFile, 'SHA-256').then(h => forensicSha256.textContent = h);
            CryptoEngine.hashBuffer(currentImageFile, 'SHA-512').then(h => forensicSha512.textContent = h);
        }
    }

    async function renderBitPlane() {
        if (!currentImage.naturalWidth) return;
        const w = currentImage.naturalWidth;
        const h = currentImage.naturalHeight;

        bitPlaneCanvas.width = w;
        bitPlaneCanvas.height = h;

        const offCanvas = document.createElement('canvas');
        offCanvas.width = w;
        offCanvas.height = h;
        const oCtx = offCanvas.getContext('2d');
        oCtx.drawImage(currentImage, 0, 0);

        const imgData = oCtx.getImageData(0, 0, w, h);
        const buf = imgData.data.buffer.slice(0);

        try {
            const { result } = await worker.send({
                type: 'bit-plane',
                data: buf,
                width: w,
                height: h,
                channel: forensicChannel,
                bitIndex: forensicBit
            }, [buf]);

            const outImg = new ImageData(new Uint8ClampedArray(result), w, h);
            bitPlaneCanvas.getContext('2d').putImageData(outImg, 0, 0);
        } catch (e) {
            console.error('Bit plane visualization error:', e);
        }
    }

    btnStripAndSave.addEventListener('click', async () => {
        if (!currentImage.naturalWidth) return;
        const sanitizedBlob = await EXIFCleaner.sanitizeImage(currentImage, 'image/png');
        const dl = document.createElement('a');
        dl.href = URL.createObjectURL(sanitizedBlob);
        dl.download = `anonymized_${Date.now()}.png`;
        dl.click();
        URL.revokeObjectURL(dl.href);
        showToast('Image 100% anonymisée et téléchargée sans métadonnées.', 'success');
    });

    // ========================================================================
    // TAB 4: AUDIT HISTORY & SESSIONS
    // ========================================================================
    function getHistory() {
        try {
            return JSON.parse(localStorage.getItem('obscurify_history') || '[]');
        } catch {
            return [];
        }
    }

    function addHistoryRecord(record) {
        const history = getHistory();
        history.unshift(record);
        if (history.length > 25) history.pop();
        localStorage.setItem('obscurify_history', JSON.stringify(history));
        renderHistory();
    }

    function renderHistory() {
        const history = getHistory();
        historyContainer.innerHTML = '';
        if (!history.length) {
            historyEmptyState.classList.remove('hidden');
            return;
        }
        historyEmptyState.classList.add('hidden');

        history.forEach((item, idx) => {
            const card = document.createElement('div');
            card.className = 'history-item';
            const dateStr = new Date(item.date).toLocaleString('fr-FR');
            card.innerHTML = `
                <div class="history-left">
                    <img src="${item.thumbUrl}" class="history-thumb" alt="Thumbnail">
                    <div class="history-title-group">
                        <h4>${item.filename}</h4>
                        <p>${item.algo.toUpperCase()} · ${dateStr}</p>
                        <code style="font-size:0.68rem;color:var(--text-tertiary);">${item.sha256.substring(0, 24)}...</code>
                    </div>
                </div>
                <div class="history-actions">
                    <button class="btn-icon" data-copy-hash="${item.sha256}" title="Copier le hash">📋</button>
                    <button class="btn-icon" data-del-idx="${idx}" title="Supprimer" style="color:var(--accent-rose);">🗑️</button>
                </div>
            `;

            card.querySelector('[data-copy-hash]').addEventListener('click', () => {
                navigator.clipboard.writeText(item.sha256);
                showToast('Hash copié !', 'success');
            });

            card.querySelector('[data-del-idx]').addEventListener('click', () => {
                const hist = getHistory();
                hist.splice(idx, 1);
                localStorage.setItem('obscurify_history', JSON.stringify(hist));
                renderHistory();
                showToast('Entrée supprimée de l\'historique.', 'info');
            });

            historyContainer.appendChild(card);
        });
    }

    btnExportHistory.addEventListener('click', () => {
        const history = getHistory();
        const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
        const dl = document.createElement('a');
        dl.href = URL.createObjectURL(blob);
        dl.download = `obscurify_audit_${Date.now()}.json`;
        dl.click();
        URL.revokeObjectURL(dl.href);
    });

    btnClearHistory.addEventListener('click', () => {
        if (confirm('Voulez-vous purger complètement l\'historique d\'audit ?')) {
            localStorage.removeItem('obscurify_history');
            renderHistory();
            showToast('Historique purgé avec succès.', 'info');
        }
    });

    // ========================================================================
    // KEYBOARD SHORTCUTS
    // ========================================================================
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            helpModal.classList.remove('active');
        }
        if (e.ctrlKey && e.key.toLowerCase() === 'o') {
            e.preventDefault();
            obfFileInput.click();
        }
        if (e.ctrlKey && e.key === 'Enter') {
            e.preventDefault();
            btnRunObfuscate.click();
        }
        if (e.code === 'Space' && !['INPUT', 'TEXTAREA'].includes(e.target.tagName)) {
            e.preventDefault();
            if (originalPixels && obfuscatedPixels) {
                compareSplit = compareSplit > 0.5 ? 0.05 : 0.95;
                compareHandle.style.left = `${compareSplit * 100}%`;
                renderCompareCanvas();
            }
        }
    });

    // Initialize state
    updateAlgoTag();
    updateSecurityScore();
    renderHistory();
    console.log('🛡️ Obscurify Pro v4.0 initialisé avec succès');
});
