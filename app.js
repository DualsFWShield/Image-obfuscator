const MAGIC_MARKER = '_OBFS_SAAS_';

document.addEventListener('DOMContentLoaded', () => {
    // --- UI Elements ---
    const tabs = document.querySelectorAll('.tab-btn');
    const views = document.querySelectorAll('.view-content');

    const obfDrop = document.getElementById('obfuscate-drop');
    const obfFile = document.getElementById('obfuscate-file');
    const obfPreview = document.getElementById('obfuscate-preview');
    const btnObfuscate = document.getElementById('btn-obfuscate');
    
    const algoSelect = document.getElementById('algo-select');
    const obfPwd = document.getElementById('obfuscate-pwd');
    const obfSig = document.getElementById('obfuscate-sig');
    const sigLocation = document.getElementById('sig-location');
    const embedOriginalCb = document.getElementById('embed-original');
    const embedOtherFile = document.getElementById('embed-other-file');

    const revDrop = document.getElementById('revert-drop');
    const revFile = document.getElementById('revert-file');
    const revPwd = document.getElementById('revert-pwd');
    const btnRevert = document.getElementById('btn-revert');
    
    const revertResult = document.getElementById('revert-result');
    const revertPreview = document.getElementById('revert-preview');
    const btnDownloadMath = document.getElementById('btn-download-math');

    const revertHiddenContainer = document.getElementById('revert-hidden-container');
    const revertHiddenPreview = document.getElementById('revert-hidden-preview');
    const btnDownloadHidden = document.getElementById('btn-download-hidden');

    const revertSigContainer = document.getElementById('revert-sig-container');
    const revertSigText = document.getElementById('revert-sig-text');

    let originalImageFile = null;
    let uploadedImage = new Image();
    let otherImageFile = null;

    let currentMathObjectUrl = null;
    let currentHiddenObjectUrl = null;

    let targetObfuscatedFile = null;
    let targetObfuscatedImage = new Image();

    // Tabs
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            views.forEach(v => v.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(tab.dataset.target).classList.add('active');
        });
    });

    // File Drag & Drop
    function setupDropZone(dropZone, fileInput, onChange) {
        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
        dropZone.addEventListener('dragleave', e => { e.preventDefault(); dropZone.classList.remove('dragover'); });
        dropZone.addEventListener('drop', e => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if(e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                onChange(e.dataTransfer.files[0]);
            }
        });
        fileInput.addEventListener('change', e => {
            if(e.target.files.length) onChange(e.target.files[0]);
        });
    }

    setupDropZone(obfDrop, obfFile, file => {
        obfDrop.querySelector('.drop-text').classList.add('hidden');
        obfPreview.classList.remove('hidden');
        originalImageFile = file;
        uploadedImage.src = URL.createObjectURL(file);
        obfPreview.src = uploadedImage.src;
    });

    embedOtherFile.addEventListener('change', e => {
        if(e.target.files.length) {
            otherImageFile = e.target.files[0];
            embedOriginalCb.checked = false; 
        }
    });

    setupDropZone(revDrop, revFile, file => {
        const revText = revDrop.querySelector('.drop-text');
        revText.innerText = "Fichier sélectionné : " + file.name;
        targetObfuscatedFile = file;
        targetObfuscatedImage.src = URL.createObjectURL(file);
    });

    // --- CRYPTO HELPERS ---
    async function deriveKey(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']
        );
        return await crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
            keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );
    }

    async function encryptData(dataBuffer, password) {
        if (!password) return { encrypted: dataBuffer, salt: null, iv: null };
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(password, salt);
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, dataBuffer);
        return { encrypted, salt: Array.from(salt), iv: Array.from(iv) };
    }

    async function decryptData(encryptedBuffer, password, saltArr, ivArr) {
        if (!password || !saltArr) return encryptedBuffer; 
        const salt = new Uint8Array(saltArr);
        const iv = new Uint8Array(ivArr);
        const key = await deriveKey(password, salt);
        return await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedBuffer);
    }

    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }

    function base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    async function compressData(buffer) {
        if (typeof CompressionStream === 'undefined') return buffer;
        const stream = new Blob([buffer]).stream().pipeThrough(new CompressionStream('deflate-raw'));
        return await new Response(stream).arrayBuffer();
    }

    async function decompressData(buffer) {
        if (typeof DecompressionStream === 'undefined') return buffer;
        try {
            const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
            return await new Response(stream).arrayBuffer();
        } catch(e) { return buffer; }
    }

    // --- LSB Steganography ---
    function encodeLSB(imgData, payloadBytes) {
        const bits = [];
        const len = payloadBytes.length;
        for(let i=0; i<32; i++) bits.push((len >> i) & 1);
        for(let i=0; i<len; i++) {
            const b = payloadBytes[i];
            for(let j=0; j<8; j++) bits.push((b >> j) & 1);
        }
        const maxBits = (imgData.data.length / 4) * 3;
        if (bits.length > maxBits) throw new Error("Signature trop longue pour la stéganographie LSB.");

        let bitIndex = 0;
        for(let i=0; i<imgData.data.length && bitIndex < bits.length; i++) {
            if ((i + 1) % 4 === 0) continue; 
            imgData.data[i] = (imgData.data[i] & ~1) | bits[bitIndex];
            bitIndex++;
        }
    }

    function decodeLSB(imgData) {
        let len = 0;
        let dataIndex = 0;
        for(let i=0; i<32; i++) {
            while((dataIndex + 1) % 4 === 0) dataIndex++;
            if (dataIndex >= imgData.data.length) return null;
            const bit = imgData.data[dataIndex] & 1;
            len |= (bit << i);
            dataIndex++;
        }
        if (len <= 0 || len > 5000000) return null;
        const payload = new Uint8Array(len);
        for(let i=0; i<len; i++) {
            let b = 0;
            for(let j=0; j<8; j++) {
                while((dataIndex + 1) % 4 === 0) dataIndex++;
                if (dataIndex >= imgData.data.length) return null;
                const bit = imgData.data[dataIndex] & 1;
                b |= (bit << j);
                dataIndex++;
            }
            payload[i] = b;
        }
        return payload;
    }

    // --- MATH PRNG & UTILS ---
    function xmur3(str) {
        let h = 1779033703 ^ str.length;
        for(let i = 0; i < str.length; i++) {
            h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
            h = h << 13 | h >>> 19;
        }
        return function() {
            h = Math.imul(h ^ (h >>> 16), 2246822507);
            h = Math.imul(h ^ (h >>> 13), 3266489909);
            return (h ^= h >>> 16) >>> 0;
        }
    }
    function mulberry32(a) {
        return function() {
            var t = a += 0x6D2B79F5;
            t = Math.imul(t ^ t >>> 15, t | 1);
            t ^= t + Math.imul(t ^ t >>> 7, t | 61);
            return ((t ^ t >>> 14) >>> 0) / 4294967296;
        }
    }
    function getPRNG(seedStr) { return mulberry32(xmur3(seedStr)()); }
    
    function shuffleArray(array, prng) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(prng() * (i + 1));
            const temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }
    const mod = (n, m) => ((n % m) + m) % m;

    // --- 100% REVERSIBLE MATH ALGORITHMS ---
    function applyXorShuffle(imgData, width, height, prng, reverse = false) {
        const totalPixels = width * height;
        const xorStream = new Uint8Array(totalPixels * 3);
        for(let i=0; i<xorStream.length; i++) xorStream[i] = Math.floor(prng() * 256);
        const indices = new Int32Array(totalPixels);
        for(let i=0; i<totalPixels; i++) indices[i] = i;
        shuffleArray(indices, prng);
        
        const srcData = new Uint8Array(imgData.data);
        const dstData = new Uint8Array(imgData.data.length);
        
        if (!reverse) {
            for(let i=0; i<totalPixels; i++) {
                const j = indices[i];
                dstData[j*4] = srcData[i*4] ^ xorStream[i*3];
                dstData[j*4+1] = srcData[i*4+1] ^ xorStream[i*3+1];
                dstData[j*4+2] = srcData[i*4+2] ^ xorStream[i*3+2];
                dstData[j*4+3] = srcData[i*4+3];
            }
        } else {
            for(let i=0; i<totalPixels; i++) {
                const j = indices[i];
                dstData[i*4] = srcData[j*4] ^ xorStream[i*3];
                dstData[i*4+1] = srcData[j*4+1] ^ xorStream[i*3+1];
                dstData[i*4+2] = srcData[j*4+2] ^ xorStream[i*3+2];
                dstData[i*4+3] = srcData[j*4+3];
            }
        }
        imgData.data.set(dstData);
    }

    function applyLogisticXOR(imgData, width, height, prng, reverse = false) {
        const totalPixels = width * height;
        const xorStream = new Uint8Array(totalPixels * 3);
        let x = prng() * 0.5 + 0.2;
        const r = 3.99 + prng() * 0.009;
        for(let i=0; i<xorStream.length; i++) {
            x = r * x * (1 - x);
            xorStream[i] = Math.floor(x * 256);
        }
        const srcData = new Uint8Array(imgData.data);
        const dstData = new Uint8Array(imgData.data.length);
        for(let i=0; i<imgData.data.length; i++) {
            if ((i + 1) % 4 === 0) dstData[i] = srcData[i];
            else {
                const pIdx = Math.floor(i / 4);
                const cIdx = i % 4;
                dstData[i] = srcData[i] ^ xorStream[pIdx * 3 + cIdx];
            }
        }
        imgData.data.set(dstData);
    }

    function applyCatMap(imgData, width, height, prng, reverse = false) {
        const iterations = 5 + Math.floor(prng() * 15);
        const srcData = new Uint32Array(imgData.data.buffer);
        const dstData = new Uint32Array(width * height);
        const mapping = new Int32Array(width * height);
        for(let i=0; i<width*height; i++) mapping[i] = i;

        for(let iter=0; iter<iterations; iter++) {
            const nextMap = new Int32Array(width * height);
            for(let y=0; y<height; y++) {
                for(let x=0; x<width; x++) {
                    if (!reverse) {
                        const nx = (x + y) % width;
                        const ny = (nx + y) % height;
                        nextMap[ny * width + nx] = mapping[y * width + x];
                    } else {
                        const py = mod(y - x, height);
                        const px = mod(x - py, width);
                        nextMap[py * width + px] = mapping[y * width + x];
                    }
                }
            }
            mapping.set(nextMap);
        }
        for(let i=0; i<width*height; i++) dstData[i] = srcData[mapping[i]];
        imgData.data.set(new Uint8Array(dstData.buffer));
    }

    function applyBakerMap(imgData, width, height, prng, reverse = false) {
        const total = width * height;
        const srcData = new Uint32Array(imgData.data.buffer);
        const dstData = new Uint32Array(total);
        const iterations = 10 + Math.floor(prng() * 10);
        const mapping = new Int32Array(total);
        for(let i=0; i<total; i++) mapping[i] = i;

        for(let iter=0; iter<iterations; iter++) {
            const nextMap = new Int32Array(total);
            if (!reverse) {
                let left = 0, right = Math.floor((total + 1) / 2);
                for(let i=0; i<total; i++) {
                    if (i % 2 === 0) nextMap[left++] = mapping[i];
                    else nextMap[right++] = mapping[i];
                }
            } else {
                const half = Math.floor((total + 1) / 2);
                for(let i=0; i<total; i++) {
                    if (i < half) nextMap[i * 2] = mapping[i];
                    else nextMap[(i - half) * 2 + 1] = mapping[i];
                }
            }
            mapping.set(nextMap);
        }
        for(let i=0; i<total; i++) dstData[i] = srcData[mapping[i]];
        imgData.data.set(new Uint8Array(dstData.buffer));
    }

    function applyAffineMap(imgData, width, height, prng, reverse = false) {
        const b = Math.floor(prng() * 20) + 1;
        const c = Math.floor(prng() * 20) + 1;
        const srcData = new Uint32Array(imgData.data.buffer);
        const dstData = new Uint32Array(width * height);
        for(let y=0; y<height; y++) {
            for(let x=0; x<width; x++) {
                if (!reverse) {
                    const nx = mod(x + b * y, width);
                    const ny = mod(c * nx + y, height);
                    dstData[ny * width + nx] = srcData[y * width + x];
                } else {
                    const py = mod(y - c * x, height);
                    const px = mod(x - b * py, width);
                    dstData[py * width + px] = srcData[y * width + x];
                }
            }
        }
        imgData.data.set(new Uint8Array(dstData.buffer));
    }

    function applyWaveShift(imgData, width, height, prng, reverse = false) {
        const freqX = 10 + prng() * 50; const ampX = 10 + prng() * 100;
        const freqY = 10 + prng() * 50; const ampY = 10 + prng() * 100;
        const src = new Uint32Array(imgData.data.buffer);
        const dst = new Uint32Array(width * height);
        
        if (!reverse) {
            const temp = new Uint32Array(width * height);
            for(let y=0; y<height; y++) {
                const shift = Math.floor(Math.sin(y / freqY) * ampX);
                for(let x=0; x<width; x++) {
                    const nx = mod(x + shift, width);
                    temp[y * width + nx] = src[y * width + x];
                }
            }
            for(let x=0; x<width; x++) {
                const shift = Math.floor(Math.cos(x / freqX) * ampY);
                for(let y=0; y<height; y++) {
                    const ny = mod(y + shift, height);
                    dst[ny * width + x] = temp[y * width + x];
                }
            }
        } else {
            const temp = new Uint32Array(width * height);
            for(let x=0; x<width; x++) {
                const shift = Math.floor(Math.cos(x / freqX) * ampY);
                for(let y=0; y<height; y++) {
                    const ny = mod(y - shift, height);
                    temp[ny * width + x] = src[y * width + x];
                }
            }
            for(let y=0; y<height; y++) {
                const shift = Math.floor(Math.sin(y / freqY) * ampX);
                for(let x=0; x<width; x++) {
                    const nx = mod(x - shift, width);
                    dst[y * width + nx] = temp[y * width + x];
                }
            }
        }
        imgData.data.set(new Uint8Array(dst.buffer));
    }

    function gcd(a, b) {
        while (b !== 0n) { let t = b; b = a % b; a = t; }
        return a;
    }
    function modInverse(a, m) {
        let m0 = m, y = 0n, x = 1n;
        if (m === 1n) return 0n;
        while (a > 1n) {
            let q = a / m, t = m;
            m = a % m; a = t; t = y;
            y = x - q * y; x = t;
        }
        if (x < 0n) x += m0;
        return x;
    }
    function applyPrimeScatter(imgData, width, height, prng, reverse = false) {
        const N = BigInt(width * height);
        if(N === 0n) return;
        let P = BigInt(Math.floor(prng() * 1000000) + 1000000);
        while (gcd(P, N) !== 1n) { P += 1n; }
        const invP = modInverse(P, N);
        const srcData = new Uint32Array(imgData.data.buffer);
        const dstData = new Uint32Array(width * height);
        const factor = reverse ? invP : P;
        for(let i=0n; i<N; i++) {
            const target = Number((i * factor) % N);
            dstData[target] = srcData[Number(i)];
        }
        imgData.data.set(new Uint8Array(dstData.buffer));
    }

    function applyRgbShift(imgData, width, height, prng, reverse = false) {
        const dr_x = Math.floor(prng() * width); const dr_y = Math.floor(prng() * height);
        const dg_x = Math.floor(prng() * width); const dg_y = Math.floor(prng() * height);
        const db_x = Math.floor(prng() * width); const db_y = Math.floor(prng() * height);
        const src = new Uint8Array(imgData.data);
        const dst = new Uint8Array(imgData.data.length);
        
        for(let y=0; y<height; y++) {
            for(let x=0; x<width; x++) {
                const i = (y * width + x) * 4;
                const rx = mod(reverse ? x - dr_x : x + dr_x, width);
                const ry = mod(reverse ? y - dr_y : y + dr_y, height);
                const gx = mod(reverse ? x - dg_x : x + dg_x, width);
                const gy = mod(reverse ? y - dg_y : y + dg_y, height);
                const bx = mod(reverse ? x - db_x : x + db_x, width);
                const by = mod(reverse ? y - db_y : y + db_y, height);
                
                if (!reverse) {
                    dst[(ry * width + rx) * 4] = src[i];
                    dst[(gy * width + gx) * 4 + 1] = src[i+1];
                    dst[(by * width + bx) * 4 + 2] = src[i+2];
                } else {
                    dst[i] = src[(ry * width + rx) * 4];
                    dst[i+1] = src[(gy * width + gx) * 4 + 1];
                    dst[i+2] = src[(by * width + bx) * 4 + 2];
                }
                dst[i+3] = src[i+3];
            }
        }
        imgData.data.set(dst);
    }

    // --- DESTRUCTIVES ---
    function applyQuantizeShuffle(imgData, width, height, prng, reverse = false) {
        if (!reverse) {
            const data = imgData.data;
            for (let y = 0; y < height; y += 4) {
                for (let x = 0; x < width; x += 4) {
                    const i = (y * width + x) * 4;
                    const r = Math.round(data[i] / 48) * 48;
                    const g = Math.round(data[i+1] / 48) * 48;
                    const b = Math.round(data[i+2] / 48) * 48;
                    for (let dy = 0; dy < 4 && y + dy < height; dy++) {
                        for (let dx = 0; dx < 4 && x + dx < width; dx++) {
                            const idx = ((y + dy) * width + (x + dx)) * 4;
                            data[idx] = r; data[idx+1] = g; data[idx+2] = b;
                        }
                    }
                }
            }
        }
        applyXorShuffle(imgData, width, height, prng, reverse);
    }
    
    function applyColorCrush(imgData, width, height, prng, reverse = false) {
        if (!reverse) {
            const data = imgData.data;
            for(let i=0; i<data.length; i+=4) {
                data[i] = Math.round(data[i] / 64) * 64;
                data[i+1] = Math.round(data[i+1] / 64) * 64;
                data[i+2] = Math.round(data[i+2] / 64) * 64;
            }
        }
        applyCatMap(imgData, width, height, prng, reverse);
    }
    
    function applyBlurNoise(imgData, width, height, prng, reverse = false) {
        if (!reverse) {
            const data = imgData.data;
            const tmp = new Uint8Array(data);
            for(let y=1; y<height-1; y++) {
                for(let x=1; x<width-1; x++) {
                    const i = (y * width + x) * 4;
                    for(let c=0; c<3; c++) {
                        data[i+c] = (tmp[i-4+c] + tmp[i+4+c] + tmp[i-width*4+c] + tmp[i+width*4+c]) >> 2;
                    }
                }
            }
            for(let i=0; i<data.length; i+=4) {
                data[i] = Math.min(255, Math.max(0, data[i] + (prng()-0.5)*150));
                data[i+1] = Math.min(255, Math.max(0, data[i+1] + (prng()-0.5)*150));
                data[i+2] = Math.min(255, Math.max(0, data[i+2] + (prng()-0.5)*150));
            }
        }
        applyWaveShift(imgData, width, height, prng, reverse);
    }

    function applySaltPepper(imgData, width, height, prng, reverse = false) {
        if (!reverse) {
            const data = new Uint32Array(imgData.data.buffer);
            for(let i=0; i<data.length; i++) {
                const rand = prng();
                if (rand < 0.1) data[i] = 0xFF000000;
                else if (rand < 0.2) data[i] = 0xFFFFFFFF;
            }
        }
        applyAffineMap(imgData, width, height, prng, reverse);
    }

    // --- COMPRESSION-RESISTANT ALGORITHMS (Block-Level Permutation) ---
    // Key insight: JPEG processes 8×8 blocks. By permuting ENTIRE blocks,
    // compression only affects WITHIN each block, not block positions.
    // → Reversible even after JPEG compression or WhatsApp sending.
    function applyBlockShuffle(imgData, w, h, prng, reverse, blockSize) {
        const bw = Math.floor(w / blockSize);
        const bh = Math.floor(h / blockSize);
        const numBlocks = bw * bh;
        if (numBlocks < 2) return;
        // Fisher-Yates permutation seeded by PRNG
        const perm = Array.from({length: numBlocks}, (_, i) => i);
        // Need deterministic permutation, consume prng in same order
        const rands = [];
        for (let i = numBlocks - 1; i > 0; i--) rands.push(Math.floor(prng() * (i + 1)));
        for (let k = 0; k < rands.length; k++) {
            const i = numBlocks - 1 - k;
            [perm[i], perm[rands[k]]] = [perm[rands[k]], perm[i]];
        }
        const src = new Uint8Array(imgData.data);
        const dst = new Uint8Array(src.length);
        dst.set(src); // copy edge pixels that don't fit in blocks
        for (let bi = 0; bi < numBlocks; bi++) {
            const srcIdx = reverse ? perm[bi] : bi;
            const dstIdx = reverse ? bi : perm[bi];
            const srcX = (srcIdx % bw) * blockSize;
            const srcY = Math.floor(srcIdx / bw) * blockSize;
            const dstX = (dstIdx % bw) * blockSize;
            const dstY = Math.floor(dstIdx / bw) * blockSize;
            for (let dy = 0; dy < blockSize; dy++) {
                const srcRow = ((srcY + dy) * w + srcX) * 4;
                const dstRow = ((dstY + dy) * w + dstX) * 4;
                for (let dx = 0; dx < blockSize; dx++) {
                    const si = srcRow + dx * 4;
                    const di = dstRow + dx * 4;
                    dst[di] = src[si]; dst[di+1] = src[si+1];
                    dst[di+2] = src[si+2]; dst[di+3] = src[si+3];
                }
            }
        }
        imgData.data.set(dst);
    }
    function applyBlockShuffle8(imgData, w, h, prng, reverse) {
        applyBlockShuffle(imgData, w, h, prng, reverse, 8);
    }
    function applyBlockShuffle16(imgData, w, h, prng, reverse) {
        applyBlockShuffle(imgData, w, h, prng, reverse, 16);
    }

    // --- DFWS (DualsFWShield) — Compression/Crop/Screenshot-Resistant ---
    // Each 8×8 block gets: channel rotation + flip + inversion + position shuffle.
    // All ops survive JPEG. Each surviving block is independently reversible.
    function applyDFWS(imgData, w, h, prng, reverse) {
        const BS = 8;
        const bw = Math.floor(w / BS), bh = Math.floor(h / BS);
        const numBlocks = bw * bh;
        if (numBlocks < 2) return;

        // Generate per-block transforms (deterministic from PRNG)
        const transforms = new Array(numBlocks);
        for (let i = 0; i < numBlocks; i++) {
            transforms[i] = {
                chanRot: Math.floor(prng() * 3),   // 0=none, 1=RGB→GBR, 2=RGB→BRG
                hFlip:   prng() > 0.5,
                vFlip:   prng() > 0.5,
                invert:  prng() > 0.5
            };
        }
        // Generate block permutation (Fisher-Yates)
        const perm = Array.from({length: numBlocks}, (_, i) => i);
        for (let i = numBlocks - 1; i > 0; i--) {
            const j = Math.floor(prng() * (i + 1));
            [perm[i], perm[j]] = [perm[j], perm[i]];
        }

        const src = new Uint8Array(imgData.data);
        const dst = new Uint8Array(src.length);
        dst.set(src); // preserve edge pixels outside block grid

        function transformBlock(srcBuf, dstBuf, sx, sy, dx, dy, tf, rev) {
            for (let by = 0; by < BS; by++) {
                for (let bx = 0; bx < BS; bx++) {
                    // Flip coordinates
                    let rx = rev ? (tf.hFlip ? BS-1-bx : bx) : bx;
                    let ry = rev ? (tf.vFlip ? BS-1-by : by) : by;
                    let ox = !rev ? (tf.hFlip ? BS-1-bx : bx) : bx;
                    let oy = !rev ? (tf.vFlip ? BS-1-by : by) : by;
                    const si = ((sy + ry) * w + (sx + rx)) * 4;
                    const di = ((dy + oy) * w + (dx + ox)) * 4;
                    let r = srcBuf[si], g = srcBuf[si+1], b = srcBuf[si+2];
                    // Channel rotation
                    if (!rev) {
                        if (tf.chanRot === 1) { const t=r; r=g; g=b; b=t; }
                        else if (tf.chanRot === 2) { const t=r; r=b; b=g; g=t; }
                        if (tf.invert) { r=255-r; g=255-g; b=255-b; }
                    } else {
                        if (tf.invert) { r=255-r; g=255-g; b=255-b; }
                        if (tf.chanRot === 1) { const t=b; b=g; g=r; r=t; }
                        else if (tf.chanRot === 2) { const t=g; g=b; b=r; r=t; }
                    }
                    dstBuf[di] = r; dstBuf[di+1] = g; dstBuf[di+2] = b; dstBuf[di+3] = srcBuf[si+3];
                }
            }
        }

        if (!reverse) {
            // Forward: transform each block, then shuffle
            for (let i = 0; i < numBlocks; i++) {
                const srcX = (i % bw) * BS, srcY = Math.floor(i / bw) * BS;
                const dstIdx = perm[i];
                const dstX = (dstIdx % bw) * BS, dstY = Math.floor(dstIdx / bw) * BS;
                transformBlock(src, dst, srcX, srcY, dstX, dstY, transforms[i], false);
            }
        } else {
            // Reverse: un-shuffle, then un-transform
            for (let i = 0; i < numBlocks; i++) {
                const shuffledIdx = perm[i]; // block i went to position perm[i]
                const srcX = (shuffledIdx % bw) * BS, srcY = Math.floor(shuffledIdx / bw) * BS;
                const dstX = (i % bw) * BS, dstY = Math.floor(i / bw) * BS;
                transformBlock(src, dst, srcX, srcY, dstX, dstY, transforms[i], true);
            }
        }
        imgData.data.set(dst);
    }

    // --- 6 NEW ALGORITHMS (main thread fallback) ---
    function hilbertD2XY(n, d) {
        let x = 0, y = 0, s, t = d;
        for (s = 1; s < n; s *= 2) {
            const rx = 1 & (t / 2), ry = 1 & (t ^ rx);
            if (ry === 0) { if (rx === 1) { x = s-1-x; y = s-1-y; } const tmp = x; x = y; y = tmp; }
            x += s * rx; y += s * ry; t = Math.floor(t / 4);
        }
        return [x, y];
    }
    function applyHilbert(imgData, w, h, prng, rev) {
        const total = w * h; let n = 1; while (n*n < total) n *= 2;
        const src32 = new Uint32Array(imgData.data.buffer.slice(0)), dst32 = new Uint32Array(total);
        const offset = Math.floor(prng() * 1000000), mapping = new Int32Array(total);
        let idx = 0;
        for (let d = 0; d < n*n && idx < total; d++) {
            const [hx, hy] = hilbertD2XY(n, (d + offset) % (n * n));
            if (hx < w && hy < h) { mapping[idx] = hy * w + hx; idx++; }
        }
        while (idx < total) { mapping[idx] = idx; idx++; }
        if (!rev) { for (let i = 0; i < total; i++) dst32[mapping[i]] = src32[i]; }
        else { for (let i = 0; i < total; i++) dst32[i] = src32[mapping[i]]; }
        new Uint8Array(imgData.data.buffer).set(new Uint8Array(dst32.buffer));
    }
    function applySpiral(imgData, w, h, prng, rev) {
        const total = w * h;
        const src32 = new Uint32Array(imgData.data.buffer.slice(0)), dst32 = new Uint32Array(total);
        const spiral = []; let top = 0, bottom = h-1, left = 0, right = w-1;
        while (top <= bottom && left <= right) {
            for (let x = left; x <= right; x++) spiral.push(top*w+x); top++;
            for (let y = top; y <= bottom; y++) spiral.push(y*w+right); right--;
            if (top <= bottom) { for (let x = right; x >= left; x--) spiral.push(bottom*w+x); bottom--; }
            if (left <= right) { for (let y = bottom; y >= top; y--) spiral.push(y*w+left); left++; }
        }
        if (!rev) { for (let i = 0; i < total; i++) dst32[spiral[i]] = src32[i]; }
        else { for (let i = 0; i < total; i++) dst32[i] = src32[spiral[i]]; }
        new Uint8Array(imgData.data.buffer).set(new Uint8Array(dst32.buffer));
    }
    function applyZigzag(imgData, w, h, prng, rev) {
        const total = w * h;
        const src32 = new Uint32Array(imgData.data.buffer.slice(0)), dst32 = new Uint32Array(total);
        const order = [];
        for (let sum = 0; sum < w+h-1; sum++) {
            if (sum % 2 === 0) { for (let y = Math.min(sum, h-1); y >= Math.max(0, sum-w+1); y--) order.push(y*w+(sum-y)); }
            else { for (let y = Math.max(0, sum-w+1); y <= Math.min(sum, h-1); y++) order.push(y*w+(sum-y)); }
        }
        if (!rev) { for (let i = 0; i < total; i++) dst32[order[i]] = src32[i]; }
        else { for (let i = 0; i < total; i++) dst32[i] = src32[order[i]]; }
        new Uint8Array(imgData.data.buffer).set(new Uint8Array(dst32.buffer));
    }
    function applyChirikov(imgData, w, h, prng, rev) {
        const K = 2 + prng() * 8, iter = 3 + Math.floor(prng() * 7);
        const src32 = new Uint32Array(imgData.data.buffer.slice(0)), dst32 = new Uint32Array(w*h);
        const mapping = new Int32Array(w*h); for (let i = 0; i < w*h; i++) mapping[i] = i;
        const TWO_PI = 2 * Math.PI;
        for (let it = 0; it < iter; it++) {
            const next = new Int32Array(w*h);
            for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
                if (!rev) { const pn = mod(y + Math.floor(K*w*Math.sin(TWO_PI*x/w)/TWO_PI), h); const qn = mod(x+pn, w); next[pn*w+qn] = mapping[y*w+x]; }
                else { const qp = mod(x-y, w); const pp = mod(y - Math.floor(K*w*Math.sin(TWO_PI*qp/w)/TWO_PI), h); next[pp*w+qp] = mapping[y*w+x]; }
            }
            mapping.set(next);
        }
        for (let i = 0; i < w*h; i++) dst32[i] = src32[mapping[i]];
        new Uint8Array(imgData.data.buffer).set(new Uint8Array(dst32.buffer));
    }
    function applyHenon(imgData, w, h, prng, rev) {
        const a = 1.2 + prng()*0.2, b = 0.2 + prng()*0.1, total = w*h;
        const src32 = new Uint32Array(imgData.data.buffer.slice(0)), dst32 = new Uint32Array(total);
        const seq = new Float64Array(total);
        let xh = prng()*0.5, yh = prng()*0.5;
        for (let i = 0; i < total; i++) { const nx = 1 - a*xh*xh + yh; yh = b*xh; xh = nx; seq[i] = xh; }
        const idx = new Int32Array(total); for (let i = 0; i < total; i++) idx[i] = i;
        idx.sort((a, b) => seq[a] - seq[b]);
        if (!rev) { for (let i = 0; i < total; i++) dst32[idx[i]] = src32[i]; }
        else { for (let i = 0; i < total; i++) dst32[i] = src32[idx[i]]; }
        new Uint8Array(imgData.data.buffer).set(new Uint8Array(dst32.buffer));
    }
    function applyRubik(imgData, w, h, prng, rev) {
        const numMoves = 20 + Math.floor(prng()*40), moves = [];
        for (let i = 0; i < numMoves; i++) moves.push({ ch: Math.floor(prng()*3), isRow: prng()<0.5, idx: Math.floor(prng()*Math.max(w,h)), shift: Math.floor(prng()*Math.max(w,h)) });
        if (rev) moves.reverse();
        const d = imgData.data;
        for (const m of moves) {
            if (m.isRow) {
                const y = m.idx % h, row = new Uint8Array(w);
                for (let x = 0; x < w; x++) row[x] = d[(y*w+x)*4+m.ch];
                for (let x = 0; x < w; x++) d[(y*w+x)*4+m.ch] = row[rev ? mod(x+m.shift,w) : mod(x-m.shift,w)];
            } else {
                const x = m.idx % w, col = new Uint8Array(h);
                for (let y = 0; y < h; y++) col[y] = d[(y*w+x)*4+m.ch];
                for (let y = 0; y < h; y++) d[(y*w+x)*4+m.ch] = col[rev ? mod(y+m.shift,h) : mod(y-m.shift,h)];
            }
        }
    }

    // --- DCT ROBUST WATERMARK (SynthID-style) ---
    const RobustWatermark = {
        // 1D DCT-II
        dct8(block) {
            const N = 8, out = new Float64Array(N);
            for (let k = 0; k < N; k++) {
                let sum = 0;
                for (let n = 0; n < N; n++) sum += block[n] * Math.cos(Math.PI * (2*n+1) * k / (2*N));
                out[k] = sum * (k === 0 ? Math.sqrt(1/N) : Math.sqrt(2/N));
            }
            return out;
        },
        // 1D IDCT-II
        idct8(coef) {
            const N = 8, out = new Float64Array(N);
            for (let n = 0; n < N; n++) {
                let sum = 0;
                for (let k = 0; k < N; k++) sum += coef[k] * Math.cos(Math.PI * (2*n+1) * k / (2*N)) * (k === 0 ? Math.sqrt(1/N) : Math.sqrt(2/N));
                out[n] = sum;
            }
            return out;
        },
        // 2D DCT on 8x8 block
        dct2d(block) {
            const tmp = new Float64Array(64);
            for (let r = 0; r < 8; r++) { const row = this.dct8(block.subarray(r*8, r*8+8)); for (let c = 0; c < 8; c++) tmp[r*8+c] = row[c]; }
            for (let c = 0; c < 8; c++) { const col = new Float64Array(8); for (let r = 0; r < 8; r++) col[r] = tmp[r*8+c]; const res = this.dct8(col); for (let r = 0; r < 8; r++) tmp[r*8+c] = res[r]; }
            return tmp;
        },
        // 2D IDCT on 8x8 block
        idct2d(coef) {
            const tmp = new Float64Array(64);
            for (let c = 0; c < 8; c++) { const col = new Float64Array(8); for (let r = 0; r < 8; r++) col[r] = coef[r*8+c]; const res = this.idct8(col); for (let r = 0; r < 8; r++) tmp[r*8+c] = res[r]; }
            for (let r = 0; r < 8; r++) { const row = this.idct8(tmp.subarray(r*8, r*8+8)); for (let c = 0; c < 8; c++) tmp[r*8+c] = row[c]; }
            return tmp;
        },
        // Mid-frequency positions for embedding (survive JPEG quantization)
        MID_FREQ: [[1,2],[2,1],[3,2],[2,3],[1,4],[4,1],[3,3],[4,4],[2,2],[5,5]],
        QUANT_STEP: 35, // Base step, will be adaptive

        rgbToY(r, g, b) { return 0.299*r + 0.587*g + 0.114*b; },
        yToRgb(y, r, g, b) {
            const oldY = this.rgbToY(r, g, b);
            const dy = y - oldY;
            return [Math.max(0,Math.min(255, r + dy)), Math.max(0,Math.min(255, g + dy)), Math.max(0,Math.min(255, b + dy))];
        },

        embed(imgData, text) {
            const w = imgData.width, h = imgData.height, d = imgData.data;
            const bytes = new TextEncoder().encode(text.substring(0, 16));
            const bits = [];
            for (let i = 0; i < 8; i++) bits.push((bytes.length >> i) & 1);
            for (const b of bytes) for (let j = 0; j < 8; j++) bits.push((b >> j) & 1);
            if (bits.length === 0) return;

            const numBits = bits.length;
            const freqPerBlock = this.MID_FREQ.length;

            for (let by = 0; by + 8 <= h; by += 8) {
                for (let bx = 0; bx + 8 <= w; bx += 8) {
                    const block = new Float64Array(64);
                    let avgY = 0;
                    for (let r = 0; r < 8; r++) {
                        for (let c = 0; c < 8; c++) {
                            const i = ((by+r)*w+(bx+c))*4;
                            block[r*8+c] = this.rgbToY(d[i], d[i+1], d[i+2]);
                            avgY += block[r*8+c];
                        }
                    }
                    avgY /= 64;

                    // Adaptive Q: weaker in dark areas to prevent grain
                    const Q = this.QUANT_STEP * (0.4 + (avgY / 255) * 0.8);
                    const dct = this.dct2d(block);
                    
                    // Packet Mode: every 4x4 block cluster (32x32px) repeats the whole payload
                    const blockIdxInMacro = (Math.floor((by%32)/8) * 4 + Math.floor((bx%32)/8));
                    
                    for (let bi = 0; bi < freqPerBlock; bi++) {
                        const bitIdx = (blockIdxInMacro * freqPerBlock + bi) % numBits;
                        const [r, c] = this.MID_FREQ[bi];
                        const bit = bits[bitIdx];
                        const coef = dct[r*8+c];
                        const quantized = Math.round(coef / Q) * Q;
                        dct[r*8+c] = quantized + (bit ? Q/4 : -Q/4);
                    }

                    const spatial = this.idct2d(dct);
                    for (let r = 0; r < 8; r++) {
                        for (let c = 0; c < 8; c++) {
                            const i = ((by+r)*w+(bx+c))*4;
                            const [nr, ng, nb] = this.yToRgb(spatial[r*8+c], d[i], d[i+1], d[i+2]);
                            d[i] = nr; d[i+1] = ng; d[i+2] = nb;
                        }
                    }
                }
            }
        },

        extract(imgData) {
            const w = imgData.width, h = imgData.height, d = imgData.data;
            const maxBits = 8 + 16 * 8;
            const votes = new Array(maxBits).fill(null).map(() => [0, 0]);
            const freqPerBlock = this.MID_FREQ.length;

            // Sample with high coverage
            for (let by = 0; by + 8 <= h; by += 8) {
                for (let bx = 0; bx + 8 <= w; bx += 8) {
                    const block = new Float64Array(64);
                    let avgY = 0;
                    for (let r = 0; r < 8; r++) {
                        for (let c = 0; c < 8; c++) {
                            const i = ((by+r)*w+(bx+c))*4;
                            block[r*8+c] = this.rgbToY(d[i], d[i+1], d[i+2]);
                            avgY += block[r*8+c];
                        }
                    }
                    avgY /= 64;
                    const Q = this.QUANT_STEP * (0.4 + (avgY / 255) * 0.8);
                    const dct = this.dct2d(block);
                    
                    const blockIdxInMacro = (Math.floor((by%32)/8) * 4 + Math.floor((bx%32)/8));
                    
                    for (let bi = 0; bi < freqPerBlock; bi++) {
                        const bitIdx = (blockIdxInMacro * freqPerBlock + bi) % maxBits;
                        const [r, c] = this.MID_FREQ[bi];
                        const coef = dct[r*8+c];
                        const quantized = Math.round(coef / Q) * Q;
                        const bit = (coef - quantized) > 0 ? 1 : 0;
                        votes[bitIdx][bit]++;
                    }
                }
            }

            const finalBits = votes.map(v => v[1] > v[0] ? 1 : 0);
            let len = 0;
            for (let i = 0; i < 8; i++) len |= finalBits[i] << i;
            if (len <= 0 || len > 16) return null;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                let b = 0;
                for (let j = 0; j < 8; j++) {
                    const idx = 8 + i*8 + j;
                    if (idx < finalBits.length) b |= finalBits[idx] << j;
                }
                bytes[i] = b;
            }
            try {
                const t = new TextDecoder().decode(bytes);
                if (/^[\x20-\x7E]+$/.test(t)) return t;
            } catch(e) {}
            return null;
        },
        getDimensions(imgData) {
            const wm = this.extract(imgData);
            if (wm && wm.startsWith('DIM:')) {
                const parts = wm.split(':');
                return { w: parseInt(parts[1]), h: parseInt(parts[2]), text: parts[3] };
            }
            return null;
        }
    };

    // --- ALGO ROUTING ---
    function applyAlgorithm(imgData, width, height, algo, seed, reverse = false) {
        const prng = getPRNG(seed);
        if (algo === 'xor-shuffle') applyXorShuffle(imgData, width, height, prng, reverse);
        else if (algo === 'logistic-xor') applyLogisticXOR(imgData, width, height, prng, reverse);
        else if (algo === 'cat-map') applyCatMap(imgData, width, height, prng, reverse);
        else if (algo === 'baker-map') applyBakerMap(imgData, width, height, prng, reverse);
        else if (algo === 'affine-map') applyAffineMap(imgData, width, height, prng, reverse);
        else if (algo === 'wave-shift') applyWaveShift(imgData, width, height, prng, reverse);
        else if (algo === 'prime-scatter') applyPrimeScatter(imgData, width, height, prng, reverse);
        else if (algo === 'rgb-shift') applyRgbShift(imgData, width, height, prng, reverse);
        else if (algo === 'hilbert') applyHilbert(imgData, width, height, prng, reverse);
        else if (algo === 'spiral') applySpiral(imgData, width, height, prng, reverse);
        else if (algo === 'zigzag') applyZigzag(imgData, width, height, prng, reverse);
        else if (algo === 'chirikov') applyChirikov(imgData, width, height, prng, reverse);
        else if (algo === 'henon') applyHenon(imgData, width, height, prng, reverse);
        else if (algo === 'rubik') applyRubik(imgData, width, height, prng, reverse);
        else if (algo === 'block-shuffle-8') applyBlockShuffle8(imgData, width, height, prng, reverse);
        else if (algo === 'block-shuffle-16') applyBlockShuffle16(imgData, width, height, prng, reverse);
        else if (algo === 'dfws') applyDFWS(imgData, width, height, prng, reverse);
        else if (algo === 'quantize-shuffle') applyQuantizeShuffle(imgData, width, height, prng, reverse);
        else if (algo === 'color-crush') applyColorCrush(imgData, width, height, prng, reverse);
        else if (algo === 'blur-noise') applyBlurNoise(imgData, width, height, prng, reverse);
        else if (algo === 'salt-pepper') applySaltPepper(imgData, width, height, prng, reverse);
        // 'none' = stego-only, no pixel manipulation
    }

    // --- OBFUSQUER ---
    btnObfuscate.addEventListener('click', async () => {
        if (!originalImageFile) return alert("Veuillez charger une image d'abord.");
        const pwd = obfPwd.value;
        const sig = obfSig.value;
        const algo = algoSelect.value;
        const sigLoc = sigLocation?.value || 'meta';
        btnObfuscate.innerText = "Calculs Mathématiques...";
        btnObfuscate.disabled = true;

        try {
            const canvas = document.createElement('canvas');
            canvas.width = uploadedImage.width;
            canvas.height = uploadedImage.height;
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(uploadedImage, 0, 0);

            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const internalSalt = crypto.randomUUID();
            const seed = pwd ? pwd + internalSalt : 'public' + internalSalt;
            
            if (algo === 'dfws') {
                RobustWatermark.embed(imgData, "DualsFWShield");
            }
            applyAlgorithm(imgData, canvas.width, canvas.height, algo, seed, false);
            
            let metadata = { v: 5, alg: algo, pwd: !!pwd, salt: internalSalt, mime: originalImageFile.type };

            let fileToEmbed = null;
            if (otherImageFile) fileToEmbed = otherImageFile;
            else if (embedOriginalCb.checked) fileToEmbed = originalImageFile;

            if (fileToEmbed) {
                btnObfuscate.innerText = "Chiffrement du payload...";
                const buf = await fileToEmbed.arrayBuffer();
                const comp = await compressData(buf);
                const { encrypted, salt: pSalt, iv: pIv } = await encryptData(comp, pwd);
                metadata.payload = {
                    data: arrayBufferToBase64(encrypted),
                    salt: pSalt ? arrayBufferToBase64(pSalt) : null,
                    iv: pIv ? arrayBufferToBase64(pIv) : null,
                    mime: fileToEmbed.type
                };
            }

            let sigPayload = null;
            if (sig) {
                const enc = new TextEncoder();
                const comp = await compressData(enc.encode(sig));
                const { encrypted, salt: sSalt, iv: sIv } = await encryptData(comp, pwd);
                sigPayload = {
                    data: arrayBufferToBase64(encrypted),
                    salt: sSalt ? arrayBufferToBase64(sSalt) : null,
                    iv: sIv ? arrayBufferToBase64(sIv) : null
                };
            }

            if (sigPayload && sigLoc === 'lsb') {
                const textToHide = "LSB_SIG:" + JSON.stringify(sigPayload);
                const bytesToHide = new TextEncoder().encode(textToHide);
                try {
                    encodeLSB(imgData, bytesToHide);
                } catch(e) {
                    alert("Message trop long pour les pixels. Sauvegardé en métadonnées.");
                    metadata.sig = sigPayload;
                }
            } else if (sigPayload) {
                metadata.sig = sigPayload;
            }

            ctx.putImageData(imgData, 0, 0);
            
            btnObfuscate.innerText = "Génération du fichier PNG...";
            const visualBlob = await new Promise(r => canvas.toBlob(r, 'image/png'));
            
            const jsonStr = JSON.stringify(metadata);
            const tail = new TextEncoder().encode(jsonStr + MAGIC_MARKER);
            const finalBlob = new Blob([visualBlob, tail], { type: 'image/png' });

            const a = document.createElement('a');
            a.href = URL.createObjectURL(finalBlob);
            a.download = `obscurify_${Date.now()}.png`;
            a.click();
            URL.revokeObjectURL(a.href);

        } catch (e) {
            console.error(e);
            alert("Erreur: " + e.message);
        }
        btnObfuscate.innerText = "Offusquer & Télécharger (PNG)";
        btnObfuscate.disabled = false;
    });

    // --- RESTAURER ---
    btnRevert.addEventListener('click', async () => {
        if (!targetObfuscatedFile) return alert("Veuillez sélectionner l'image.");
        btnRevert.innerText = "Equation Inverse & Stéganographie...";
        btnRevert.disabled = true;
        revertResult.classList.add('hidden');
        revertHiddenContainer.classList.add('hidden');
        revertSigContainer.classList.add('hidden');

        try {
            const buf = await targetObfuscatedFile.arrayBuffer();
            const dec = new TextDecoder();
            
            const tailString = dec.decode(buf.slice(Math.max(0, buf.byteLength - 15000000)));
            const magicIdx = tailString.lastIndexOf(MAGIC_MARKER);
            if (magicIdx === -1) throw new Error("Format invalide. Ce n'est pas une image Obscurify.");
            
            const jsonStart = tailString.substring(0, magicIdx).lastIndexOf('{"v":5');
            if (jsonStart === -1) throw new Error("Métadonnées altérées ou version obsolète.");
            const jsonStr = tailString.substring(jsonStart, magicIdx);
            const meta = JSON.parse(jsonStr);

            if (meta.pwd && !revPwd.value) throw new Error("Mot de passe requis pour restaurer.");
            const seed = meta.pwd ? revPwd.value + meta.salt : 'public' + meta.salt;

            const canvas = document.createElement('canvas');
            canvas.width = targetObfuscatedImage.width;
            canvas.height = targetObfuscatedImage.height;
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(targetObfuscatedImage, 0, 0);
            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            
            let sigPayload = meta.sig;
            const lsbBytes = decodeLSB(imgData);
            if (lsbBytes) {
                const text = new TextDecoder().decode(lsbBytes);
                if (text.startsWith("LSB_SIG:")) sigPayload = JSON.parse(text.substring(8));
            }

            applyAlgorithm(imgData, canvas.width, canvas.height, meta.alg, seed, true);
            ctx.putImageData(imgData, 0, 0);

            const mathBlob = await new Promise(r => canvas.toBlob(r, meta.mime));
            if (currentMathObjectUrl) URL.revokeObjectURL(currentMathObjectUrl);
            currentMathObjectUrl = URL.createObjectURL(mathBlob);
            
            revertPreview.src = currentMathObjectUrl;
            revertResult.classList.remove('hidden');

            if (meta.payload) {
                const encArr = base64ToArrayBuffer(meta.payload.data);
                const sSalt = meta.payload.salt ? base64ToArrayBuffer(meta.payload.salt) : null;
                const sIv = meta.payload.iv ? base64ToArrayBuffer(meta.payload.iv) : null;
                try {
                    const decComp = await decryptData(encArr, meta.pwd ? revPwd.value : null, sSalt, sIv);
                    const original = await decompressData(decComp);
                    const blob = new Blob([original], { type: meta.payload.mime });
                    if (currentHiddenObjectUrl) URL.revokeObjectURL(currentHiddenObjectUrl);
                    currentHiddenObjectUrl = URL.createObjectURL(blob);
                    revertHiddenPreview.src = currentHiddenObjectUrl;
                    revertHiddenContainer.classList.remove('hidden');
                } catch(e) {}
            }

            if (sigPayload) {
                const encArr = base64ToArrayBuffer(sigPayload.data);
                const sSalt = sigPayload.salt ? base64ToArrayBuffer(sigPayload.salt) : null;
                const sIv = sigPayload.iv ? base64ToArrayBuffer(sigPayload.iv) : null;
                try {
                    const decComp = await decryptData(encArr, meta.pwd ? revPwd.value : null, sSalt, sIv);
                    const decFinal = await decompressData(decComp);
                    revertSigText.innerText = new TextDecoder().decode(decFinal);
                    revertSigContainer.classList.remove('hidden');
                } catch(e) {}
            }

        } catch (e) {
            console.error(e);
            alert("Erreur: " + e.message);
        }
        btnRevert.innerText = "Restaurer";
        btnRevert.disabled = false;
    });

    btnDownloadMath.addEventListener('click', () => {
        const a = document.createElement('a');
        a.href = currentMathObjectUrl;
        a.download = `restored_math_${Date.now()}.png`;
        a.click();
    });
    btnDownloadHidden.addEventListener('click', () => {
        const a = document.createElement('a');
        a.href = currentHiddenObjectUrl;
        a.download = `extracted_payload_${Date.now()}.png`;
        a.click();
    });

    // ================================================================
    //  AETHERSHARE INTEGRATION — Partager Tab
    // ================================================================
    const ShareEncoder = {
        async fileToBase64(blob) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => { const r = reader.result; resolve(r.includes(',') ? r.split(',')[1] : r); };
                reader.onerror = reject;
                reader.readAsDataURL(blob);
            });
        },
        base64ToBlob(base64) {
            const bc = atob(base64), ba = [];
            for (let o = 0; o < bc.length; o += 1024) {
                const s = bc.slice(o, o + 1024), bn = new Array(s.length);
                for (let i = 0; i < s.length; i++) bn[i] = s.charCodeAt(i);
                ba.push(new Uint8Array(bn));
            }
            return new Blob(ba);
        },
        async compressStream(stream) {
            if (!window.CompressionStream) return new Response(stream).blob();
            return await new Response(stream.pipeThrough(new CompressionStream('gzip'))).blob();
        },
        async decompressBlob(blob) {
            if (!window.DecompressionStream) return blob;
            return await new Response(blob.stream().pipeThrough(new DecompressionStream('gzip'))).blob();
        },
        async compressImage(file, q = 0.7) {
            return new Promise(r => {
                if (!file.type.startsWith('image/')) { r(file); return; }
                const img = new Image(); img.src = URL.createObjectURL(file);
                img.onload = () => { const c = document.createElement('canvas'); c.width = img.width; c.height = img.height; c.getContext('2d').drawImage(img, 0, 0); c.toBlob(b => r(b), 'image/webp', q); };
                img.onerror = () => r(file);
            });
        },
        async deriveKey(password, salt) {
            const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
            return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        },
        async encrypt(blob, password) {
            const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await this.deriveKey(password, salt), buf = await blob.arrayBuffer();
            const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf);
            return { salt: this.bufToB64(salt), iv: this.bufToB64(iv), data: this.bufToB64(enc) };
        },
        async decrypt(b64Data, password, b64Salt, b64Iv) {
            const salt = this.b64ToBuf(b64Salt), iv = this.b64ToBuf(b64Iv), enc = this.b64ToBuf(b64Data);
            const key = await this.deriveKey(password, salt);
            return new Blob([await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, enc)]);
        },
        async encryptBlob(blob, password) {
            const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await this.deriveKey(password, salt), buf = await blob.arrayBuffer();
            const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf);
            return { salt: this.bufToB64(salt), iv: this.bufToB64(iv), blob: new Blob([enc]) };
        },
        async decryptBlob(encBlob, password, b64Salt, b64Iv) {
            const salt = this.b64ToBuf(b64Salt), iv = this.b64ToBuf(b64Iv), buf = await encBlob.arrayBuffer();
            const key = await this.deriveKey(password, salt);
            return new Blob([await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, buf)]);
        },
        bufToB64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); },
        b64ToBuf(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); },
        strToB64(str) { return this.bufToB64(new TextEncoder().encode(str)); },
        b64ToStr(b64) { return new TextDecoder().decode(this.b64ToBuf(b64)); }
    };

    // Share DOM
    const S = {
        dropZone: document.getElementById('share-drop-zone'),
        fileInput: document.getElementById('share-file-input'),
        optionsPanel: document.getElementById('share-options-panel'),
        filename: document.getElementById('share-filename'),
        filesize: document.getElementById('share-filesize'),
        lossyToggle: document.getElementById('share-lossy-toggle'),
        encryptToggle: document.getElementById('share-encrypt-toggle'),
        pwdContainer: document.getElementById('share-pwd-container'),
        senderPwd: document.getElementById('share-sender-pwd'),
        beamToggle: document.getElementById('share-beam-toggle'),
        beamInfo: document.getElementById('share-beam-info'),
        advancedToggle: document.getElementById('share-advanced-toggle'),
        advancedPanel: document.getElementById('share-advanced-panel'),
        timebomb: document.getElementById('share-timebomb'),
        vibe: document.getElementById('share-vibe'),
        geoToggle: document.getElementById('share-geo-toggle'),
        audioTxBtn: document.getElementById('share-audio-tx-btn'),
        camoBtn: document.getElementById('share-camo-btn'),
        generateBtn: document.getElementById('share-generate-btn'),
        resultPanel: document.getElementById('share-result-panel'),
        shareUrl: document.getElementById('share-url'),
        copyBtn: document.getElementById('share-copy-btn'),
        qrBtn: document.getElementById('share-qr-btn'),
        previewLink: document.getElementById('share-preview-link'),
        qrContainer: document.getElementById('share-qr-container'),
        qrcodeBox: document.getElementById('share-qrcode'),
        statusMsg: document.getElementById('share-status-msg'),
        progressContainer: document.getElementById('share-progress-container'),
        progressFill: document.getElementById('share-progress-fill'),
        progressText: document.getElementById('share-progress-text'),
        // Receiver
        senderView: document.getElementById('share-sender'),
        receiverView: document.getElementById('share-receiver'),
        recvFilename: document.getElementById('share-recv-filename'),
        recvFilesize: document.getElementById('share-recv-filesize'),
        decryptPanel: document.getElementById('share-decrypt-panel'),
        decryptPwd: document.getElementById('share-decrypt-pwd'),
        decryptBtn: document.getElementById('share-decrypt-btn'),
        downloadBtn: document.getElementById('share-download-btn'),
        recvProgress: document.getElementById('share-recv-progress'),
        recvProgressFill: document.getElementById('share-recv-progress-fill'),
        recvProgressText: document.getElementById('share-recv-progress-text'),
        // Audio
        openAudioBtn: document.getElementById('open-audio-btn'),
        audioModal: document.getElementById('audio-modal'),
        closeAudioBtn: document.getElementById('close-audio-btn'),
        startListenBtn: document.getElementById('start-listen-btn'),
        stopListenBtn: document.getElementById('stop-listen-btn'),
        audioCanvas: document.getElementById('audio-visualizer'),
        streamOutput: document.getElementById('stream-output'),
        // Camo
        camoExitTrigger: document.getElementById('camo-exit-trigger'),
        toastContainer: document.getElementById('toast-container')
    };

    let shareFile = null;
    let shareReceivedHeader = null;
    let shareReceivedBlob = null;
    let shareIncomingFile = {};

    function formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + s[i];
    }

    function showToast(message, type = 'info') {
        const t = document.createElement('div');
        t.className = `toast ${type}`;
        const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';
        t.innerHTML = `<i>${icon}</i> <span>${message}</span>`;
        S.toastContainer.appendChild(t);
        void t.offsetWidth;
        t.classList.add('visible');
        setTimeout(() => { t.classList.remove('visible'); setTimeout(() => t.remove(), 300); }, 3000);
    }

    function setShareLoading(on, text = 'Traitement...') {
        if (on) {
            S.progressContainer.classList.remove('hidden');
            S.generateBtn.disabled = true;
            S.progressText.innerText = text;
            S.progressFill.style.width = '70%';
        } else {
            S.progressContainer.classList.add('hidden');
            S.generateBtn.disabled = false;
            S.progressFill.style.width = '0%';
        }
    }

    // File drop
    S.dropZone.addEventListener('click', () => S.fileInput.click());
    ['dragenter','dragover','dragleave','drop'].forEach(e => S.dropZone.addEventListener(e, ev => { ev.preventDefault(); ev.stopPropagation(); }));
    S.dropZone.addEventListener('dragover', () => S.dropZone.classList.add('drag-over'));
    S.dropZone.addEventListener('dragleave', () => S.dropZone.classList.remove('drag-over'));
    S.dropZone.addEventListener('drop', e => { S.dropZone.classList.remove('drag-over'); handleShareFile(e.dataTransfer.files); });
    S.fileInput.addEventListener('change', e => handleShareFile(e.target.files));

    async function handleShareFile(files) {
        if (!files || !files.length) return;
        let file;
        if (files.length > 1) {
            const zip = new JSZip();
            for (let i = 0; i < files.length; i++) zip.file(files[i].name, files[i]);
            const blob = await zip.generateAsync({ type: 'blob' });
            file = new File([blob], 'archive.zip', { type: 'application/zip' });
            S.filename.innerText = `📦 archive.zip (${files.length} fichiers)`;
        } else {
            file = files[0];
            S.filename.innerText = file.name;
        }
        shareFile = file;
        S.filesize.innerText = formatSize(file.size);
        S.optionsPanel.classList.remove('hidden');
        S.resultPanel.classList.add('hidden');
        if (file.type.startsWith('image/')) { S.lossyToggle.parentElement.parentElement.classList.remove('hidden'); S.lossyToggle.checked = true; }
        else { S.lossyToggle.parentElement.parentElement.classList.add('hidden'); S.lossyToggle.checked = false; }
    }

    // Toggles
    S.encryptToggle.addEventListener('change', () => S.pwdContainer.classList.toggle('hidden', !S.encryptToggle.checked));
    S.beamToggle.addEventListener('change', () => S.beamInfo.classList.toggle('hidden', !S.beamToggle.checked));
    S.advancedToggle.addEventListener('click', () => S.advancedPanel.classList.toggle('hidden'));

    /* 
    // Audio (Missing share/audio.js)
    S.openAudioBtn.addEventListener('click', () => S.audioModal.classList.remove('hidden'));
    S.closeAudioBtn.addEventListener('click', () => { S.audioModal.classList.add('hidden'); if (window.audioComp) window.audioComp.stopListening(); S.startListenBtn.classList.remove('hidden'); S.stopListenBtn.classList.add('hidden'); });
    S.startListenBtn.addEventListener('click', () => {
        S.startListenBtn.classList.add('hidden'); S.stopListenBtn.classList.remove('hidden');
        S.streamOutput.innerText = 'Écoute des signaux Aether...';
        if (window.audioComp) window.audioComp.startListening(
            data => { const ctx = S.audioCanvas.getContext('2d'), w = S.audioCanvas.width, h = S.audioCanvas.height; ctx.fillStyle = '#000'; ctx.fillRect(0,0,w,h); const bw = (w/data.length)*2.5; let x = 0; for (let i=0;i<data.length;i++) { const bh=data[i]/2; ctx.fillStyle=`rgb(${bh+100},50,200)`; ctx.fillRect(x,h-bh,bw,bh); x+=bw+1; } },
            bit => { const sp = document.createElement('span'); sp.innerText = bit; sp.style.color = bit === 1 ? '#0f0' : '#555'; S.streamOutput.appendChild(sp); S.streamOutput.scrollTop = S.streamOutput.scrollHeight; }
        );
    });
    S.stopListenBtn.addEventListener('click', () => { if (window.audioComp) window.audioComp.stopListening(); S.startListenBtn.classList.remove('hidden'); S.stopListenBtn.classList.add('hidden'); S.streamOutput.innerText += '\n[Arrêté]'; });
    S.audioTxBtn.addEventListener('click', () => { if (shareFile && window.audioComp) window.audioComp.transmit(shareFile.name); else showToast('Fichier requis', 'error'); });
    */

    /*
    // Camouflage (Missing share/features.js)
    if (typeof Features !== 'undefined') {
        S.camoBtn.addEventListener('click', () => Features.toggleCamouflage(true));
        if (S.camoExitTrigger) S.camoExitTrigger.addEventListener('dblclick', () => Features.toggleCamouflage(false));
        let escCount = 0, escTimer = null;
        document.addEventListener('keydown', e => {
            if (!document.body.classList.contains('camo-mode')) return;
            if (e.key === 'Escape') { escCount++; if (escTimer) clearTimeout(escTimer); escTimer = setTimeout(() => escCount = 0, 500); if (escCount >= 3) { Features.toggleCamouflage(false); escCount = 0; } }
        });
    }
    */

    // Copy & QR
    S.copyBtn.addEventListener('click', () => { navigator.clipboard.writeText(S.shareUrl.value); showToast('Lien copié !', 'success'); });
    S.qrBtn.addEventListener('click', () => {
        S.qrContainer.classList.toggle('hidden');
        if (!S.qrContainer.classList.contains('hidden')) {
            S.qrcodeBox.innerHTML = '';
            try { const qr = qrcode(0, 'L'); qr.addData(S.shareUrl.value); qr.make(); S.qrcodeBox.innerHTML = qr.createImgTag(4, 8); const img = S.qrcodeBox.querySelector('img'); if (img) { img.style.width = '100%'; img.style.height = 'auto'; img.style.imageRendering = 'pixelated'; } }
            catch(e) { showToast('Données trop volumineuses pour le QR', 'error'); S.qrContainer.classList.add('hidden'); }
        }
    });

    // Download
    S.downloadBtn.addEventListener('click', () => {
        if (!shareReceivedBlob) return;
        const a = document.createElement('a'); a.href = URL.createObjectURL(shareReceivedBlob);
        a.download = shareReceivedHeader ? shareReceivedHeader.filename : 'download';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
    });

    // Decrypt
    S.decryptBtn.addEventListener('click', async () => {
        if (!shareReceivedHeader || !shareReceivedHeader.encrypted) return;
        const pwd = S.decryptPwd.value;
        if (!pwd) { showToast('Mot de passe requis', 'error'); return; }
        S.decryptBtn.disabled = true; S.decryptBtn.innerText = 'Déchiffrement...';
        try {
            if (shareReceivedHeader.beam) shareReceivedBlob = await ShareEncoder.decryptBlob(shareReceivedBlob, pwd, shareReceivedHeader.salt, shareReceivedHeader.iv);
            else { const dec = await ShareEncoder.decrypt(shareReceivedHeader.payload, pwd, shareReceivedHeader.salt, shareReceivedHeader.iv); shareReceivedBlob = await ShareEncoder.decompressBlob(dec); }
            S.recvFilesize.innerText = formatSize(shareReceivedBlob.size);
            S.downloadBtn.disabled = false; S.decryptPanel.classList.add('hidden');
            S.recvFilename.innerText = shareReceivedHeader.filename;
        } catch(e) { showToast('Échec du déchiffrement', 'error'); }
        S.decryptBtn.disabled = false; S.decryptBtn.innerText = 'Déverrouiller';
    });

    // Generate Link
    S.generateBtn.addEventListener('click', async () => {
        if (!shareFile) return;
        if (S.beamToggle.checked) {
            alert("Beam P2P est temporairement indisponible (share/p2p.js manquant)");
            /*
            setShareLoading(true, 'Initialisation Beam...');
            try {
                const peerId = await window.p2p.init();
                window.p2p.waitForReceiver(() => {
                    S.statusMsg.innerText = '🚀 Envoi en cours...';
                    S.progressContainer.classList.remove('hidden'); S.progressFill.style.width = '0%';
                    window.p2p.sendFile(shareFile, {}, pct => { S.progressFill.style.width = pct+'%'; S.progressText.innerText = pct+'%'; S.statusMsg.innerText = `🚀 Envoi... ${pct}%`; })
                    .then(() => { setShareLoading(false); showToast('Transfert terminé !', 'success'); S.statusMsg.innerText = '✅ Transfert Complete !'; });
                }, err => { showToast('Erreur P2P: ' + err.message, 'error'); });
                const hash = `BEAM|${peerId}|${encodeURIComponent(shareFile.name)}|${shareFile.size}`;
                showShareResult(hash);
                S.statusMsg.innerText = '📡 Beam Active: En attente du destinataire...';
            } catch(e) { showToast('Erreur Beam: ' + e.message, 'error'); }
            */
            setShareLoading(false);
            return;
        }
        setShareLoading(true, 'Traitement...');
        setTimeout(async () => {
            try {
                let blob = shareFile;
                if (S.lossyToggle.checked && shareFile.type.startsWith('image/')) { setShareLoading(true, 'Optimisation Image...'); blob = await ShareEncoder.compressImage(shareFile); }
                setShareLoading(true, 'Compression...');
                const compressed = await ShareEncoder.compressStream(blob.stream());
                const header = { filename: shareFile.name, encrypted: S.encryptToggle.checked };
                const vibe = S.vibe.value; if (vibe !== 'default') header.vibe = vibe;
                const tb = parseInt(S.timebomb.value); if (tb > 0 && typeof Features !== 'undefined') header.expiry = Features.getExpiryTimestamp(tb);
                if (S.geoToggle.checked && typeof Features !== 'undefined') { setShareLoading(true, 'Géolocalisation...'); header.geo = await Features.getCurrentPosition(); }
                let payload;
                if (header.encrypted) {
                    const pwd = S.senderPwd.value; if (!pwd) throw new Error('Mot de passe requis');
                    setShareLoading(true, 'Chiffrement...'); const enc = await ShareEncoder.encrypt(compressed, pwd);
                    header.salt = enc.salt; header.iv = enc.iv; payload = enc.data;
                } else { setShareLoading(true, 'Encodage...'); payload = await ShareEncoder.fileToBase64(compressed); }
                const hb64 = ShareEncoder.strToB64(JSON.stringify(header));
                showShareResult(`AETHER|${hb64}|${payload}`);
            } catch(e) { showToast('Erreur: ' + e.message, 'error'); }
            setShareLoading(false);
        }, 50);
    });

    function showShareResult(hash) {
        const url = `${location.origin}${location.pathname}#${hash}`;
        S.shareUrl.value = url; S.previewLink.href = url;
        S.resultPanel.classList.remove('hidden');
        S.qrcodeBox.innerHTML = ''; S.qrContainer.classList.add('hidden');
    }

    // Routing: detect share links in URL hash
    function handleShareRouting() {
        const hash = location.hash.substring(1);
        if (!hash || hash.length < 6 || !hash.includes('|')) return;
        // Activate Share tab and receiver
        tabs.forEach(t => t.classList.remove('active'));
        views.forEach(v => v.classList.remove('active'));
        document.querySelector('[data-target="share-view"]').classList.add('active');
        document.getElementById('share-view').classList.add('active');
        S.senderView.classList.remove('active');
        S.receiverView.classList.add('active');
        parseShareHash(hash);
    }

    async function parseShareHash(hash) {
        S.downloadBtn.disabled = true; S.decryptPanel.classList.add('hidden');
        try {
            if (hash.startsWith('BEAM|')) {
                alert("Beam P2P est temporairement indisponible (share/p2p.js manquant)");
                /*
                const p = hash.split('|'), peerId = p[1];
                const hdr = { filename: decodeURIComponent(p[2]), beam: true };
                S.recvFilename.innerText = '📡 ' + hdr.filename;
                S.recvFilesize.innerText = 'Connexion au pair...';
                shareReceivedHeader = hdr;
                shareIncomingFile = { chunks: [], receivedSize: 0, totalSize: 0, initialized: false };
                S.recvProgress.classList.remove('hidden'); S.recvProgressFill.style.width = '0%';
                await window.p2p.init();
                window.p2p.connect(peerId, data => {
                    if (data.type === 'meta') {
                        shareReceivedHeader = { filename: data.filename, size: data.size, fileType: data.fileType || 'application/octet-stream', encrypted: data.encrypted, salt: data.salt, iv: data.iv, beam: true };
                        shareIncomingFile.totalSize = data.size; shareIncomingFile.initialized = true;
                        S.recvFilename.innerText = (data.encrypted ? '🔒 ' : '📡 ') + data.filename;
                        S.recvFilesize.innerText = 'Réception en cours...';
                    } else if (data.type === 'chunk' && shareIncomingFile.initialized) {
                        shareIncomingFile.chunks.push(data.data);
                        shareIncomingFile.receivedSize += data.data.size || data.data.byteLength;
                        const pct = Math.min(100, Math.round((shareIncomingFile.receivedSize / shareIncomingFile.totalSize) * 100));
                        S.recvProgressFill.style.width = pct + '%'; S.recvProgressText.innerText = pct + '%';
                        if (shareIncomingFile.receivedSize >= shareIncomingFile.totalSize) {
                            shareReceivedBlob = new Blob(shareIncomingFile.chunks, { type: shareReceivedHeader.fileType });
                            shareIncomingFile.chunks = [];
                            if (shareReceivedHeader.encrypted) { S.recvFilesize.innerText = 'Fichier chiffré reçu.'; S.decryptPanel.classList.remove('hidden'); }
                            else { S.recvFilesize.innerText = formatSize(shareReceivedBlob.size); S.downloadBtn.disabled = false; }
                            setTimeout(() => S.recvProgress.classList.add('hidden'), 1000);
                        }
                    }
                }, err => { S.recvFilesize.innerText = 'Connexion échouée.'; showToast('Erreur P2P: ' + err.message, 'error'); });
                */
                return;
            }
            let header, payload;
            if (hash.startsWith('AETHER|')) {
                const p = hash.split('|'); header = JSON.parse(ShareEncoder.b64ToStr(p[1])); payload = p[2];
            } else {
                const p = hash.split('|');
                if (p[0] === 'SECURE') { header = { filename: decodeURIComponent(p[1]), encrypted: true, salt: p[2], iv: p[3] }; payload = p[4]; }
                else { header = { filename: decodeURIComponent(p[0]), encrypted: false }; payload = p[1]; }
            }
            shareReceivedHeader = header; shareReceivedHeader.payload = payload;
            S.recvFilename.innerText = (header.encrypted ? '🔒 ' : '') + header.filename;
            if (header.expiry && typeof Features !== 'undefined') { const st = Features.checkExpiry(header.expiry); if (st.expired) { S.recvFilename.innerText = '💥 Lien Expiré'; S.recvFilesize.innerText = 'Auto-détruit.'; return; } }
            if (header.geo && typeof Features !== 'undefined') { S.recvFilesize.innerText = 'Vérification position...'; const gs = await Features.verifyLocation(header.geo.lat, header.geo.lng); if (!gs.allowed) { S.recvFilename.innerText = '📍 Accès Refusé'; S.recvFilesize.innerText = gs.error || 'Mauvaise position.'; return; } }
            if (header.vibe && typeof Features !== 'undefined') Features.applyVibe(header.vibe);
            if (header.encrypted) { S.recvFilesize.innerText = 'Fichier Chiffré'; S.decryptPanel.classList.remove('hidden'); }
            else { S.recvFilesize.innerText = 'Traitement...'; setTimeout(async () => { const cb = ShareEncoder.base64ToBlob(payload); shareReceivedBlob = await ShareEncoder.decompressBlob(cb); S.recvFilesize.innerText = formatSize(shareReceivedBlob.size); S.downloadBtn.disabled = false; }, 100); }
        } catch(e) { S.recvFilename.innerText = 'Erreur de parsing'; S.recvFilesize.innerText = 'URL invalide'; }
    }

    handleShareRouting();
    window.addEventListener('hashchange', handleShareRouting);

    // ================================================================
    //  ENHANCEMENT FEATURES
    // ================================================================

    // --- Web Worker ---
    let obfWorker = null;
    try { obfWorker = new Worker('worker.js'); } catch(e) { console.warn('Worker unavailable, using main thread'); }
    function workerApply(algo, dataBuffer, w, h, seed, reverse, intensity) {
        return new Promise((resolve, reject) => {
            if (!obfWorker) { reject('no worker'); return; }
            const id = Math.random();
            const handler = e => { if (e.data.id === id) { obfWorker.removeEventListener('message', handler); if (e.data.error) reject(e.data.error); else resolve(new Uint8Array(e.data.result)); } };
            obfWorker.addEventListener('message', handler);
            const copy = dataBuffer.slice(0);
            obfWorker.postMessage({ id, algo, data: copy, width: w, height: h, seed, reverse, intensity }, [copy]);
        });
    }

    // --- Theme Toggle (Dark/Light) ---
    const themeBtn = document.getElementById('theme-toggle');
    if (localStorage.getItem('obscurify-theme') === 'light') { document.body.classList.add('light-mode'); themeBtn.textContent = '☀️'; }
    themeBtn.addEventListener('click', () => {
        document.body.classList.toggle('light-mode');
        const isLight = document.body.classList.contains('light-mode');
        themeBtn.textContent = isLight ? '☀️' : '🌙';
        localStorage.setItem('obscurify-theme', isLight ? 'light' : 'dark');
    });

    // --- Password Strength Meter ---
    const pwdFill = document.getElementById('pwd-strength-fill');
    const pwdText = document.getElementById('pwd-strength-text');
    obfPwd.addEventListener('input', () => {
        const p = obfPwd.value, len = p.length;
        let score = 0;
        if (len >= 6) score += 20; if (len >= 10) score += 20; if (len >= 14) score += 10;
        if (/[A-Z]/.test(p)) score += 10; if (/[a-z]/.test(p)) score += 10;
        if (/[0-9]/.test(p)) score += 10; if (/[^A-Za-z0-9]/.test(p)) score += 20;
        score = Math.min(100, score);
        pwdFill.style.width = score + '%';
        const colors = ['#ff4444', '#ff8800', '#ffcc00', '#88cc00', '#00cc44'];
        const labels = ['Très faible', 'Faible', 'Moyen', 'Fort', 'Excellent'];
        const idx = Math.min(4, Math.floor(score / 25));
        pwdFill.style.background = colors[idx];
        pwdText.textContent = len ? labels[idx] : '';
        pwdText.style.color = colors[idx];
        updateSecurityScore();
    });

    // --- Security Score Gauge ---
    const gaugeArc = document.getElementById('gauge-arc');
    const gaugeVal = document.getElementById('gauge-value');
    const gaugeLabel = document.getElementById('gauge-label');
    function updateSecurityScore() {
        let score = 0;
        const algo = algoSelect.value;
        const destructives = ['quantize-shuffle','color-crush','blur-noise','salt-pepper'];
        if (algo === 'none') score += 5;
        else score += destructives.includes(algo) ? 10 : 20;
        const pwd = obfPwd.value;
        if (pwd.length >= 6) score += 15; if (pwd.length >= 10) score += 10; if (pwd.length >= 14) score += 5;
        if (/[^A-Za-z0-9]/.test(pwd)) score += 5;
        if (embedOriginalCb.checked || otherImageFile) score += 15;
        if (obfSig.value) score += 10;
        const sigLoc = document.getElementById('sig-location');
        if (sigLoc && sigLoc.value === 'lsb' && obfSig.value) score += 5;
        const wmToggle = document.getElementById('watermark-toggle');
        if (wmToggle && wmToggle.checked) score += 10;
        const glitch = document.getElementById('glitch-slider');
        if (glitch && parseInt(glitch.value) === 100) score += 5;
        score = Math.min(100, score);
        const dashLen = (score / 100) * 157;
        gaugeArc.setAttribute('stroke-dasharray', dashLen + ' 157');
        const colors = ['#ff4444','#ff8800','#ffcc00','#88cc00','#00cc44'];
        const labels = ['Vulnérable','Faible','Moyen','Fort','Blindé'];
        const idx = Math.min(4, Math.floor(score / 25));
        gaugeArc.setAttribute('stroke', colors[idx]);
        gaugeVal.textContent = score;
        gaugeLabel.textContent = labels[idx];
    }
    const COMPRESSION_DATA = {
        'none':             { level: '—',  color: '#94a3b8', desc: 'Aucune obfuscation. Le fichier caché survit si exporté en PNG.' },
        'xor-shuffle':      { level: '🟢 Forte', color: '#10b981', desc: 'Déplacement massif de pixels. L\'image reste visuellement brouillée même après JPEG Q30.' },
        'logistic-xor':     { level: '🟢 Forte', color: '#10b981', desc: 'Chaos non-linéaire. Brouillage total très résistant à toute compression.' },
        'cat-map':          { level: '🟢 Forte', color: '#10b981', desc: 'Permutation fractale. La torsion globale survit à JPEG Q50+.' },
        'baker-map':        { level: '🟢 Forte', color: '#10b981', desc: 'Découpage en bandes. Effet visible même après compression lourde.' },
        'affine-map':       { level: '🟡 Moyenne', color: '#f59e0b', desc: 'Décalage linéaire modulo. Les motifs réguliers sont partiellement lissés par JPEG.' },
        'wave-shift':       { level: '🟡 Moyenne', color: '#f59e0b', desc: 'Ondulations sinusoïdales. Les basses fréquences survivent, les détails fins sont perdus.' },
        'prime-scatter':    { level: '🟡 Moyenne', color: '#f59e0b', desc: 'Dispersion par nombres premiers. Effet partiel après JPEG Q60+.' },
        'rgb-shift':        { level: '🔴 Faible', color: '#ef4444', desc: 'Décalage de canaux. JPEG fusionne les couleurs voisines, réduisant l\'effet visible.' },
        'hilbert':          { level: '🟢 Forte', color: '#10b981', desc: 'Courbe de remplissage. Redistribution totale des pixels, très résistant.' },
        'spiral':           { level: '🟢 Forte', color: '#10b981', desc: 'Réorganisation en spirale. Brouillage fort résistant à la compression.' },
        'zigzag':           { level: '🟢 Forte', color: '#10b981', desc: 'Parcours diagonal JPEG-like. Survit bien car aligné sur la structure DCT.' },
        'chirikov':         { level: '🟢 Forte', color: '#10b981', desc: 'Map standard chaotique. Déplacement non-linéaire massif, très résistant.' },
        'henon':            { level: '🟢 Forte', color: '#10b981', desc: 'Attracteur chaotique. Dispersion fractalique très résistante.' },
        'rubik':            { level: '🟢 Forte', color: '#10b981', desc: 'Rotation de plans RGB. Effet de brouillage survit à toute compression.' },
        'block-shuffle-8':  { level: '⭐ RÉVERSIBLE', color: '#8b5cf6', desc: 'Permutation de blocs 8×8 (aligné JPEG). Réversible même après compression JPEG Q50+ / WhatsApp.', compReversible: true },
        'block-shuffle-16': { level: '⭐ RÉVERSIBLE', color: '#8b5cf6', desc: 'Permutation de blocs 16×16. Plus robuste aux redimensionnements. Réversible après recompression.', compReversible: true },
        'dfws':             { level: '\ud83d\udee1\ufe0f DFWS', color: '#f59e0b', desc: 'DualsFWShield — Shuffle + rotation canaux + flip + inversion par bloc 8×8. Résiste JPEG, crop, screenshot. Les parties survivantes sont individuellement restaurables.', compReversible: true },
        'quantize-shuffle': { level: '🟢 Forte', color: '#10b981', desc: 'Quantification + permutation. La pixélisation résiste naturellement à JPEG.' },
        'color-crush':      { level: '🟢 Forte', color: '#10b981', desc: 'Palette réduite. Le broyage de couleurs est amplifié par la compression.' },
        'blur-noise':       { level: '🟡 Moyenne', color: '#f59e0b', desc: 'Flou + bruit. Le bruit est lissé par JPEG mais le flou persiste.' },
        'salt-pepper':      { level: '🟡 Moyenne', color: '#f59e0b', desc: 'Pixels aléatoires noir/blanc. JPEG lisse les points isolés.' }
    };
    function updateCompressionInfo() {
        const info = document.getElementById('algo-compression-info');
        if (!info) return;
        const algo = algoSelect.value;
        const data = COMPRESSION_DATA[algo];
        if (!data || algo === 'none') { info.style.display = 'none'; return; }
        info.style.display = 'block';
        const revNote = data.compReversible
            ? '<br><span style="color:#10b981;font-size:0.65rem;">✅ Cet algo est RÉVERSIBLE même après compression JPEG / envoi WhatsApp. La qualité sera légèrement dégradée par la compression mais l\'image sera restaurée.</span>'
            : '<br><span style="color:#f59e0b;font-size:0.65rem;">⚠️ Reversibilité math. perdue après compression JPEG — exporter en PNG pour restaurer.</span>';
        info.innerHTML = `<span style="color:${data.color};font-weight:600;">${data.level}</span> — ${data.desc}${revNote}`;
    }
    algoSelect.addEventListener('change', () => {
        updateSecurityScore();
        updateCompressionInfo();
        const destructives = ['quantize-shuffle','color-crush','blur-noise','salt-pepper'];
        const warn = document.getElementById('algo-warning');
        if (warn) warn.classList.toggle('hidden', !destructives.includes(algoSelect.value));
        // Show/hide stego notice for 'none' mode
        const noneNotice = document.getElementById('algo-none-notice');
        if (noneNotice) noneNotice.classList.toggle('hidden', algoSelect.value !== 'none');
    });
    updateCompressionInfo();
    embedOriginalCb.addEventListener('change', updateSecurityScore);
    obfSig.addEventListener('input', updateSecurityScore);
    document.getElementById('watermark-toggle')?.addEventListener('change', updateSecurityScore);
    document.getElementById('glitch-slider')?.addEventListener('input', e => {
        document.getElementById('glitch-value').textContent = e.target.value;
        const warn = document.getElementById('glitch-warning');
        if (warn) warn.classList.toggle('hidden', parseInt(e.target.value) >= 100);
        updateSecurityScore();
    });
    updateSecurityScore();

    // --- Watermark Toggle ---
    const wmToggle = document.getElementById('watermark-toggle');
    const wmInput = document.getElementById('watermark-input');
    wmToggle?.addEventListener('change', () => wmInput.classList.toggle('hidden', !wmToggle.checked));
    document.querySelectorAll('input[name="wm-mode"]').forEach(r => r.addEventListener('change', () => {
        const dctNotice = document.getElementById('wm-dct-notice');
        const wmText = document.getElementById('watermark-text');
        if (r.value === 'dct' && r.checked) {
            dctNotice?.classList.remove('hidden');
            if (wmText) { wmText.maxLength = 16; wmText.placeholder = 'Texte du watermark (max 16 car.)'; }
        } else if (r.value === 'lsb' && r.checked) {
            dctNotice?.classList.add('hidden');
            if (wmText) { wmText.maxLength = 32; wmText.placeholder = 'Texte du watermark (max 32 car.)'; }
        }
        updateSecurityScore();
    }));

    // --- Spread-Spectrum Watermark ---
    function embedWatermark(imgData, text) {
        const bits = []; const bytes = new TextEncoder().encode(text.substring(0, 32));
        for (let i = 0; i < 16; i++) bits.push((bytes.length >> i) & 1);
        for (const b of bytes) for (let j = 0; j < 8; j++) bits.push((b >> j) & 1);
        const step = Math.max(1, Math.floor(imgData.data.length / 4 / bits.length));
        for (let i = 0; i < bits.length; i++) {
            const px = i * step * 4 + 2;
            if (px < imgData.data.length) imgData.data[px] = (imgData.data[px] & 0xFE) | bits[i];
        }
    }
    function extractWatermark(imgData) {
        let len = 0;
        const totalBits = Math.floor(imgData.data.length / 4);
        const guessStep = s => { let l = 0; for (let i = 0; i < 16; i++) { const px = i * s * 4 + 2; if (px < imgData.data.length) l |= (imgData.data[px] & 1) << i; } return l; };
        for (let s = 1; s < 200; s++) { len = guessStep(s); if (len > 0 && len <= 32) { const bytes = new Uint8Array(len); for (let i = 0; i < len; i++) { let b = 0; for (let j = 0; j < 8; j++) { const px = (16 + i * 8 + j) * s * 4 + 2; if (px < imgData.data.length) b |= (imgData.data[px] & 1) << j; } bytes[i] = b; } try { const t = new TextDecoder().decode(bytes); if (/^[\x20-\x7E]+$/.test(t)) return t; } catch(e){} } }
        return null;
    }

    // --- Sound Notifications ---
    function playSound(type) {
        try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const osc = ctx.createOscillator(), gain = ctx.createGain();
            osc.connect(gain); gain.connect(ctx.destination);
            gain.gain.value = 0.15;
            if (type === 'success') { osc.frequency.value = 880; osc.type = 'sine'; }
            else if (type === 'error') { osc.frequency.value = 220; osc.type = 'square'; }
            else { osc.frequency.value = 660; osc.type = 'sine'; }
            osc.start(); osc.stop(ctx.currentTime + 0.15);
        } catch(e) {}
    }

    // --- Konami Code ---
    const konamiSeq = [38,38,40,40,37,39,37,39,66,65];
    let konamiIdx = 0;
    document.addEventListener('keydown', e => {
        if (e.keyCode === konamiSeq[konamiIdx]) { konamiIdx++; if (konamiIdx === konamiSeq.length) { document.body.classList.toggle('konami-mode'); showToast('🌈 Mode Secret Activé !', 'success'); playSound('success'); konamiIdx = 0; } }
        else konamiIdx = 0;
    });

    // --- Comparison Slider ---
    let compareOrigData = null, compareObfData = null, compareW = 0, compareH = 0;
    const compareContainer = document.getElementById('compare-container');
    const compareCanvas = document.getElementById('compare-canvas');
    const compareHandle = document.getElementById('compare-handle');
    let compareDragging = false, comparePos = 0.5;

    function drawComparison() {
        if (!compareOrigData || !compareObfData) return;
        const ctx = compareCanvas.getContext('2d');
        compareCanvas.width = compareW; compareCanvas.height = compareH;
        const orig = new ImageData(new Uint8ClampedArray(compareOrigData), compareW, compareH);
        const obf = new ImageData(new Uint8ClampedArray(compareObfData), compareW, compareH);
        const splitX = Math.floor(compareW * comparePos);
        ctx.putImageData(orig, 0, 0);
        const obfCanvas = document.createElement('canvas');
        obfCanvas.width = compareW; obfCanvas.height = compareH;
        obfCanvas.getContext('2d').putImageData(obf, 0, 0);
        ctx.drawImage(obfCanvas, splitX, 0, compareW - splitX, compareH, splitX, 0, compareW - splitX, compareH);
        compareHandle.style.left = (comparePos * 100) + '%';
    }

    const slider = document.getElementById('compare-slider');
    function startDrag(e) { compareDragging = true; moveDrag(e); }
    function moveDrag(e) {
        if (!compareDragging) return;
        const rect = slider.getBoundingClientRect();
        const clientX = e.touches ? e.touches[0].clientX : e.clientX;
        comparePos = Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
        drawComparison();
    }
    function endDrag() { compareDragging = false; }
    slider.addEventListener('mousedown', startDrag); slider.addEventListener('touchstart', startDrag);
    document.addEventListener('mousemove', moveDrag); document.addEventListener('touchmove', moveDrag);
    document.addEventListener('mouseup', endDrag); document.addEventListener('touchend', endDrag);

    // --- Effect Gallery ---
    const galleryEl = document.getElementById('effect-gallery');
    const algos = ['xor-shuffle','logistic-xor','cat-map','baker-map','affine-map','wave-shift','prime-scatter','rgb-shift','hilbert','spiral','zigzag','chirikov','henon','rubik','block-shuffle-8','block-shuffle-16','dfws','quantize-shuffle','color-crush','blur-noise','salt-pepper'];
    const algoNames = ['XOR','Logistic','Cat Map','Baker','Affine','Wave','Prime','RGB','Hilbert','Spiral','Zigzag','Chirikov','H\u00e9non','Rubik','Bloc 8\u00d78','Bloc 16\u00d716','DFWS','Quantize','Crush','Blur','S&P'];
    const REVERSIBLE_COUNT = 17; // first 17 are reversible, last 4 are destructive
    function buildGallery() {
        galleryEl.innerHTML = '';
        if (!originalImageFile) { galleryEl.innerHTML = '<p style="grid-column:span 4;text-align:center;color:var(--text-muted);font-size:0.75rem;">Chargez une image pour voir les effets</p>'; return; }
        const thumbSize = 64;
        const thumbCanvas = document.createElement('canvas');
        thumbCanvas.width = thumbSize; thumbCanvas.height = thumbSize;
        const thumbCtx = thumbCanvas.getContext('2d');
        thumbCtx.drawImage(uploadedImage, 0, 0, thumbSize, thumbSize);
        const origData = thumbCtx.getImageData(0, 0, thumbSize, thumbSize);

        // Section: "Aucun" (stego only)
        const noneHeader = document.createElement('div');
        noneHeader.className = 'gallery-section-header';
        noneHeader.innerHTML = '🔒 St\u00e9go Pure';
        noneHeader.style.cssText = 'grid-column:span 4;font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--primary);padding:4px 0;border-bottom:1px solid rgba(99,102,241,0.2);margin-bottom:2px;';
        galleryEl.appendChild(noneHeader);
        // None thumb = original image unchanged
        const noneDiv = document.createElement('div');
        noneDiv.className = 'effect-thumb' + (algoSelect.value === 'none' ? ' active' : '');
        const noneCanvas = document.createElement('canvas');
        noneCanvas.width = thumbSize; noneCanvas.height = thumbSize;
        noneCanvas.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(origData.data), thumbSize, thumbSize), 0, 0);
        noneDiv.appendChild(noneCanvas);
        const noneLabel = document.createElement('div');
        noneLabel.className = 'effect-thumb-label';
        noneLabel.textContent = 'Aucun';
        noneDiv.appendChild(noneLabel);
        noneDiv.addEventListener('click', () => { algoSelect.value = 'none'; buildGallery(); updateSecurityScore(); });
        galleryEl.appendChild(noneDiv);

        // Section: Reversible
        const revHeader = document.createElement('div');
        revHeader.className = 'gallery-section-header';
        revHeader.innerHTML = '\u2705 R\u00e9versibles';
        revHeader.style.cssText = 'grid-column:span 4;font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:#10b981;padding:6px 0 2px;border-bottom:1px solid rgba(16,185,129,0.2);margin-bottom:2px;margin-top:6px;';
        galleryEl.appendChild(revHeader);

        algos.forEach((algo, i) => {
            // Insert compression-resistant header before block-shuffle algos
            if (i === 14) {
                const compHeader = document.createElement('div');
                compHeader.className = 'gallery-section-header';
                compHeader.innerHTML = '\u2b50 Anti-Compression';
                compHeader.style.cssText = 'grid-column:span 4;font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:#8b5cf6;padding:6px 0 2px;border-bottom:1px solid rgba(139,92,246,0.3);margin-bottom:2px;margin-top:6px;';
                galleryEl.appendChild(compHeader);
            }
            // Insert destructive header before first destructive algo
            if (i === REVERSIBLE_COUNT) {
                const destHeader = document.createElement('div');
                destHeader.className = 'gallery-section-header';
                destHeader.innerHTML = '\u26a0\ufe0f Destructifs';
                destHeader.style.cssText = 'grid-column:span 4;font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:#f59e0b;padding:6px 0 2px;border-bottom:1px solid rgba(245,158,11,0.2);margin-bottom:2px;margin-top:6px;';
                galleryEl.appendChild(destHeader);
            }
            const div = document.createElement('div');
            div.className = 'effect-thumb' + (algoSelect.value === algo ? ' active' : '');
            if (i >= REVERSIBLE_COUNT) div.style.borderColor = 'rgba(245,158,11,0.3)';
            else if (i >= 14) div.style.borderColor = 'rgba(139,92,246,0.5)';
            const c = document.createElement('canvas');
            c.width = thumbSize; c.height = thumbSize;
            const ctx = c.getContext('2d');
            const copy = new ImageData(new Uint8ClampedArray(origData.data), thumbSize, thumbSize);
            applyAlgorithm(copy, thumbSize, thumbSize, algo, 'gallery_preview_' + algo, false);
            ctx.putImageData(copy, 0, 0);
            div.appendChild(c);
            // Compression resistance badge
            const compData = COMPRESSION_DATA[algo];
            if (compData) {
                const badge = document.createElement('div');
                badge.className = 'effect-thumb-badge';
                badge.style.cssText = `position:absolute;top:3px;right:3px;width:10px;height:10px;border-radius:50%;background:${compData.color};border:1px solid rgba(0,0,0,0.3);`;
                badge.title = compData.level + ' — ' + compData.desc;
                div.appendChild(badge);
            }
            const label = document.createElement('div');
            label.className = 'effect-thumb-label';
            label.textContent = algoNames[i];
            div.appendChild(label);
            div.addEventListener('click', () => { algoSelect.value = algo; buildGallery(); updateSecurityScore(); updateCompressionInfo(); });
            galleryEl.appendChild(div);
        });
    }
    algoSelect.addEventListener('change', buildGallery);

    // --- History (IndexedDB) ---
    const DB_NAME = 'ObscurifyHistory', DB_VER = 1, STORE = 'history';
    function openDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, DB_VER);
            req.onupgradeneeded = e => e.target.result.createObjectStore(STORE, { keyPath: 'id', autoIncrement: true });
            req.onsuccess = e => resolve(e.target.result);
            req.onerror = e => reject(e.target.error);
        });
    }
    async function addHistory(entry) {
        const db = await openDB();
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).add(entry);
    }
    async function getHistory() {
        const db = await openDB();
        return new Promise(resolve => {
            const tx = db.transaction(STORE, 'readonly');
            const req = tx.objectStore(STORE).getAll();
            req.onsuccess = () => resolve(req.result.reverse());
        });
    }
    async function clearHistory() {
        const db = await openDB();
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).clear();
    }
    async function renderHistory() {
        const list = document.getElementById('history-list');
        const empty = document.getElementById('history-empty');
        const clearBtn = document.getElementById('history-clear');
        const items = await getHistory();
        if (!items.length) { list.innerHTML = ''; empty.classList.remove('hidden'); clearBtn.classList.add('hidden'); return; }
        empty.classList.add('hidden'); clearBtn.classList.remove('hidden');
        list.innerHTML = items.slice(0, 50).map(h => `<div class="history-card"><img class="history-thumb" src="${h.thumb}" alt=""><div class="history-info"><div class="h-name">${h.filename}</div><div class="h-meta">${new Date(h.date).toLocaleString('fr-FR')} · ${h.algo}</div></div><span class="history-badge">${h.algo}</span></div>`).join('');
    }
    document.getElementById('history-clear')?.addEventListener('click', async () => { await clearHistory(); renderHistory(); showToast('Historique effacé', 'info'); });

    // Create thumbnail for history
    function createThumb(img, size = 80) {
        const c = document.createElement('canvas'); c.width = size; c.height = size;
        c.getContext('2d').drawImage(img, 0, 0, size, size);
        return c.toDataURL('image/webp', 0.5);
    }

    // --- SHA-256 Hash ---
    async function computeSHA256(blob) {
        const buf = await blob.arrayBuffer();
        const hash = await crypto.subtle.digest('SHA-256', buf);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // --- GIF Export ---
    const btnExportGif = document.getElementById('btn-export-gif');
    btnExportGif?.addEventListener('click', async () => {
        if (!originalImageFile || !compareOrigData || !compareObfData) { showToast('Offusquez d\'abord une image', 'error'); return; }
        btnExportGif.disabled = true; btnExportGif.textContent = '⏳';
        try {
            const gif = new GIF({ workers: 2, quality: 10, width: compareW, height: compareH, workerScript: 'https://cdn.jsdelivr.net/npm/gif.js@0.2.0/dist/gif.worker.js' });
            const c1 = document.createElement('canvas'); c1.width = compareW; c1.height = compareH;
            c1.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(compareOrigData), compareW, compareH), 0, 0);
            const c2 = document.createElement('canvas'); c2.width = compareW; c2.height = compareH;
            c2.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(compareObfData), compareW, compareH), 0, 0);
            gif.addFrame(c1, { delay: 1000, copy: true });
            gif.addFrame(c2, { delay: 1000, copy: true });
            gif.on('finished', blob => {
                const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
                a.download = `obscurify_${Date.now()}.gif`; a.click();
                showToast('GIF exporté !', 'success'); playSound('success');
            });
            gif.render();
        } catch(e) { showToast('Erreur GIF: ' + e.message, 'error'); }
        btnExportGif.disabled = false; btnExportGif.textContent = 'GIF';
    });

    // --- Batch File Support ---
    let batchFiles = [];
    function renderBatchThumbs() {
        const container = document.getElementById('batch-thumbs');
        if (!container) return;
        container.innerHTML = '';
        batchFiles.forEach((file, i) => {
            const wrap = document.createElement('div');
            wrap.className = 'batch-thumb-wrap';
            wrap.draggable = true;
            wrap.dataset.index = i;
            const img = document.createElement('img');
            img.className = 'batch-thumb';
            img.src = URL.createObjectURL(file);
            const num = document.createElement('div');
            num.className = 'batch-thumb-num';
            num.textContent = i + 1;
            wrap.appendChild(img);
            wrap.appendChild(num);
            // Drag & Drop reorder
            wrap.addEventListener('dragstart', e => { e.dataTransfer.setData('text/plain', i); wrap.classList.add('dragging'); });
            wrap.addEventListener('dragend', () => wrap.classList.remove('dragging'));
            wrap.addEventListener('dragover', e => { e.preventDefault(); wrap.classList.add('drag-over'); });
            wrap.addEventListener('dragleave', () => wrap.classList.remove('drag-over'));
            wrap.addEventListener('drop', e => {
                e.preventDefault();
                wrap.classList.remove('drag-over');
                const from = parseInt(e.dataTransfer.getData('text/plain'));
                const to = i;
                if (from !== to) {
                    const [moved] = batchFiles.splice(from, 1);
                    batchFiles.splice(to, 0, moved);
                    renderBatchThumbs();
                }
            });
            container.appendChild(wrap);
        });
    }
    obfFile.addEventListener('change', e => {
        const files = e.target.files;
        if (files.length > 1) {
            batchFiles = Array.from(files);
            document.getElementById('batch-info').classList.remove('hidden');
            document.getElementById('batch-count').textContent = batchFiles.length;
            renderBatchThumbs();
            const first = files[0];
            originalImageFile = first;
            uploadedImage.src = URL.createObjectURL(first);
            obfPreview.src = uploadedImage.src;
            obfDrop.querySelector('.drop-text').classList.add('hidden');
            obfPreview.classList.remove('hidden');
            uploadedImage.onload = () => { buildGallery(); updateSecurityScore(); };
        } else if (files.length === 1) {
            batchFiles = [];
            document.getElementById('batch-info').classList.add('hidden');
            document.getElementById('batch-thumbs').innerHTML = '';
            uploadedImage.onload = () => { buildGallery(); updateSecurityScore(); };
        }
    });

    // --- Override Obfuscate Button for Batch + Worker + Compare + History + Hash ---
    const origObfHandler = btnObfuscate.onclick;
    btnObfuscate.removeEventListener('click', () => {});
    // We need to replace the existing click handler
    const newObfuscateHandler = async () => {
        const filesToProcess = batchFiles.length > 1 ? batchFiles : (originalImageFile ? [originalImageFile] : []);
        if (!filesToProcess.length) return alert("Chargez une image d'abord.");
        const pwd = obfPwd.value;
        const sig = obfSig.value;
        const algo = algoSelect.value;
        const sigLoc = sigLocation?.value || 'meta';
        const glitchIntensity = parseInt(document.getElementById('glitch-slider')?.value || 100) / 100;
        const wmText = wmToggle?.checked ? document.getElementById('watermark-text')?.value : '';
        const wmMode = document.querySelector('input[name="wm-mode"]:checked')?.value || 'lsb';
        btnObfuscate.innerText = "Calculs..."; btnObfuscate.disabled = true;
        const batchProg = document.getElementById('batch-progress');
        const batchFill = document.getElementById('batch-progress-fill');
        const batchText = document.getElementById('batch-progress-text');
        if (filesToProcess.length > 1) batchProg.classList.remove('hidden');

        for (let fi = 0; fi < filesToProcess.length; fi++) {
            const file = filesToProcess[fi];
            if (filesToProcess.length > 1) {
                batchFill.style.width = ((fi / filesToProcess.length) * 100) + '%';
                batchText.textContent = `Image ${fi + 1} / ${filesToProcess.length}`;
            }
            try {
                const img = new Image();
                img.src = URL.createObjectURL(file);
                await new Promise(r => img.onload = r);
                const canvas = document.createElement('canvas');
                canvas.width = img.width; canvas.height = img.height;
                const ctx = canvas.getContext('2d', { willReadFrequently: true });
                ctx.drawImage(img, 0, 0);
                const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const isRobust = document.getElementById('robust-mode')?.checked;
                let internalSalt = crypto.randomUUID();
                if (isRobust && pwd) {
                    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pwd + "OBSCURE_FIXED_SALT_v1"));
                    internalSalt = Array.from(new Uint8Array(hash).slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
                }
                const seed = pwd ? pwd + internalSalt : 'public' + internalSalt;

                // Store original for comparison
                if (fi === 0) { compareOrigData = new Uint8Array(imgData.data); compareW = canvas.width; compareH = canvas.height; }

                // Apply algorithm (try worker first) — skip for 'none'
                if (algo !== 'none') {
                    try {
                        const result = await workerApply(algo, imgData.data.buffer.slice(0), canvas.width, canvas.height, seed, false, glitchIntensity);
                        imgData.data.set(result);
                    } catch(e) {
                        applyAlgorithm(imgData, canvas.width, canvas.height, algo, seed, false);
                    }
                }

                // Watermark (LSB or DCT)
                let activeWmText = wmText;
                let activeWmMode = wmMode;
                if (algo === 'dfws') {
                    activeWmText = `DIM:${imgData.width}:${imgData.height}:DFWS`;
                    activeWmMode = 'dct';
                }
                if (activeWmText) {
                    if (activeWmMode === 'dct') RobustWatermark.embed(imgData, activeWmText);
                    else embedWatermark(imgData, activeWmText);
                }

                let metadata = { v: 5, alg: algo, pwd: !!pwd, salt: internalSalt, mime: file.type };
                if (isRobust) metadata.robust = true;
                if (activeWmText) { metadata.wm = true; metadata.wmMode = activeWmMode; }

                let fileToEmbed = null;
                if (otherImageFile) fileToEmbed = otherImageFile;
                else if (embedOriginalCb.checked) fileToEmbed = file;
                if (fileToEmbed) {
                    const buf = await fileToEmbed.arrayBuffer();
                    const comp = await compressData(buf);
                    const shouldEncrypt = document.getElementById('stego-encrypt')?.checked && pwd;
                    let payload;
                    if (shouldEncrypt) {
                        const { encrypted, salt: pSalt, iv: pIv } = await encryptData(comp, pwd);
                        payload = { data: arrayBufferToBase64(encrypted), salt: pSalt ? arrayBufferToBase64(pSalt) : null, iv: pIv ? arrayBufferToBase64(pIv) : null, enc: true };
                    } else {
                        payload = { data: arrayBufferToBase64(comp), enc: false };
                    }
                    metadata.payload = { ...payload, mime: fileToEmbed.type || 'application/octet-stream', filename: fileToEmbed.name };
                }

                let sigPayload = null;
                if (sig) {
                    const comp = await compressData(new TextEncoder().encode(sig));
                    const { encrypted, salt: ss, iv: si } = await encryptData(comp, pwd);
                    sigPayload = { data: arrayBufferToBase64(encrypted), salt: ss ? arrayBufferToBase64(ss) : null, iv: si ? arrayBufferToBase64(si) : null };
                }
                if (sigPayload && sigLoc === 'lsb') { try { encodeLSB(imgData, new TextEncoder().encode("LSB_SIG:" + JSON.stringify(sigPayload))); } catch(e) { metadata.sig = sigPayload; } }
                else if (sigPayload) metadata.sig = sigPayload;

                // Store obfuscated for comparison
                if (fi === 0) { compareObfData = new Uint8Array(imgData.data); }

                ctx.putImageData(imgData, 0, 0);
                const exportFormat = document.getElementById('export-format')?.value || 'image/png';
                const exportQuality = exportFormat === 'image/jpeg' ? 0.92 : undefined;
                const visualBlob = await new Promise(r => canvas.toBlob(r, exportFormat, exportQuality));
                const tail = new TextEncoder().encode(JSON.stringify(metadata) + MAGIC_MARKER);
                const finalBlob = new Blob([visualBlob, tail], { type: exportFormat });

                // SHA-256
                if (fi === 0) {
                    const hash = await computeSHA256(finalBlob);
                    document.getElementById('hash-value').textContent = hash;
                    document.getElementById('integrity-hash').classList.remove('hidden');
                }

                const a = document.createElement('a');
                a.href = URL.createObjectURL(finalBlob);
                a.download = `obscurify_${Date.now()}_${fi}.${exportFormat.split('/')[1]}`;
                a.click(); URL.revokeObjectURL(a.href);

                // History
                try { await addHistory({ date: Date.now(), filename: file.name, algo, thumb: createThumb(img) }); } catch(e) {}

            } catch(e) { console.error(e); alert("Erreur: " + e.message); }
        }

        // Show comparison
        if (compareOrigData && compareObfData) {
            compareContainer.classList.remove('hidden');
            comparePos = 0.5;
            drawComparison();
        }

        batchProg.classList.add('hidden');
        btnObfuscate.innerText = "Offusquer & Télécharger";
        btnObfuscate.disabled = false;
        playSound('success');
        showToast(filesToProcess.length > 1 ? `${filesToProcess.length} images traitées !` : 'Image offusquée !', 'success');
        renderHistory();
    };

    // Replace the old handler
    btnObfuscate.replaceWith(btnObfuscate.cloneNode(true));
    const newBtn = document.getElementById('btn-obfuscate');
    newBtn.addEventListener('click', newObfuscateHandler);

    // Also update revert to extract watermark
    const oldRevertBtn = document.getElementById('btn-revert');
    const revertClone = oldRevertBtn.cloneNode(true);
    oldRevertBtn.replaceWith(revertClone);
    revertClone.addEventListener('click', async () => {
        if (!targetObfuscatedFile) return alert("Sélectionnez l'image.");
        revertClone.innerText = "Restauration..."; revertClone.disabled = true;
        revertResult.classList.add('hidden'); revertHiddenContainer.classList.add('hidden');
        revertSigContainer.classList.add('hidden');
        document.getElementById('revert-watermark-container')?.classList.add('hidden');
        try {
            const buf = await targetObfuscatedFile.arrayBuffer();
            const tailString = new TextDecoder().decode(buf.slice(Math.max(0, buf.byteLength - 1000000)));
            const magicIdx = tailString.lastIndexOf(MAGIC_MARKER);
            
            let meta, normalizedCanvas = null;
            if (magicIdx === -1) {
                // FALLBACK: Metadata lost (Crop/JPEG). Try to detect DFWS via Watermark
                const canvas = document.createElement('canvas');
                canvas.width = targetObfuscatedImage.width; canvas.height = targetObfuscatedImage.height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(targetObfuscatedImage, 0, 0);
                const wmDim = RobustWatermark.getDimensions(ctx.getImageData(0,0,canvas.width,canvas.height));
                if (wmDim && wmDim.w && wmDim.h) {
                    showToast(`🔍 Watermark détecté: DFWS (${wmDim.w}x${wmDim.h})`, "info");
                    meta = { v: 5, alg: 'dfws', pwd: false, robust: true, salt: 'public' };
                    normalizedCanvas = document.createElement('canvas');
                    normalizedCanvas.width = wmDim.w; normalizedCanvas.height = wmDim.h;
                    normalizedCanvas.getContext('2d').drawImage(targetObfuscatedImage, 0, 0, wmDim.w, wmDim.h);
                } else {
                    throw new Error("Métadonnées et Watermark absents. Image non reconnue.");
                }
            } else {
                const jsonStart = tailString.substring(0, magicIdx).lastIndexOf('{"v":5');
                if (jsonStart === -1) throw new Error("Métadonnées altérées.");
                meta = JSON.parse(tailString.substring(jsonStart, magicIdx));
                
                const canvas = document.createElement('canvas');
                canvas.width = targetObfuscatedImage.width; canvas.height = targetObfuscatedImage.height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(targetObfuscatedImage, 0, 0);
                const wmDim = RobustWatermark.getDimensions(ctx.getImageData(0,0,canvas.width,canvas.height));
                if (wmDim && (wmDim.w !== targetObfuscatedImage.width || wmDim.h !== targetObfuscatedImage.height)) {
                    showToast(`⚠️ Redimensionnement détecté. Restauration canonique (${wmDim.w}x${wmDim.h})...`, "warning");
                    normalizedCanvas = document.createElement('canvas');
                    normalizedCanvas.width = wmDim.w; normalizedCanvas.height = wmDim.h;
                    normalizedCanvas.getContext('2d').drawImage(targetObfuscatedImage, 0, 0, wmDim.w, wmDim.h);
                }
            }

            if (meta.pwd && !revPwd.value) {
                showToast("⚠️ Image protégée. Tentative sans mot de passe (résultat incorrect).", "info");
            }

            let saltToUse = meta.salt;
            if (meta.robust) {
                const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(revPwd.value + "OBSCURE_FIXED_SALT_v1"));
                saltToUse = Array.from(new Uint8Array(hash).slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
            }
            const seed = meta.pwd ? revPwd.value + saltToUse : 'public' + saltToUse;
            
            const canvas = normalizedCanvas || document.createElement('canvas');
            if (!normalizedCanvas) {
                canvas.width = targetObfuscatedImage.width; canvas.height = targetObfuscatedImage.height;
                canvas.getContext('2d').drawImage(targetObfuscatedImage, 0, 0);
            }
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            
            // Extract watermark before revert (try both modes)
            if (meta.wm) {
                let wm = null;
                try {
                    if (meta.wmMode === 'dct') wm = RobustWatermark.extract(imgData);
                    else wm = extractWatermark(imgData);
                } catch(e) { console.warn('WM extract primary fail:', e); }
                if (!wm) {
                    try { wm = meta.wmMode === 'dct' ? extractWatermark(imgData) : RobustWatermark.extract(imgData); }
                    catch(e) { console.warn('WM extract fallback fail:', e); }
                }
                if (wm) { 
                    let displayWm = wm;
                    if (wm.startsWith('DIM:')) {
                        const p = wm.split(':');
                        displayWm = `${p[3] || 'DFWS'} (${p[1]}x${p[2]})`;
                    }
                    document.getElementById('revert-watermark-text').textContent = displayWm; 
                    document.getElementById('revert-watermark-container').classList.remove('hidden'); 
                }
                else { document.getElementById('revert-watermark-text').textContent = '(non décodé — image altérée ?)'; document.getElementById('revert-watermark-container').classList.remove('hidden'); }
            }
            let sigPayload = meta.sig;
            const lsbBytes = decodeLSB(imgData);
            if (lsbBytes) { const t = new TextDecoder().decode(lsbBytes); if (t.startsWith("LSB_SIG:")) sigPayload = JSON.parse(t.substring(8)); }
            // Skip algo revert for 'none' (stego-only)
            if (meta.alg !== 'none') {
                try { const result = await workerApply(meta.alg, imgData.data.buffer.slice(0), canvas.width, canvas.height, seed, true, 1); imgData.data.set(result); }
                catch(e) { applyAlgorithm(imgData, canvas.width, canvas.height, meta.alg, seed, true); }
            }
            ctx.putImageData(imgData, 0, 0);
            const mathBlob = await new Promise(r => canvas.toBlob(r, meta.mime));
            if (currentMathObjectUrl) URL.revokeObjectURL(currentMathObjectUrl);
            currentMathObjectUrl = URL.createObjectURL(mathBlob);
            revertPreview.src = currentMathObjectUrl;
            revertResult.classList.remove('hidden');
            if (meta.payload) {
                try {
                    let original;
                    if (meta.payload.enc) {
                        const decComp = await decryptData(base64ToArrayBuffer(meta.payload.data), meta.pwd ? revPwd.value : null, meta.payload.salt ? base64ToArrayBuffer(meta.payload.salt) : null, meta.payload.iv ? base64ToArrayBuffer(meta.payload.iv) : null);
                        original = await decompressData(decComp);
                    } else {
                        original = await decompressData(base64ToArrayBuffer(meta.payload.data));
                    }
                    const blob = new Blob([original], { type: meta.payload.mime });
                    if (currentHiddenObjectUrl) URL.revokeObjectURL(currentHiddenObjectUrl);
                    currentHiddenObjectUrl = URL.createObjectURL(blob);
                    // If it's an image, show preview; otherwise show icon
                    if (meta.payload.mime && meta.payload.mime.startsWith('image/')) {
                        revertHiddenPreview.src = currentHiddenObjectUrl;
                    } else {
                        const extMap = {'application/pdf':'PDF','application/zip':'ZIP','application/vnd.openxmlformats-officedocument.wordprocessingml.document':'DOCX','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':'XLSX','application/vnd.openxmlformats-officedocument.presentationml.presentation':'PPTX','text/plain':'TXT','application/json':'JSON'};
                        const extLabel = extMap[meta.payload.mime] || meta.payload.mime.split('/')[1]?.toUpperCase() || 'FICHIER';
                        revertHiddenPreview.src = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 120"><rect width="200" height="120" rx="12" fill="%23334155"/><text x="100" y="55" text-anchor="middle" fill="%2394a3b8" font-size="40">\ud83d\udcc4</text><text x="100" y="90" text-anchor="middle" fill="%23e2e8f0" font-size="18">' + extLabel + '</text></svg>');
                    }
                    revertHiddenContainer.classList.remove('hidden');
                } catch(e) { console.warn('Payload extraction failed:', e); }
            }
            if (sigPayload) {
                try {
                    let text;
                    if (sigPayload.enc !== false) {
                        const decComp = await decryptData(base64ToArrayBuffer(sigPayload.data), meta.pwd ? revPwd.value : null, sigPayload.salt ? base64ToArrayBuffer(sigPayload.salt) : null, sigPayload.iv ? base64ToArrayBuffer(sigPayload.iv) : null);
                        text = new TextDecoder().decode(await decompressData(decComp));
                    } else {
                        text = new TextDecoder().decode(await decompressData(base64ToArrayBuffer(sigPayload.data)));
                    }
                    revertSigText.innerText = text;
                    revertSigContainer.classList.remove('hidden');
                } catch(e) {}
            }
            playSound('success');
        } catch(e) { console.error(e); alert("Erreur: " + e.message); playSound('error'); }
        revertClone.innerText = "Restaurer"; revertClone.disabled = false;
    });

    // --- BRUTE FORCE SCAN (Multi-Algo) ---
    document.getElementById('btn-brute-force')?.addEventListener('click', async () => {
        if (!targetObfuscatedFile) return alert("Sélectionnez l'image.");
        const btn = document.getElementById('btn-brute-force');
        btn.innerText = "Scan en cours..."; btn.disabled = true;
        showToast("🚀 Scan global lancé (21+ algorithmes)...", "info");
        
        try {
            const zip = new JSZip();
            const w = targetObfuscatedImage.width, h = targetObfuscatedImage.height;
            const pwd = revPwd.value;
            
            // Derive deterministic salt
            const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pwd + "OBSCURE_FIXED_SALT_v1"));
            const robustSalt = Array.from(new Uint8Array(hash).slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');

            // Extract watermark in case we can detect the right one
            const tempCanvas = document.createElement('canvas'); tempCanvas.width = w; tempCanvas.height = h;
            const tempCtx = tempCanvas.getContext('2d'); tempCtx.drawImage(targetObfuscatedImage, 0, 0);
            const wm = RobustWatermark.extract(tempCtx.getImageData(0,0,w,h));
            if (wm) zip.file("watermark_detected.txt", "Watermark extrait : " + wm);

            // Reversible algos from code (index 0 to 16)
            const reversibleAlgos = ['xor-shuffle','logistic-xor','cat-map','baker-map','affine-map','wave-shift','prime-scatter','rgb-shift','hilbert','spiral','zigzag','chirikov','henon','rubik','block-shuffle-8','block-shuffle-16','dfws'];
            const reversibleNames = ['XOR','Logistic','Cat Map','Baker','Affine','Wave','Prime','RGB','Hilbert','Spiral','Zigzag','Chirikov','Henon','Rubik','Bloc8x8','Bloc16x16','DFWS'];

            for (let i = 0; i < reversibleAlgos.length; i++) {
                const algo = reversibleAlgos[i];
                const name = reversibleNames[i];
                
                // Try two modes: Normal (random salt - unlikely to work if meta lost) and Robust (deterministic salt)
                const trials = [
                    { seed: 'public' + 'public', label: 'Public_NoPwd' },
                    { seed: (pwd || 'public') + 'public', label: 'Normal' },
                    { seed: (pwd || 'public') + robustSalt, label: 'Robust' }
                ];

                for (const trial of trials) {
                    const seed = trial.seed;
                    const canvas = document.createElement('canvas'); canvas.width = w; canvas.height = h;
                    const ctx = canvas.getContext('2d'); ctx.drawImage(targetObfuscatedImage, 0, 0);
                    const imgData = ctx.getImageData(0, 0, w, h);
                    
                    try {
                        const result = await workerApply(algo, imgData.data.buffer.slice(0), w, h, seed, true, 1);
                        imgData.data.set(result);
                    } catch(e) {
                        applyAlgorithm(imgData, w, h, algo, seed, true);
                    }
                    
                    ctx.putImageData(imgData, 0, 0);
                    const blob = await new Promise(r => canvas.toBlob(r, 'image/png'));
                    zip.file(`${name}_${trial.label}.png`, blob);
                }
            }

            const content = await zip.generateAsync({ type: "blob" });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(content);
            a.download = `obscurify_bruteforce_${Date.now()}.zip`;
            a.click();
            showToast("📦 ZIP généré avec tous les essais !", "success");
            playSound('success');
        } catch(e) {
            console.error(e);
            alert("Erreur brute-force: " + e.message);
        }
        btn.innerText = "🚀 Scan Multi-Algorithmes (Brute Force)"; btn.disabled = false;
    });

    // Download buttons need re-binding since we cloned
    document.getElementById('btn-download-math')?.addEventListener('click', () => { const a = document.createElement('a'); a.href = currentMathObjectUrl; a.download = `restored_${Date.now()}.png`; a.click(); });
    document.getElementById('btn-download-hidden')?.addEventListener('click', () => {
        const a = document.createElement('a');
        a.href = currentHiddenObjectUrl;
        // Detect extension from blob type
        const ext = currentHiddenObjectUrl ? 'bin' : 'png';
        fetch(currentHiddenObjectUrl).then(r => {
            const mime = r.headers.get('Content-Type') || 'application/octet-stream';
            const extensions = {'image/png':'png','image/jpeg':'jpg','image/webp':'webp','application/pdf':'pdf','application/zip':'zip','application/vnd.openxmlformats-officedocument.wordprocessingml.document':'docx','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':'xlsx','application/vnd.openxmlformats-officedocument.presentationml.presentation':'pptx','text/plain':'txt','application/json':'json'};
            a.download = `extracted_${Date.now()}.${extensions[mime] || mime.split('/')[1] || 'bin'}`;
            a.click();
        }).catch(() => { a.download = `extracted_${Date.now()}.bin`; a.click(); });
    });

    // --- File Preview for Share receiver ---
    function showFilePreview(blob, filename) {
        const el = document.getElementById('share-file-preview');
        if (!el) return;
        el.innerHTML = '';
        if (blob.type.startsWith('image/')) {
            const img = document.createElement('img');
            img.src = URL.createObjectURL(blob);
            img.style.cssText = 'max-width:100%;max-height:200px;border-radius:8px;';
            el.appendChild(img); el.classList.remove('hidden');
        } else if (blob.type.startsWith('text/')) {
            blob.text().then(t => { const pre = document.createElement('pre'); pre.style.cssText = 'padding:10px;font-size:0.75rem;color:var(--text-muted);white-space:pre-wrap;'; pre.textContent = t.substring(0, 2000); el.appendChild(pre); el.classList.remove('hidden'); });
        }
    }

    // --- Render history on tab switch ---
    tabs.forEach(t => t.addEventListener('click', () => { if (t.dataset.target === 'history-view') renderHistory(); }));

    // --- Drag between tabs: drag obfuscated output to share ---
    document.addEventListener('dragover', e => e.preventDefault());

    // --- Transfer Stats for P2P ---
    let transferStart = 0, transferBytes = 0, statInterval = null;
    function startTransferStats() {
        transferStart = Date.now(); transferBytes = 0;
        const statsEl = document.getElementById('share-stats');
        if (statsEl) statsEl.classList.remove('hidden');
        statInterval = setInterval(() => {
            const elapsed = (Date.now() - transferStart) / 1000;
            document.getElementById('stat-elapsed').textContent = Math.round(elapsed) + 's';
            document.getElementById('stat-speed').textContent = formatSize(transferBytes / Math.max(1, elapsed)) + '/s';
            document.getElementById('stat-sent').textContent = formatSize(transferBytes);
        }, 500);
    }
    function stopTransferStats() { if (statInterval) clearInterval(statInterval); }

    // --- Zoom/Pan on Preview ---
    (function initZoom() {
        const viewport = document.getElementById('zoom-viewport');
        const img = document.getElementById('obfuscate-preview');
        if (!viewport || !img) return;
        let scale = 1, panX = 0, panY = 0, isPanning = false, startX, startY;
        function applyTransform() { img.style.transform = `translate(${panX}px, ${panY}px) scale(${scale})`; }
        viewport.addEventListener('wheel', e => {
            if (!img.src || img.classList.contains('hidden') || !img.naturalWidth) return;
            e.preventDefault();
            const delta = e.deltaY > 0 ? -0.15 : 0.15;
            scale = Math.max(1, Math.min(8, scale + delta));
            if (scale <= 1) { panX = 0; panY = 0; }
            applyTransform();
        }, { passive: false });
        viewport.addEventListener('mousedown', e => {
            if (scale <= 1) return;
            isPanning = true; startX = e.clientX - panX; startY = e.clientY - panY;
            viewport.style.cursor = 'grabbing';
        });
        document.addEventListener('mousemove', e => {
            if (!isPanning) return;
            panX = e.clientX - startX; panY = e.clientY - startY;
            applyTransform();
        });
        document.addEventListener('mouseup', () => { isPanning = false; viewport.style.cursor = scale > 1 ? 'grab' : ''; });
        viewport.addEventListener('dblclick', () => { scale = 1; panX = 0; panY = 0; applyTransform(); });
        // Reset zoom when new image loaded
        const observer = new MutationObserver(() => { scale = 1; panX = 0; panY = 0; applyTransform(); });
        observer.observe(img, { attributes: true, attributeFilter: ['src'] });
    })();

    // Init history render
    renderHistory();
    console.log('✅ Obscurify v3.0 — All features loaded');
});
