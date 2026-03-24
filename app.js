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
        else if (algo === 'quantize-shuffle') applyQuantizeShuffle(imgData, width, height, prng, reverse);
        else if (algo === 'color-crush') applyColorCrush(imgData, width, height, prng, reverse);
        else if (algo === 'blur-noise') applyBlurNoise(imgData, width, height, prng, reverse);
        else if (algo === 'salt-pepper') applySaltPepper(imgData, width, height, prng, reverse);
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
});
