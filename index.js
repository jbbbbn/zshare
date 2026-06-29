#!/usr/bin/env node
/**
 * @fileoverview zshare — Zero-Config Encrypted Local P2P Transfer
 * @version      2.0.0
 * @license      MIT
 *
 * A CLI tool that creates an encrypted peer-to-peer channel over your local
 * network for transferring text AND binary files between devices. Uses WebRTC
 * DataChannels for direct device-to-device transfers and a 100% pure-JS
 * SHA256-CTR stream cipher for end-to-end encryption — no cloud, no accounts,
 * no setup on the receiving device.
 *
 * ┌─ SEND mode ─────────────────────────────────────────────────────────────┐
 * │  1. Detect payload (text string or file path)                           │
 * │  2. Encrypt with SHA256-CTR + embed in HTML <script> as JSON literal   │
 * │  3. Serve over HTTP; receiver scans QR → page auto-decrypts instantly  │
 * │  4. WebRTC DataChannel opens for status reporting                       │
 * └─────────────────────────────────────────────────────────────────────────┘
 * ┌─ RECV mode ─────────────────────────────────────────────────────────────┐
 * │  1. Serve a mobile upload UI (text textarea + file picker)              │
 * │  2. Phone connects → WebRTC DataChannel established over LAN            │
 * │  3. Phone encrypts payload and sends in 32 KB chunks                   │
 * │  4. PC reassembles chunks, decrypts, verifies SHA-256, saves/prints    │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * @example
 *   node index.js send "Hello from PC"   // Share text
 *   node index.js send ./report.pdf      // Share a file (max 20 MB)
 *   node index.js recv                   // Receive text or files from phone
 */

import os   from 'os';
import fs   from 'fs';
import path from 'path';
import http from 'http';
import { WebSocketServer } from 'ws';
import qrcode from 'qrcode-terminal';
import { RTCPeerConnection } from 'werift';


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1 · PURE-JS CRYPTOGRAPHIC ENGINE (SHA256-CTR)
//
// All crypto is implemented in vanilla JS with zero external dependencies.
// This is essential because window.crypto.subtle is blocked by modern browsers
// in non-HTTPS "insecure" contexts (which includes local-network HTTP).
//
// ┌─ Cipher construction ───────────────────────────────────────────────────┐
// │  Key derivation:  K = SHA-256(passcode)              [32 bytes]         │
// │  Keystream block: B_i = SHA-256(K ‖ IV ‖ counter_i) [32 bytes each]   │
// │  Stream cipher:   C_i = P_i XOR B_i  (symmetric — same for decrypt)   │
// │  Integrity:       SHA-256(plaintext or raw file bytes) stored in        │
// │                   the encrypted envelope, verified after decryption.   │
// └─────────────────────────────────────────────────────────────────────────┘
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Performs a 32-bit unsigned right rotation — a fundamental SHA-256 primitive.
 *
 * @param {number} value  - 32-bit integer to rotate
 * @param {number} amount - Bit positions to rotate rightward
 * @returns {number} Rotated value (unsigned 32-bit)
 */
function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
}

/**
 * Computes the SHA-256 hash of an arbitrary byte sequence.
 *
 * Implements the full FIPS 180-4 specification:
 *   1. Message padding: append 0x80, then zero-pad to length ≡ 56 (mod 64)
 *   2. Append original bit-length as a 64-bit big-endian integer
 *   3. Process each 512-bit chunk through 64 compression rounds
 *   4. Output: 256-bit digest concatenated from 8 × 32-bit hash words
 *
 * @param {Uint8Array|Array<number>} bytes - Input bytes to hash
 * @returns {string} 64-character lowercase hex digest
 */
function sha256Bytes(bytes) {
    // Round constants: first 32 bits of fractional parts of cube roots of primes 2..311
    const K = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];

    // Initial hash state: first 32 bits of fractional parts of square roots of primes 2..19
    const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

    // Normalise to Uint8Array so .set() is available
    const b   = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const len = b.length;

    // ── Pre-processing: pad message to (length ≡ 56 mod 64) bytes ─────────────
    const pad = [0x80]; // Append the single '1' bit
    while ((len + pad.length + 8) % 64 !== 0) pad.push(0x00);

    const msg = new Uint8Array(len + pad.length + 8);
    msg.set(b, 0);
    msg.set(pad, len);

    // Append original bit-count as 64-bit big-endian integer (last 8 bytes)
    const bits = len * 8;
    const L    = msg.length;
    msg[L-8]=Math.floor(bits/0x100000000000000)&0xff; msg[L-7]=Math.floor(bits/0x1000000000000)&0xff;
    msg[L-6]=Math.floor(bits/0x10000000000)&0xff;     msg[L-5]=Math.floor(bits/0x100000000)&0xff;
    msg[L-4]=(bits>>>24)&0xff; msg[L-3]=(bits>>>16)&0xff; msg[L-2]=(bits>>>8)&0xff; msg[L-1]=bits&0xff;

    // ── Compression: process each 64-byte chunk ────────────────────────────────
    const W = new Array(64);
    for (let i = 0; i < msg.length; i += 64) {
        // Load current hash state into working variables
        let a=H[0],bb=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];

        for (let t = 0; t < 64; t++) {
            if (t < 16) {
                // Load 4 bytes as a big-endian 32-bit word into message schedule
                const j = i + t * 4;
                W[t] = (msg[j]<<24)|(msg[j+1]<<16)|(msg[j+2]<<8)|msg[j+3];
            } else {
                // Expand message schedule via σ0 and σ1 functions
                const s0 = (rightRotate(W[t-15],7) ^ rightRotate(W[t-15],18) ^ (W[t-15]>>>3)) | 0;
                const s1 = (rightRotate(W[t-2],17)  ^ rightRotate(W[t-2],19)  ^ (W[t-2]>>>10)) | 0;
                W[t] = (W[t-16] + s0 + W[t-7] + s1) | 0;
            }

            // SHA-256 round: T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
            const T1 = (h + (rightRotate(e,6)^rightRotate(e,11)^rightRotate(e,25))
                          + ((e&f)^(~e&g)) + K[t] + W[t]) | 0;
            // T2 = Σ0(a) + Maj(a,b,c)
            const T2 = ((rightRotate(a,2)^rightRotate(a,13)^rightRotate(a,22))
                          + ((a&bb)^(a&c)^(bb&c))) | 0;

            h=g; g=f; f=e; e=(d+T1)|0; d=c; c=bb; bb=a; a=(T1+T2)|0;
        }

        // Accumulate compressed chunk into running hash state
        H[0]=(H[0]+a)|0;  H[1]=(H[1]+bb)|0; H[2]=(H[2]+c)|0;  H[3]=(H[3]+d)|0;
        H[4]=(H[4]+e)|0;  H[5]=(H[5]+f)|0;  H[6]=(H[6]+g)|0;  H[7]=(H[7]+h)|0;
    }

    // Concatenate 8 × 32-bit words → 64-char hex digest
    return H.map(v => ('00000000'+(v>>>0).toString(16)).slice(-8)).join('');
}

/**
 * Encodes a JavaScript string to UTF-8 bytes, handling the full Unicode range
 * including surrogate pairs (emoji, CJK ideographs, etc.).
 *
 * @param {string} str - Input string to encode
 * @returns {Uint8Array} UTF-8 encoded byte array
 */
function stringToUtf8(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
        let cp = str.charCodeAt(i);
        if      (cp < 0x80)                   { out.push(cp); }
        else if (cp < 0x800)                  { out.push(0xc0|(cp>>6), 0x80|(cp&0x3f)); }
        else if (cp < 0xd800 || cp >= 0xe000) { out.push(0xe0|(cp>>12), 0x80|((cp>>6)&0x3f), 0x80|(cp&0x3f)); }
        else {
            // Surrogate pair: combine high (cp) + low surrogate into a single code point
            i++;
            cp = 0x10000 + (((cp & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
            out.push(0xf0|(cp>>18), 0x80|((cp>>12)&0x3f), 0x80|((cp>>6)&0x3f), 0x80|(cp&0x3f));
        }
    }
    return new Uint8Array(out);
}

/**
 * Decodes a UTF-8 byte array back to a JavaScript string.
 *
 * @param {Uint8Array|Array<number>} bytes - UTF-8 encoded bytes
 * @returns {string} Decoded JavaScript string
 */
function utf8ToString(bytes) {
    let out = '', i = 0;
    while (i < bytes.length) {
        const c = bytes[i++];
        if      (c < 128)            { out += String.fromCharCode(c); }
        else if (c > 191 && c < 224) { out += String.fromCharCode(((c&31)<<6)|(bytes[i++]&63)); }
        else if (c > 223 && c < 240) { out += String.fromCharCode(((c&15)<<12)|((bytes[i++]&63)<<6)|(bytes[i++]&63)); }
        else {
            // 4-byte sequence → surrogate pair
            let v = ((c&7)<<18)|((bytes[i++]&63)<<12)|((bytes[i++]&63)<<6)|(bytes[i++]&63);
            v -= 0x10000;
            out += String.fromCharCode(0xd800|(v>>10), 0xdc00|(v&0x3ff));
        }
    }
    return out;
}

/**
 * Computes SHA-256 of a JavaScript string by first encoding it to UTF-8.
 * Delegates to sha256Bytes() for the actual hash computation.
 *
 * @param {string} text - Input string
 * @returns {string} 64-character hex SHA-256 digest
 */
function sha256(text) { return sha256Bytes(stringToUtf8(text)); }

/**
 * Converts a lowercase hex string to a Uint8Array of bytes.
 *
 * @param {string} hex - Even-length hex string (e.g. "ff0a3c")
 * @returns {Uint8Array} Decoded byte array
 */
function hexToBytes(hex) {
    const bytes = [];
    for (let c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
    return new Uint8Array(bytes);
}

/**
 * Converts a Uint8Array (or plain number array) to a lowercase hex string.
 *
 * @param {Uint8Array|Array<number>} bytes - Input bytes
 * @returns {string} Lowercase hex string
 */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => ('00'+b.toString(16)).slice(-2)).join('');
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2 · SHA256-CTR STREAM CIPHER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * SHA256-CTR stream cipher — used for both encryption AND decryption.
 *
 * Because XOR is its own inverse, a single call with the correct key and IV
 * recovers the original plaintext from ciphertext (and vice versa).
 *
 * Keystream per 32-byte block i:
 *   B_i = SHA-256( key[32B] ‖ IV[12B] ‖ counter_i[4B, big-endian] )
 *
 * @param {Uint8Array|string} payload  - Bytes or string to encrypt/decrypt
 * @param {string}            passcode - User passcode; key derived via SHA-256(passcode)
 * @param {string}            [ivHex]  - 12-byte IV as hex (provide for decryption; omit to generate)
 * @returns {{ iv: string, ciphertext: string }} IV and result, both as hex strings
 */
function cryptSHA256CTR(payload, passcode, ivHex) {
    // Derive 256-bit symmetric key from the passcode
    const keyBytes = hexToBytes(sha256(passcode));

    // Use the provided IV (decryption) or generate a fresh random one (encryption)
    let ivBytes;
    if (ivHex) {
        ivBytes = hexToBytes(ivHex);
    } else {
        ivBytes = new Uint8Array(12);
        for (let i = 0; i < 12; i++) ivBytes[i] = Math.floor(Math.random() * 256);
    }

    // Accept both string and binary (Uint8Array) payloads
    const inputBytes  = typeof payload === 'string' ? stringToUtf8(payload) : payload;
    const outputBytes = new Uint8Array(inputBytes.length);

    // XOR each byte with the next keystream byte, refilling blocks as needed
    let blockCounter = 0;
    let ksBlock = new Uint8Array(0); // Current 32-byte keystream block
    let ksPos   = 0;                  // Position within current block

    for (let i = 0; i < inputBytes.length; i++) {
        if (ksPos >= ksBlock.length) {
            // Build block input: key[32] ‖ IV[12] ‖ counter[4]
            const ctr = [(blockCounter>>>24)&0xff, (blockCounter>>>16)&0xff,
                         (blockCounter>>>8)&0xff,   blockCounter&0xff];
            const blockIn = new Uint8Array([...keyBytes, ...ivBytes, ...ctr]);
            ksBlock = hexToBytes(sha256Bytes(blockIn));
            ksPos = 0;
            blockCounter++;
        }
        outputBytes[i] = inputBytes[i] ^ ksBlock[ksPos++]; // XOR with keystream byte
    }

    return { iv: bytesToHex(ivBytes), ciphertext: bytesToHex(outputBytes) };
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3 · HIGH-LEVEL ENCRYPT / DECRYPT API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encrypts a text string and wraps it in a portable JSON envelope.
 *
 * Envelope schema:
 *   { type: "text", iv, ciphertext, sha256 }
 *   - iv:         Random 12-byte IV (hex)
 *   - ciphertext: Encrypted UTF-8 bytes of plaintext (hex)
 *   - sha256:     SHA-256 of original plaintext; used for post-decrypt verification
 *
 * @param {string} plaintext - Text to encrypt
 * @param {string} passcode  - Shared session passcode
 * @returns {string} JSON envelope string
 */
function encryptText(plaintext, passcode) {
    const hash = sha256(plaintext);
    const enc  = cryptSHA256CTR(plaintext, passcode);
    return JSON.stringify({ type: 'text', iv: enc.iv, ciphertext: enc.ciphertext, sha256: hash });
}

/**
 * Encrypts a binary file buffer and wraps it in a portable JSON envelope.
 * Includes file metadata (name, MIME type, byte count) so the receiver can
 * restore the original file with correct name and type.
 *
 * Envelope schema:
 *   { type: "file", filename, mimeType, originalSize, iv, ciphertext, sha256 }
 *
 * @param {Buffer}  fileBuffer - Raw file bytes (Node.js Buffer)
 * @param {string}  filename   - Original filename to restore on the receiver side
 * @param {string}  mimeType   - MIME type (e.g. "image/jpeg") for browser download
 * @param {string}  passcode   - Shared session passcode
 * @returns {string} JSON envelope string
 */
function encryptFile(fileBuffer, filename, mimeType, passcode) {
    const fileBytes = new Uint8Array(fileBuffer);
    const hash      = sha256Bytes(fileBytes); // Hash of raw bytes before encryption
    const enc       = cryptSHA256CTR(fileBytes, passcode);
    return JSON.stringify({
        type: 'file', filename, mimeType,
        originalSize: fileBytes.length,
        iv: enc.iv, ciphertext: enc.ciphertext, sha256: hash
    });
}

/**
 * Decrypts a text envelope created by encryptText(), verifying SHA-256 integrity.
 *
 * @param {string} encryptedJsonStr - JSON envelope from encryptText()
 * @param {string} passcode         - Session passcode (must match encryption passcode)
 * @returns {string} Original plaintext
 * @throws {Error} If integrity check fails (wrong passcode or data tampered)
 */
function decryptText(encryptedJsonStr, passcode) {
    const { iv, ciphertext, sha256: expected } = JSON.parse(encryptedJsonStr);
    const result    = cryptSHA256CTR(hexToBytes(ciphertext), passcode, iv);
    const plaintext = utf8ToString(hexToBytes(result.ciphertext));
    if (sha256(plaintext) !== expected)
        throw new Error('Integrity check failed: SHA-256 mismatch — wrong passcode or data tampered.');
    return plaintext;
}

/**
 * Decrypts a file envelope created by encryptFile(), verifying SHA-256 integrity.
 *
 * @param {string} encryptedJsonStr - JSON envelope from encryptFile()
 * @param {string} passcode         - Session passcode (must match encryption passcode)
 * @returns {Buffer} Decrypted file bytes ready to write to disk with fs.writeFileSync
 * @throws {Error} If integrity check fails (wrong passcode or file data tampered)
 */
function decryptFile(encryptedJsonStr, passcode) {
    const { iv, ciphertext, sha256: expected } = JSON.parse(encryptedJsonStr);
    const result         = cryptSHA256CTR(hexToBytes(ciphertext), passcode, iv);
    const decryptedBytes = hexToBytes(result.ciphertext);
    if (sha256Bytes(new Uint8Array(decryptedBytes)) !== expected)
        throw new Error('File integrity check failed: SHA-256 mismatch — wrong passcode or file tampered.');
    return Buffer.from(decryptedBytes);
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4 · UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * No hard file size limit is enforced. Large files will produce proportionally
 * large HTML pages (2× the file size as hex), but modern browsers handle this well.
 * The practical limit is available RAM on both sender and receiver devices.
 */

/**
 * Generates a human-readable session passcode in the format "zsh-xxxxxx",
 * where the suffix is 6 lowercase alphanumeric characters.
 * This passcode is both shown in the terminal and embedded in the QR URL.
 *
 * @returns {string} Passcode, e.g. "zsh-k8f2n1"
 */
function generatePasscode() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let code = 'zsh-';
    for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
    return code;
}

/**
 * Detects whether a CLI argument is an existing local file path or a raw text string.
 * Resolves the path, stats it, and reads extension-based metadata on success.
 *
 * @param {string} arg - Raw CLI argument (e.g. "./file.pdf" or "Hello world")
 * @returns {{ type: 'file', path, filename, mimeType, size }
 *          | { type: 'text' }}
 */
function detectPayload(arg) {
    try {
        const resolved = path.resolve(arg);
        const stat     = fs.statSync(resolved);
        if (stat.isFile()) {
            const ext = path.extname(resolved).toLowerCase();
            return {
                type: 'file',
                path: resolved,
                filename: path.basename(resolved),
                mimeType: getMimeType(ext),
                size: stat.size
            };
        }
    } catch (_) { /* not a valid file path — treat as raw text */ }
    return { type: 'text' };
}

/**
 * Returns the MIME type string for a given file extension.
 * Covers the most common document, media, code, and archive formats.
 * Falls back to 'application/octet-stream' for unknown extensions.
 *
 * @param {string} ext - Extension including the dot (e.g. ".pdf")
 * @returns {string} MIME type string
 */
function getMimeType(ext) {
    const map = {
        // Images
        '.jpg':'image/jpeg',   '.jpeg':'image/jpeg',  '.png':'image/png',
        '.gif':'image/gif',    '.webp':'image/webp',  '.svg':'image/svg+xml',
        '.ico':'image/x-icon', '.bmp':'image/bmp',
        // Documents
        '.pdf':'application/pdf',
        '.doc':'application/msword',
        '.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.xls':'application/vnd.ms-excel',
        '.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        '.ppt':'application/vnd.ms-powerpoint',
        '.pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        // Text & Code
        '.txt':'text/plain',  '.md':'text/markdown', '.csv':'text/csv',
        '.json':'application/json', '.xml':'application/xml', '.yaml':'text/yaml',
        '.html':'text/html',  '.css':'text/css',
        '.js':'application/javascript', '.ts':'application/typescript',
        '.py':'text/x-python', '.sh':'application/x-sh',
        // Archives
        '.zip':'application/zip', '.tar':'application/x-tar',
        '.gz':'application/gzip', '.rar':'application/vnd.rar',
        '.7z':'application/x-7z-compressed',
        // Audio
        '.mp3':'audio/mpeg', '.wav':'audio/wav', '.ogg':'audio/ogg', '.flac':'audio/flac',
        // Video
        '.mp4':'video/mp4', '.mov':'video/quicktime', '.avi':'video/x-msvideo',
        '.mkv':'video/x-matroska', '.webm':'video/webm'
    };
    return map[ext] || 'application/octet-stream';
}

/**
 * Formats a byte count as a human-readable size string.
 *
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted string (e.g. "4.2 MB", "800 KB", "23 B")
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const units = ['B','KB','MB','GB'];
    const i     = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
}

/**
 * Returns the first non-loopback IPv4 address found on the local machine.
 * Used to construct the share URL that remote devices on the same LAN can reach.
 *
 * @returns {string} Local IPv4 address (e.g. "192.168.1.42"), or "127.0.0.1" as fallback
 */
function getLocalIP() {
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
        for (const iface of ifaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) return iface.address;
        }
    }
    return '127.0.0.1';
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 5 · BROWSER CRYPTO BUNDLE
//
// This string is injected verbatim into the <script> tag of every HTML page
// served to connecting devices. It mirrors Sections 1-3 in ES5-compatible
// syntax (no arrow functions, no const/let in some paths, NO backtick literals,
// NO ${...} interpolations) so it can safely nest inside a Node.js template
// literal string without escaping issues.
// ═══════════════════════════════════════════════════════════════════════════════

const CRYPTO_HELPERS_JS = `
/* ── SHA-256 ──────────────────────────────────────────────────────────────── */
function _rr(v,n){return(v>>>n)|(v<<(32-n));}
function sha256Bytes(bytes){
    var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
           0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
           0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
           0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
           0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
           0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
           0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
           0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var b=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
    var len=b.length,pad=[0x80];
    while((len+pad.length+8)%64!==0)pad.push(0);
    var msg=new Uint8Array(len+pad.length+8);
    msg.set(b,0);msg.set(pad,len);
    var bits=len*8,L=msg.length;
    msg[L-8]=Math.floor(bits/0x100000000000000)&0xff;msg[L-7]=Math.floor(bits/0x1000000000000)&0xff;
    msg[L-6]=Math.floor(bits/0x10000000000)&0xff;msg[L-5]=Math.floor(bits/0x100000000)&0xff;
    msg[L-4]=(bits>>>24)&0xff;msg[L-3]=(bits>>>16)&0xff;msg[L-2]=(bits>>>8)&0xff;msg[L-1]=bits&0xff;
    var W=new Array(64);
    for(var i=0;i<msg.length;i+=64){
        var a=H[0],bb=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
        for(var t=0;t<64;t++){
            if(t<16){var j=i+t*4;W[t]=(msg[j]<<24)|(msg[j+1]<<16)|(msg[j+2]<<8)|msg[j+3];}
            else{var s0=(_rr(W[t-15],7)^_rr(W[t-15],18)^(W[t-15]>>>3))|0;
                 var s1=(_rr(W[t-2],17)^_rr(W[t-2],19)^(W[t-2]>>>10))|0;W[t]=(W[t-16]+s0+W[t-7]+s1)|0;}
            var T1=(h+(_rr(e,6)^_rr(e,11)^_rr(e,25))+((e&f)^(~e&g))+K[t]+W[t])|0;
            var T2=((_rr(a,2)^_rr(a,13)^_rr(a,22))+((a&bb)^(a&c)^(bb&c)))|0;
            h=g;g=f;f=e;e=(d+T1)|0;d=c;c=bb;bb=a;a=(T1+T2)|0;
        }
        H[0]=(H[0]+a)|0;H[1]=(H[1]+bb)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;
        H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
    }
    return H.map(function(v){return('00000000'+((v>>>0).toString(16))).slice(-8);}).join('');
}
/* ── Encoding helpers ─────────────────────────────────────────────────────── */
function stringToUtf8(str){
    var out=[];
    for(var i=0;i<str.length;i++){
        var cp=str.charCodeAt(i);
        if(cp<0x80)out.push(cp);
        else if(cp<0x800)out.push(0xc0|(cp>>6),0x80|(cp&0x3f));
        else if(cp<0xd800||cp>=0xe000)out.push(0xe0|(cp>>12),0x80|((cp>>6)&0x3f),0x80|(cp&0x3f));
        else{i++;cp=0x10000+(((cp&0x3ff)<<10)|(str.charCodeAt(i)&0x3ff));
             out.push(0xf0|(cp>>18),0x80|((cp>>12)&0x3f),0x80|((cp>>6)&0x3f),0x80|(cp&0x3f));}
    }return new Uint8Array(out);
}
function utf8ToString(bytes){
    var out='',i=0;
    while(i<bytes.length){
        var c=bytes[i++];
        if(c<128)out+=String.fromCharCode(c);
        else if(c>191&&c<224)out+=String.fromCharCode(((c&31)<<6)|(bytes[i++]&63));
        else if(c>223&&c<240)out+=String.fromCharCode(((c&15)<<12)|((bytes[i++]&63)<<6)|(bytes[i++]&63));
        else{var v=((c&7)<<18)|((bytes[i++]&63)<<12)|((bytes[i++]&63)<<6)|(bytes[i++]&63);
             v-=0x10000;out+=String.fromCharCode(0xd800|(v>>10),0xdc00|(v&0x3ff));}
    }return out;
}
function sha256(text){return sha256Bytes(stringToUtf8(text));}
function hexToBytes(hex){var b=[];for(var c=0;c<hex.length;c+=2)b.push(parseInt(hex.substr(c,2),16));return new Uint8Array(b);}
function bytesToHex(bytes){return Array.from(bytes).map(function(b){return('00'+b.toString(16)).slice(-2);}).join('');}
function formatBytes(n){if(n===0)return'0 B';var u=['B','KB','MB','GB'];var i=Math.min(Math.floor(Math.log(n)/Math.log(1024)),u.length-1);return(n/Math.pow(1024,i)).toFixed(i>0?1:0)+' '+u[i];}
function getFileEmoji(t){if(!t)return'📁';if(t.startsWith('image/'))return'🖼';if(t.startsWith('video/'))return'🎬';if(t.startsWith('audio/'))return'🎵';if(t==='application/pdf')return'📄';if(t.includes('zip')||t.includes('tar')||t.includes('rar')||t.includes('gzip'))return'📦';if(t.startsWith('text/'))return'📃';return'📁';}

/* ── SHA256-CTR cipher ────────────────────────────────────────────────────── */
function cryptSHA256CTR(payload,passcode,ivHex){
    var keyBytes=hexToBytes(sha256(passcode));
    var ivBytes;
    if(ivHex){ivBytes=hexToBytes(ivHex);}
    else{ivBytes=new Uint8Array(12);for(var k=0;k<12;k++)ivBytes[k]=Math.floor(Math.random()*256);}
    var inputBytes=(typeof payload==='string')?stringToUtf8(payload):payload;
    var outputBytes=new Uint8Array(inputBytes.length);
    var bc=0,ksBlock=[],ksPos=0;
    for(var i=0;i<inputBytes.length;i++){
        if(ksPos>=ksBlock.length){
            var ctr=[(bc>>>24)&0xff,(bc>>>16)&0xff,(bc>>>8)&0xff,bc&0xff];
            var inp=new Uint8Array(keyBytes.length+ivBytes.length+ctr.length);
            inp.set(keyBytes,0);inp.set(ivBytes,keyBytes.length);inp.set(ctr,keyBytes.length+ivBytes.length);
            ksBlock=hexToBytes(sha256Bytes(inp));ksPos=0;bc++;
        }
        outputBytes[i]=inputBytes[i]^ksBlock[ksPos++];
    }
    return{iv:bytesToHex(ivBytes),ciphertext:bytesToHex(outputBytes)};
}
/* ── High-level encrypt / decrypt ─────────────────────────────────────────── */
function encryptText(pt,pc){
    var h=sha256(pt),enc=cryptSHA256CTR(pt,pc);
    return JSON.stringify({type:'text',iv:enc.iv,ciphertext:enc.ciphertext,sha256:h});
}
function encryptFilePayload(bytes,filename,mimeType,size,pc){
    var h=sha256Bytes(bytes),enc=cryptSHA256CTR(bytes,pc);
    return JSON.stringify({type:'file',filename:filename,mimeType:mimeType,
                           originalSize:size,iv:enc.iv,ciphertext:enc.ciphertext,sha256:h});
}
/* Unified decrypt → {type:'text',content} or {type:'file',filename,mimeType,originalSize,bytes} */
function decryptPayload(jsonStr,passcode){
    var meta=JSON.parse(jsonStr);
    var res=cryptSHA256CTR(hexToBytes(meta.ciphertext),passcode,meta.iv);
    var dec=hexToBytes(res.ciphertext);
    if(sha256Bytes(dec)!==meta.sha256)throw new Error('Decryption failed: wrong key or data tampered.');
    if((meta.type||'text')==='file')
        return{type:'file',filename:meta.filename,mimeType:meta.mimeType,
               originalSize:meta.originalSize,bytes:dec};
    return{type:'text',content:utf8ToString(dec)};
}
`;


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 6 · HTML PAGE BUILDERS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Builds the full HTML page served to a receiving device in SEND mode.
 *
 * The page uses a Neon Cyber aesthetic (deep black + electric cyan/lime accents,
 * animated grid background, glassmorphic card). The encrypted payload is embedded
 * as a JSON literal in the <script> block and decrypted entirely client-side
 * using the passcode extracted from the URL query string.
 *
 * Features:
 *  - Auto-decrypts on load when `?key=` is present in the URL
 *  - Lock screen with manual key entry for cases where the key is missing
 *  - Text mode: scrollable text box + one-tap copy button
 *  - File mode: file card with emoji icon + filename + size + download button
 *  - SHA-256 integrity badge shown after successful decryption
 *  - WebSocket connection for live status indicator (non-blocking)
 *
 * @param {string} encryptedPayload - JSON envelope from encryptText() or encryptFile()
 * @param {string} passcode         - Session passcode (embedded in the QR URL as ?key=)
 * @returns {string} Complete HTML document string
 */
function buildReceiverPage(encryptedPayload, passcode) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="description" content="zshare encrypted payload receiver — tap to decrypt and view your shared content.">
    <title>zshare // Secure Transfer</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        /* ── Reset & base ──────────────────────────────────────────────────── */
        *{box-sizing:border-box;margin:0;padding:0;}
        :root{
            --bg:#020408; --cyan:#00ffcc; --lime:#a3ff00; --amber:#ff9500;
            --card-bg:rgba(0,12,18,0.9); --card-border:rgba(0,255,204,0.18);
            --text-1:#d4fff5; --text-2:#6ab8a8;
        }
        html,body{height:100%;}
        body{
            font-family:'Space Grotesk',sans-serif;
            background:var(--bg); color:var(--text-1);
            min-height:100vh; display:flex; justify-content:center;
            align-items:center; overflow:hidden; position:relative;
        }

        /* ── Animated background ───────────────────────────────────────────── */
        .bg-grid{
            position:fixed;inset:0;z-index:0;
            background-image:linear-gradient(rgba(0,255,204,0.04)1px,transparent 1px),
                             linear-gradient(90deg,rgba(0,255,204,0.04)1px,transparent 1px);
            background-size:44px 44px;
            animation:grid-scroll 25s linear infinite;
        }
        @keyframes grid-scroll{0%{transform:translateY(0);}100%{transform:translateY(44px);}}

        .orb{position:fixed;border-radius:50%;filter:blur(110px);opacity:0.14;z-index:0;
             animation:orb-drift 18s ease-in-out infinite alternate;}
        .orb-a{width:500px;height:500px;background:radial-gradient(circle,#00ffcc,transparent);
               top:-120px;left:-80px;animation-delay:0s;}
        .orb-b{width:420px;height:420px;background:radial-gradient(circle,#a3ff00,transparent);
               bottom:-100px;right:-80px;animation-delay:-9s;}
        @keyframes orb-drift{
            0%{transform:translate(0,0) scale(1);}
            50%{transform:translate(50px,-40px) scale(1.08);}
            100%{transform:translate(-20px,55px) scale(0.92);}
        }

        /* ── Glass card ────────────────────────────────────────────────────── */
        .card{
            position:relative;z-index:2;
            background:var(--card-bg);
            border:1px solid var(--card-border);
            border-radius:24px;padding:2.4rem 2.2rem;
            width:92%;max-width:460px;
            box-shadow:0 0 50px rgba(0,255,204,0.07),0 24px 60px rgba(0,0,0,0.55);
            backdrop-filter:blur(24px) saturate(180%);
            -webkit-backdrop-filter:blur(24px) saturate(180%);
            overflow:hidden;
            animation:card-in 0.65s cubic-bezier(0.16,1,0.3,1) both;
        }
        @keyframes card-in{from{opacity:0;transform:translateY(28px) scale(0.96);}to{opacity:1;transform:none;}}
        /* Scan-line sweep */
        .card::after{content:'';position:absolute;top:-40%;left:0;right:0;height:40%;
            background:linear-gradient(transparent,rgba(0,255,204,0.025),transparent);
            animation:scan 7s linear infinite;pointer-events:none;}
        @keyframes scan{0%{top:-40%;}100%{top:140%;}}

        /* ── Brand header ──────────────────────────────────────────────────── */
        .header{text-align:center;margin-bottom:1.6rem;}
        .brand{font-size:2.2rem;font-weight:700;letter-spacing:-1px;
               background:linear-gradient(135deg,#00ffcc 0%,#a3ff00 100%);
               -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
        .brand-sub{font-size:0.65rem;letter-spacing:5px;text-transform:uppercase;
                   color:var(--text-2);margin-top:3px;}

        /* ── Status pill ───────────────────────────────────────────────────── */
        .status-pill{
            display:flex;align-items:center;justify-content:center;gap:8px;
            padding:0.45rem 1.1rem;margin-bottom:1.7rem;
            background:rgba(0,255,204,0.04);border:1px solid rgba(0,255,204,0.1);
            border-radius:999px;font-size:0.8rem;color:var(--text-2);
        }
        .dot{width:7px;height:7px;border-radius:50%;background:#ff9500;
             box-shadow:0 0 8px #ff9500;flex-shrink:0;transition:all 0.35s;}
        .dot.active{background:var(--cyan);box-shadow:0 0 8px var(--cyan),0 0 22px rgba(0,255,204,0.4);
            animation:dot-pulse 2s ease-in-out infinite;}
        .dot.error{background:#ff4d6d;box-shadow:0 0 8px #ff4d6d;}
        @keyframes dot-pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.5;transform:scale(1.4);}}

        /* ── Lock screen ───────────────────────────────────────────────────── */
        .lock-screen{display:none;text-align:center;animation:fade-up 0.4s ease;}
        @keyframes fade-up{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:none;}}
        .lock-icon{font-size:2.4rem;margin-bottom:0.75rem;
                   filter:drop-shadow(0 0 14px rgba(0,255,204,0.5));}
        .lock-title{font-size:1rem;font-weight:600;margin-bottom:0.4rem;}
        .lock-desc{font-size:0.8rem;color:var(--text-2);margin-bottom:1.2rem;line-height:1.55;}
        .input-row{display:flex;gap:8px;}
        .key-input{
            flex:1;background:rgba(0,255,204,0.04);
            border:1px solid rgba(0,255,204,0.18);border-radius:10px;
            color:var(--text-1);padding:0.72rem 0.9rem;
            font-family:'Fira Code',monospace;font-size:0.9rem;outline:none;transition:all 0.2s;
        }
        .key-input:focus{border-color:var(--cyan);box-shadow:0 0 14px rgba(0,255,204,0.15);}
        .btn-unlock{
            background:linear-gradient(135deg,#00ffcc,#00d4a8);border:none;border-radius:10px;
            color:#020408;font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:0.85rem;
            padding:0.72rem 1.1rem;cursor:pointer;white-space:nowrap;transition:all 0.2s;
        }
        .btn-unlock:hover{transform:translateY(-1px);box-shadow:0 6px 22px rgba(0,255,204,0.38);}
        .btn-unlock:active{transform:none;}
        .err-msg{color:#ff4d6d;font-size:0.77rem;margin-top:0.6rem;display:none;}

        /* ── Decrypted content ─────────────────────────────────────────────── */
        .content{display:none;animation:fade-up 0.5s cubic-bezier(0.16,1,0.3,1);}

        /* Text payload box */
        .text-wrap{position:relative;}
        .payload-text{
            background:rgba(0,255,204,0.03);border:1px solid rgba(0,255,204,0.1);
            border-radius:14px;padding:1.1rem 1rem;
            font-family:'Fira Code',monospace;font-size:0.87rem;
            color:var(--text-1);word-break:break-all;white-space:pre-wrap;
            max-height:210px;overflow-y:auto;line-height:1.65;
        }
        .btn-copy{
            position:absolute;top:0.55rem;right:0.55rem;
            background:rgba(0,255,204,0.08);border:1px solid rgba(0,255,204,0.22);
            border-radius:7px;color:var(--cyan);
            font-family:'Space Grotesk',sans-serif;font-size:0.74rem;font-weight:600;
            padding:0.28rem 0.65rem;cursor:pointer;display:flex;align-items:center;gap:4px;
            transition:all 0.2s;
        }
        .btn-copy:hover{background:rgba(0,255,204,0.16);box-shadow:0 0 14px rgba(0,255,204,0.22);}

        /* File download card */
        .file-card{
            background:rgba(0,255,204,0.03);border:1px solid rgba(0,255,204,0.12);
            border-radius:14px;padding:1.1rem;display:flex;align-items:center;gap:1rem;
        }
        .file-icon-wrap{
            width:50px;height:50px;background:rgba(0,255,204,0.07);
            border:1px solid rgba(0,255,204,0.12);border-radius:11px;
            display:flex;align-items:center;justify-content:center;
            font-size:1.6rem;flex-shrink:0;
        }
        .file-info{flex:1;min-width:0;}
        .file-name{font-size:0.9rem;font-weight:600;white-space:nowrap;
                   overflow:hidden;text-overflow:ellipsis;}
        .file-meta{font-size:0.74rem;color:var(--text-2);margin-top:3px;
                   font-family:'Fira Code',monospace;}
        .btn-download{
            background:linear-gradient(135deg,#00ffcc,#00d4a8);border:none;border-radius:10px;
            color:#020408;font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:0.8rem;
            padding:0.6rem 0.95rem;cursor:pointer;text-decoration:none;
            display:inline-flex;align-items:center;gap:5px;flex-shrink:0;transition:all 0.2s;
        }
        .btn-download:hover{transform:translateY(-1px);box-shadow:0 6px 22px rgba(0,255,204,0.38);}

        /* Integrity badge */
        .badge{
            display:flex;align-items:center;justify-content:center;gap:5px;
            margin-top:1rem;font-size:0.7rem;color:var(--cyan);opacity:0.65;
            font-family:'Fira Code',monospace;
        }
    </style>
</head>
<body>
    <div class="bg-grid"></div>
    <div class="orb orb-a"></div>
    <div class="orb orb-b"></div>

    <div class="card">
        <div class="header">
            <svg class="logo" width="64" height="64" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom: 0.5rem; filter: drop-shadow(0 0 12px rgba(0, 255, 204, 0.4));">
              <path d="M5 4H19L11 12H16L8 20H22" 
                    stroke="var(--cyan)" 
                    stroke-width="2" 
                    stroke-linecap="round" 
                    stroke-linejoin="miter" />
            </svg>
            <div class="brand">zshare</div>
            <div class="brand-sub">// ENCRYPTED TRANSFER</div>
        </div>

        <div class="status-pill">
            <div class="dot" id="dot"></div>
            <span id="status">Connecting to channel...</span>
        </div>

        <!-- Lock screen: shown when key is not in URL -->
        <div class="lock-screen" id="lock">
            <div class="lock-icon">🔐</div>
            <div class="lock-title">Payload Encrypted</div>
            <div class="lock-desc">Enter the security key shown on the sender's terminal to unlock.</div>
            <div class="input-row">
                <input id="key-input" class="key-input" type="text" placeholder="zsh-xxxxxx" autocomplete="off" spellcheck="false">
                <button class="btn-unlock" id="btn-unlock">Unlock</button>
            </div>
            <div class="err-msg" id="err-msg">&#10060; Wrong key — check and try again.</div>
        </div>

        <!-- Content shown after successful decryption -->
        <div class="content" id="content">
            <!-- Dynamic container for received items -->
            <div id="items-container" style="display:flex; flex-direction:column; gap:1.2rem;"></div>

            <div class="badge" id="badge" style="display:none">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                    <polyline points="20 6 9 17 4 12"/>
                </svg>
                E2E Encrypted &middot; SHA256-CTR &middot; Integrity Verified
            </div>
        </div>
    </div>

    <script>
        ${CRYPTO_HELPERS_JS}

        /* ── Embedded encrypted payload from the server ── */
        var rawPayload = ${JSON.stringify(encryptedPayload)};

        /* ── DOM refs ── */
        var dot       = document.getElementById('dot');
        var status    = document.getElementById('status');
        var lockEl    = document.getElementById('lock');
        var contentEl = document.getElementById('content');
        var keyInput  = document.getElementById('key-input');
        var btnUnlock = document.getElementById('btn-unlock');
        var errMsg    = document.getElementById('err-msg');
        var badge     = document.getElementById('badge');

        /* ── Extract key from URL ─────────────────────────────────────────── */
        var urlKey = new URLSearchParams(window.location.search).get('key') || '';
        if (urlKey) keyInput.value = urlKey;

        /* ── WebSocket for status indicator (non-blocking, best-effort) ───── */
        try {
            var ws = new WebSocket('ws://' + window.location.host);
            ws.onopen  = function(){ status.textContent = 'Channel established.'; dot.className='dot active'; };
            ws.onclose = function(){ /* keep current status text */ };
        } catch(e) {}

        /* ── Decrypt and render payload ───────────────────────────────────── */
        function attemptDecryption() {
            var key = keyInput.value.trim();
            if (!key) { lockEl.style.display = 'block'; return; }
            try {
                errMsg.style.display = 'none';

                var items = [];
                var envelope = JSON.parse(rawPayload);
                if (envelope.type === 'multi') {
                    items = envelope.items;
                } else {
                    items = [envelope];
                }

                var container = document.getElementById('items-container');
                container.innerHTML = ''; // Clear previous items

                var decryptedCount = 0;

                for (var i = 0; i < items.length; i++) {
                    var item = items[i];
                    var result = decryptPayload(JSON.stringify(item), key);

                    if (result.type === 'text') {
                        // Create text copy card
                        var textWrap = document.createElement('div');
                        textWrap.className = 'text-wrap';
                        textWrap.style.marginBottom = '0.5rem';
                        
                        var textId = 'text-content-' + i;
                        textWrap.innerHTML = [
                            '<div class="payload-text" id="' + textId + '"></div>',
                            '<button class="btn-copy" onclick="copyTextElement(\'' + textId + '\', this)">',
                                '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">',
                                    '<rect x="9" y="9" width="13" height="13" rx="2"/>',
                                    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
                                '</svg>',
                                '<span class="copy-label">Copy</span>',
                            '</button>'
                        ].join('');
                        container.appendChild(textWrap);
                        document.getElementById(textId).textContent = result.content;
                    } else {
                        // Create file download card
                        var blob = new Blob([result.bytes], { type: result.mimeType || 'application/octet-stream' });
                        var objectUrl = URL.createObjectURL(blob);
                        var fileCard = document.createElement('div');
                        fileCard.className = 'file-card';
                        fileCard.innerHTML = [
                            '<div class="file-icon-wrap">' + getFileEmoji(result.mimeType) + '</div>',
                            '<div class="file-info">',
                                '<div class="file-name" title="' + result.filename + '">' + result.filename + '</div>',
                                '<div class="file-meta">' + formatBytes(result.originalSize) + ' &middot; ' + (result.mimeType || 'binary') + '</div>',
                            '</div>',
                            '<a class="btn-download" href="' + objectUrl + '" download="' + result.filename + '">',
                                '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">',
                                    '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>',
                                    '<polyline points="7 10 12 15 17 10"/>',
                                    '<line x1="12" y1="15" x2="12" y2="3"/>',
                                '</svg>',
                                'Save',
                            '</a>'
                        ].join('');
                        container.appendChild(fileCard);
                    }
                    decryptedCount++;
                }

                lockEl.style.display    = 'none';
                contentEl.style.display = 'block';
                badge.style.display     = 'flex';
                status.textContent      = 'Decrypted ' + decryptedCount + ' item(s) \u2713';
                dot.className           = 'dot active';
            } catch(e) {
                errMsg.style.display = 'block';
                lockEl.style.display = 'block';
            }
        }

        /* ── Copy handler for dynamic text elements ── */
        window.copyTextElement = function(elementId, btn) {
            var txtEl = document.getElementById(elementId);
            var text = txtEl.textContent;
            var label = btn.querySelector('.copy-label');
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function() { flash(label, btn); }).catch(function() { fallback(txtEl, label, btn); });
            } else { fallback(txtEl, label, btn); }
        }
        function fallback(txtEl, label, btn) {
            var r=document.createRange(); r.selectNodeContents(txtEl);
            var s=window.getSelection(); s.removeAllRanges(); s.addRange(r);
            document.execCommand('copy'); flash(label, btn);
        }
        function flash(label, btn) {
            label.textContent = 'Copied!';
            btn.style.color = 'var(--cyan)';
            setTimeout(function(){ label.textContent = 'Copy'; btn.style.color = ''; }, 2200);
        }

        /* ── Event listeners ───────────────────────────────────────────────── */
        btnUnlock.addEventListener('click', attemptDecryption);
        keyInput.addEventListener('keydown', function(e){ if(e.key === 'Enter') attemptDecryption(); });

        /* ── Auto-decrypt on load if key is present in URL ─────────────────── */
        if (urlKey && rawPayload) {
            attemptDecryption();
        } else {
            lockEl.style.display = 'block';
        }
    </script>
</body>
</html>`;
}

/**
 * Builds the full HTML page served to a transmitting device in RECV mode.
 *
 * The page presents a mobile-optimised upload interface with two modes:
 *  - Text mode: textarea with a "Beam to PC" button
 *  - File mode: drag-and-drop / tap-to-browse file zone + file preview card
 *
 * Data flow:
 *  1. Phone connects to the WebSocket server
 *  2. WebRTC offer/answer exchange → DataChannel opens
 *  3. On send: payload is encrypted client-side (same SHA256-CTR cipher)
 *  4. Encrypted ciphertext is split into 32 KB chunks and sent sequentially
 *  5. The PC server reassembles, decrypts, verifies, and saves/prints
 *
 * @param {string} passcode - Session passcode (injected into the page script so
 *                            the phone encrypts with the same key as the PC)
 * @returns {string} Complete HTML document string
 */
function buildTransmitterPage(passcode) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
    <meta name="description" content="zshare secure uplink — send text or files to your PC over the local network.">
    <title>zshare // Secure Uplink</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        *{box-sizing:border-box;margin:0;padding:0;}
        :root{
            --bg:#020408;--cyan:#00ffcc;--lime:#a3ff00;--amber:#ff9500;
            --card-bg:rgba(0,12,18,0.9);--card-border:rgba(0,255,204,0.18);
            --text-1:#d4fff5;--text-2:#6ab8a8;
        }
        html,body{height:100%;}
        body{font-family:'Space Grotesk',sans-serif;background:var(--bg);color:var(--text-1);
             min-height:100vh;display:flex;justify-content:center;align-items:flex-start;
             padding:2rem 0 3rem;overflow-y:auto;position:relative;}
        .bg-grid{position:fixed;inset:0;z-index:0;
            background-image:linear-gradient(rgba(0,255,204,0.04)1px,transparent 1px),
                             linear-gradient(90deg,rgba(0,255,204,0.04)1px,transparent 1px);
            background-size:44px 44px;animation:grid-scroll 25s linear infinite;}
        @keyframes grid-scroll{0%{transform:translateY(0);}100%{transform:translateY(44px);}}
        .orb{position:fixed;border-radius:50%;filter:blur(110px);opacity:0.12;z-index:0;
             animation:orb-drift 18s ease-in-out infinite alternate;}
        .orb-a{width:500px;height:500px;background:radial-gradient(circle,#00ffcc,transparent);
               top:-120px;left:-80px;}
        .orb-b{width:420px;height:420px;background:radial-gradient(circle,#a3ff00,transparent);
               bottom:-100px;right:-80px;animation-delay:-9s;}
        @keyframes orb-drift{0%{transform:translate(0,0) scale(1);}50%{transform:translate(50px,-40px) scale(1.08);}100%{transform:translate(-20px,55px) scale(0.92);}}

        .card{
            position:relative;z-index:2;background:var(--card-bg);
            border:1px solid var(--card-border);border-radius:24px;
            padding:2.2rem 2rem;width:92%;max-width:460px;margin:auto;
            box-shadow:0 0 50px rgba(0,255,204,0.07),0 24px 60px rgba(0,0,0,0.55);
            backdrop-filter:blur(24px) saturate(180%);-webkit-backdrop-filter:blur(24px) saturate(180%);
            overflow:hidden;animation:card-in 0.65s cubic-bezier(0.16,1,0.3,1) both;
        }
        @keyframes card-in{from{opacity:0;transform:translateY(28px) scale(0.96);}to{opacity:1;transform:none;}}
        .card::after{content:'';position:absolute;top:-40%;left:0;right:0;height:40%;
            background:linear-gradient(transparent,rgba(0,255,204,0.025),transparent);
            animation:scan 7s linear infinite;pointer-events:none;}
        @keyframes scan{0%{top:-40%;}100%{top:140%;}}

        .header{text-align:center;margin-bottom:1.6rem;}
        .brand{font-size:2rem;font-weight:700;letter-spacing:-1px;
               background:linear-gradient(135deg,#00ffcc 0%,#a3ff00 100%);
               -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
        .brand-sub{font-size:0.65rem;letter-spacing:5px;text-transform:uppercase;color:var(--text-2);margin-top:3px;}

        .status-pill{display:flex;align-items:center;justify-content:center;gap:8px;
            padding:0.45rem 1.1rem;margin-bottom:1.6rem;
            background:rgba(0,255,204,0.04);border:1px solid rgba(0,255,204,0.1);
            border-radius:999px;font-size:0.8rem;color:var(--text-2);}
        .dot{width:7px;height:7px;border-radius:50%;background:#ff9500;box-shadow:0 0 8px #ff9500;flex-shrink:0;transition:all 0.35s;}
        .dot.active{background:var(--cyan);box-shadow:0 0 8px var(--cyan),0 0 22px rgba(0,255,204,0.4);animation:dot-pulse 2s ease-in-out infinite;}
        .dot.error{background:#ff4d6d;box-shadow:0 0 8px #ff4d6d;}
        @keyframes dot-pulse{0%,100%{opacity:1;transform:scale(1);}50%{opacity:0.5;transform:scale(1.4);}}

        /* ── Mode tabs ─────────────────────────────────────────────────────── */
        .tabs{display:flex;gap:6px;margin-bottom:1.4rem;
              background:rgba(0,255,204,0.04);border:1px solid rgba(0,255,204,0.1);
              border-radius:12px;padding:4px;}
        .tab{flex:1;padding:0.55rem;border:none;border-radius:9px;cursor:pointer;
             font-family:'Space Grotesk',sans-serif;font-size:0.85rem;font-weight:600;
             color:var(--text-2);background:transparent;transition:all 0.22s;}
        .tab.active{background:rgba(0,255,204,0.12);color:var(--cyan);
                    box-shadow:0 0 14px rgba(0,255,204,0.12);}
        .tab:hover:not(.active){color:var(--text-1);}

        /* ── Text panel ────────────────────────────────────────────────────── */
        .panel{display:none;}
        .panel.visible{display:block;}
        textarea{
            width:100%;background:rgba(0,255,204,0.03);
            border:1px solid rgba(0,255,204,0.15);border-radius:12px;
            color:var(--text-1);padding:1rem;font-family:'Space Grotesk',sans-serif;
            font-size:0.9rem;resize:vertical;min-height:130px;outline:none;
            line-height:1.55;transition:border-color 0.2s;
        }
        textarea:focus{border-color:rgba(0,255,204,0.45);box-shadow:0 0 14px rgba(0,255,204,0.1);}
        textarea::placeholder{color:var(--text-2);opacity:0.6;}

        /* ── File drop zone ────────────────────────────────────────────────── */
        .drop-zone{
            border:2px dashed rgba(0,255,204,0.25);border-radius:14px;
            padding:2.2rem 1rem;text-align:center;cursor:pointer;
            transition:all 0.2s;color:var(--text-2);font-size:0.88rem;
        }
        .drop-zone:hover,.drop-zone.drag-over{
            border-color:rgba(0,255,204,0.7);
            background:rgba(0,255,204,0.04);
            box-shadow:0 0 20px rgba(0,255,204,0.1);
            color:var(--text-1);
        }
        .drop-icon{font-size:2.2rem;margin-bottom:0.6rem;display:block;
                   filter:drop-shadow(0 0 10px rgba(0,255,204,0.4));}

        /* Selected file preview inside file panel */
        .file-preview{
            background:rgba(0,255,204,0.03);border:1px solid rgba(0,255,204,0.12);
            border-radius:12px;padding:1rem;display:none;
            align-items:center;gap:0.85rem;margin-top:0;
        }
        .preview-icon{font-size:1.7rem;flex-shrink:0;}
        .preview-info{flex:1;min-width:0;}
        .preview-name{font-size:0.88rem;font-weight:600;overflow:hidden;
                      text-overflow:ellipsis;white-space:nowrap;}
        .preview-size{font-size:0.73rem;color:var(--text-2);margin-top:2px;font-family:'Fira Code',monospace;}
        .preview-clear{background:none;border:none;color:var(--text-2);cursor:pointer;
                       font-size:1.1rem;padding:0.2rem;flex-shrink:0;transition:color 0.2s;}
        .preview-clear:hover{color:#ff4d6d;}

        /* ── Action button ─────────────────────────────────────────────────── */
        .btn-send{
            width:100%;margin-top:1rem;padding:0.9rem;
            background:linear-gradient(135deg,#00ffcc,#00d4a8);
            border:none;border-radius:12px;
            color:#020408;font-family:'Space Grotesk',sans-serif;font-weight:700;font-size:0.95rem;
            cursor:pointer;transition:all 0.22s;
            display:flex;align-items:center;justify-content:center;gap:8px;
        }
        .btn-send:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 8px 28px rgba(0,255,204,0.38);}
        .btn-send:active:not(:disabled){transform:none;}
        .btn-send:disabled{opacity:0.35;cursor:not-allowed;transform:none;box-shadow:none;}

        /* ── Progress bar ──────────────────────────────────────────────────── */
        .progress-wrap{margin-top:1rem;display:none;}
        .progress-bar{height:4px;background:rgba(0,255,204,0.1);border-radius:4px;overflow:hidden;}
        .progress-fill{height:100%;width:0%;border-radius:4px;
            background:linear-gradient(90deg,#00ffcc,#a3ff00);
            box-shadow:0 0 10px rgba(0,255,204,0.5);transition:width 0.15s ease;}
        .progress-label{font-size:0.71rem;color:var(--text-2);margin-top:5px;
                        font-family:'Fira Code',monospace;text-align:center;}

        /* ── Success overlay ───────────────────────────────────────────────── */
        .success-msg{
            display:none;text-align:center;padding:1.5rem 0;
            animation:fade-up 0.45s cubic-bezier(0.16,1,0.3,1);
        }
        @keyframes fade-up{from{opacity:0;transform:translateY(12px);}to{opacity:1;transform:none;}}
        .success-icon{font-size:2.6rem;margin-bottom:0.6rem;display:block;
                      filter:drop-shadow(0 0 18px rgba(0,255,204,0.6));}
        .success-title{font-size:1.1rem;font-weight:700;color:var(--cyan);margin-bottom:0.3rem;}
        .success-sub{font-size:0.82rem;color:var(--text-2);}
        .btn-again{
            margin-top:1.2rem;padding:0.65rem 1.4rem;
            background:rgba(0,255,204,0.08);border:1px solid rgba(0,255,204,0.22);
            border-radius:10px;color:var(--cyan);font-family:'Space Grotesk',sans-serif;
            font-weight:600;font-size:0.85rem;cursor:pointer;transition:all 0.2s;
        }
        .btn-again:hover{background:rgba(0,255,204,0.14);box-shadow:0 0 14px rgba(0,255,204,0.2);}
    </style>
</head>
<body>
    <div class="bg-grid"></div>
    <div class="orb orb-a"></div>
    <div class="orb orb-b"></div>

    <div class="card">
        <div class="header">
            <svg class="logo" width="64" height="64" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom: 0.5rem; filter: drop-shadow(0 0 12px rgba(0, 255, 204, 0.4));">
              <path d="M5 4H19L11 12H16L8 20H22" 
                    stroke="var(--cyan)" 
                    stroke-width="2" 
                    stroke-linecap="round" 
                    stroke-linejoin="miter" />
            </svg>
            <div class="brand">zshare</div>
            <div class="brand-sub">// SECURE UPLINK</div>
        </div>

        <div class="status-pill">
            <div class="dot" id="dot"></div>
            <span id="status">Establishing tunnel...</span>
        </div>

        <!-- Mode switcher tabs -->
        <div class="tabs" id="tabs">
            <button class="tab active" id="tab-text" onclick="switchTab('text')">&#128172; Text</button>
            <button class="tab"        id="tab-file" onclick="switchTab('file')">&#128193; File</button>
        </div>

        <!-- Text mode panel -->
        <div class="panel visible" id="panel-text">
            <textarea id="text-input" placeholder="Type or paste your text to send to PC..." rows="5"></textarea>
            <button class="btn-send" id="btn-send-text" disabled>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3">
                    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </svg>
                Beam Text to PC
            </button>
        </div>

        <!-- File mode panel -->
        <div class="panel" id="panel-file">
            <!-- Drop zone (hidden when file is selected) -->
            <div class="drop-zone" id="drop-zone">
                <span class="drop-icon">&#128228;</span>
                Tap to select files<br>
                <small style="font-size:0.74rem;opacity:0.6;margin-top:4px;display:block;">or drag &amp; drop &mdash; multiple files supported</small>
                <input type="file" id="file-input" style="display:none" multiple>
            </div>
            <!-- File preview (shown when file is selected) -->
            <div class="file-preview" id="file-preview">
                <div class="preview-icon" id="prev-icon">&#128193;</div>
                <div class="preview-info">
                    <div class="preview-name" id="prev-name">filename</div>
                    <div class="preview-size" id="prev-size">0 B</div>
                </div>
                <button class="preview-clear" id="btn-clear" title="Remove files">&#10005;</button>
            </div>
            <button class="btn-send" id="btn-send-file" disabled>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3">
                    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </svg>
                Beam File(s) to PC
            </button>
        </div>

        <!-- Progress bar (shared, shown during transfer) -->
        <div class="progress-wrap" id="progress-wrap">
            <div class="progress-bar"><div class="progress-fill" id="progress-fill"></div></div>
            <div class="progress-label" id="progress-label">0%</div>
        </div>

        <!-- Success overlay (shown after transfer completes) -->
        <div class="success-msg" id="success-msg">
            <span class="success-icon">&#9889;</span>
            <div class="success-title">Transfer Complete!</div>
            <div class="success-sub">Your data was encrypted and beamed to the PC.</div>
            <button class="btn-again" id="btn-again">Send Another</button>
        </div>
    </div>

    <script>
        ${CRYPTO_HELPERS_JS}

        /* ── Session passcode injected server-side ──────────────────────────── */
        var PASSCODE = '${passcode}';

        /* ── Chunk size for DataChannel messages (32 KB is safe across browsers) */
        var CHUNK_SIZE = 32768;

        /* ── State ──────────────────────────────────────────────────────────── */
        var peerConn     = null; // RTCPeerConnection
        var dataChannel  = null; // RTCDataChannel
        var selectedFile = null; // File object from picker
        var activeTab    = 'text';

        /* ── DOM refs ───────────────────────────────────────────────────────── */
        var dot         = document.getElementById('dot');
        var statusEl    = document.getElementById('status');
        var btnSendText = document.getElementById('btn-send-text');
        var btnSendFile = document.getElementById('btn-send-file');
        var textInput   = document.getElementById('text-input');
        var dropZone    = document.getElementById('drop-zone');
        var fileInput   = document.getElementById('file-input');
        var filePreview = document.getElementById('file-preview');
        var prevIcon    = document.getElementById('prev-icon');
        var prevName    = document.getElementById('prev-name');
        var prevSize    = document.getElementById('prev-size');
        var btnClear    = document.getElementById('btn-clear');
        var progressWrap = document.getElementById('progress-wrap');
        var progressFill = document.getElementById('progress-fill');
        var progressLabel = document.getElementById('progress-label');
        var successMsg  = document.getElementById('success-msg');
        var btnAgain    = document.getElementById('btn-again');

        /* ── Tab switching ──────────────────────────────────────────────────── */
        function switchTab(tab) {
            activeTab = tab;
            document.getElementById('tab-text').className = 'tab' + (tab === 'text' ? ' active' : '');
            document.getElementById('tab-file').className = 'tab' + (tab === 'file' ? ' active' : '');
            document.getElementById('panel-text').className = 'panel' + (tab === 'text' ? ' visible' : '');
            document.getElementById('panel-file').className = 'panel' + (tab === 'file' ? ' visible' : '');
        }

        /* ── File selection ─────────────────────────────────────────────────── */
        var selectedFiles = []; // Array of File objects

        dropZone.addEventListener('click', function() { fileInput.click(); });
        dropZone.addEventListener('dragover', function(e) { e.preventDefault(); dropZone.classList.add('drag-over'); });
        dropZone.addEventListener('dragleave', function() { dropZone.classList.remove('drag-over'); });
        dropZone.addEventListener('drop', function(e) {
            e.preventDefault(); dropZone.classList.remove('drag-over');
            if (e.dataTransfer.files.length > 0) setFiles(e.dataTransfer.files);
        });
        fileInput.addEventListener('change', function() { if (fileInput.files.length > 0) setFiles(fileInput.files); });

        function setFiles(filesList) {
            selectedFiles = Array.from(filesList);
            if (selectedFiles.length === 0) return;

            var totalSize = 0;
            for (var i = 0; i < selectedFiles.length; i++) {
                totalSize += selectedFiles[i].size;
            }

            if (selectedFiles.length === 1) {
                var f = selectedFiles[0];
                prevIcon.textContent = getFileEmoji(f.type);
                prevName.textContent = f.name;
                prevSize.textContent = formatBytes(f.size);
            } else {
                prevIcon.textContent = '📦';
                prevName.textContent = selectedFiles.length + ' files selected';
                prevSize.textContent = 'Total size: ' + formatBytes(totalSize);
            }

            dropZone.style.display   = 'none';
            filePreview.style.display = 'flex';
            if (dataChannel && dataChannel.readyState === 'open') btnSendFile.disabled = false;
        }

        btnClear.addEventListener('click', function() {
            selectedFiles = []; fileInput.value = '';
            filePreview.style.display = 'none'; dropZone.style.display = 'block';
            btnSendFile.disabled = true;
        });

        /* ── Progress helpers ───────────────────────────────────────────────── */
        function showProgress(pct, label) {
            progressWrap.style.display = 'block';
            progressFill.style.width   = Math.round(pct * 100) + '%';
            progressLabel.textContent  = label || (Math.round(pct * 100) + '%');
        }
        function hideProgress() { progressWrap.style.display = 'none'; progressFill.style.width = '0%'; }

        /* ── Success state ──────────────────────────────────────────────────── */
        function showSuccess() {
            document.getElementById('tabs').style.display       = 'none';
            document.getElementById('panel-text').style.display = 'none';
            document.getElementById('panel-file').style.display = 'none';
            successMsg.style.display = 'block';
            hideProgress();
        }
        btnAgain.addEventListener('click', function() {
            successMsg.style.display = 'none';
            document.getElementById('tabs').style.display       = 'flex';
            switchTab(activeTab);
            textInput.value = '';
            selectedFiles = []; fileInput.value = '';
            filePreview.style.display = 'none'; dropZone.style.display = 'block';
            btnSendFile.disabled = true;
        });

        /* ── Chunked DataChannel send protocol ──────────────────────────────── *
         * Protocol messages (all JSON-stringified):
         *   {type:'transfer-start', payloadType, filename, mimeType,
         *    originalSize, iv, sha256, totalChunks}
         *   {type:'chunk',          index, data}  (repeated totalChunks times)
         *   {type:'transfer-end'}
         * ────────────────────────────────────────────────────────────────────── */
        function sendChunked(channel, payloadJson, onProgress) {
            var meta        = JSON.parse(payloadJson);
            var cipher      = meta.ciphertext;
            var totalChunks = Math.ceil(cipher.length / CHUNK_SIZE);

            /* Send metadata header so the receiver can pre-allocate and track progress */
            channel.send(JSON.stringify({
                type: 'transfer-start',
                payloadType:  meta.type || 'text',
                filename:     meta.filename     || null,
                mimeType:     meta.mimeType     || null,
                originalSize: meta.originalSize || null,
                iv:           meta.iv,
                sha256:       meta.sha256,
                totalChunks:  totalChunks
            }));

            var idx = 0;
            function sendNext() {
                if (idx >= totalChunks) {
                    channel.send(JSON.stringify({ type: 'transfer-end' }));
                    if (onProgress) onProgress(1, 'Verifying...');
                    return;
                }
                /* Back-pressure: pause if the send buffer is getting full */
                if (channel.bufferedAmount > 4 * 1024 * 1024) {
                    setTimeout(sendNext, 60);
                    return;
                }
                var start = idx * CHUNK_SIZE;
                channel.send(JSON.stringify({ type: 'chunk', index: idx, data: cipher.slice(start, start + CHUNK_SIZE) }));
                idx++;
                if (onProgress) onProgress(idx / totalChunks, idx + '/' + totalChunks + ' chunks');
                setTimeout(sendNext, 1); /* Yield to UI thread between chunks */
            }
            sendNext();
        }

        /* ── Send text ──────────────────────────────────────────────────────── */
        btnSendText.addEventListener('click', function() {
            var text = textInput.value.trim();
            if (!text || !dataChannel || dataChannel.readyState !== 'open') return;
            btnSendText.disabled = true;
            statusEl.textContent = 'Encrypting...';
            try {
                var enc = encryptText(text, PASSCODE);
                sendChunked(dataChannel, enc, function(pct, label) {
                    showProgress(pct, 'Sending: ' + label);
                    if (pct >= 1) {
                        statusEl.textContent = 'Text sent!';
                        setTimeout(showSuccess, 600);
                    }
                });
            } catch(e) { statusEl.textContent = 'Error: ' + e.message; btnSendText.disabled = false; }
        });

        /* ── Send files sequentially ────────────────────────────────────────── */
        btnSendFile.addEventListener('click', function() {
            if (selectedFiles.length === 0 || !dataChannel || dataChannel.readyState !== 'open') return;
            btnSendFile.disabled = true;

            var fileIndex = 0;

            function sendNextFile() {
                if (fileIndex >= selectedFiles.length) {
                    statusEl.textContent = 'All files sent!';
                    setTimeout(showSuccess, 600);
                    return;
                }

                var file = selectedFiles[fileIndex];
                statusEl.textContent = 'Reading [' + (fileIndex + 1) + '/' + selectedFiles.length + ']: ' + file.name + '...';

                var reader = new FileReader();
                reader.onload = function(e) {
                    try {
                        statusEl.textContent = 'Encrypting ' + file.name + '...';
                        var bytes = new Uint8Array(e.target.result);
                        var enc   = encryptFilePayload(bytes, file.name,
                                                       file.type || 'application/octet-stream',
                                                       file.size, PASSCODE);
                        statusEl.textContent = 'Sending ' + file.name + '...';
                        sendChunked(dataChannel, enc, function(pct, label) {
                            showProgress(pct, '[' + (fileIndex + 1) + '/' + selectedFiles.length + '] ' + file.name + ' — ' + label);
                            if (pct >= 1) {
                                fileIndex++;
                                setTimeout(sendNextFile, 150); // short delay between files
                            }
                        });
                    } catch(e) {
                        statusEl.textContent = 'Error: ' + e.message;
                        btnSendFile.disabled = false;
                    }
                };
                reader.readAsArrayBuffer(file);
            }

            sendNextFile();
        });

        /* ── WebSocket → WebRTC signaling ───────────────────────────────────── */
        var ws = new WebSocket('ws://' + window.location.host);

        ws.onopen = function() {
            statusEl.textContent = 'Signaling connected — waiting for P2P tunnel...';
            dot.className = 'dot active';
        };
        ws.onclose = function() {
            statusEl.textContent = 'Connection lost.';
            dot.className = 'dot error';
        };
        ws.onerror = function() {
            statusEl.textContent = 'WebSocket error.';
            dot.className = 'dot error';
        };

        ws.onmessage = function(event) {
            var data = JSON.parse(event.data);

            if (data.type === 'offer') {
                /* Receive SDP offer → create peer connection → answer */
                peerConn = new RTCPeerConnection();

                peerConn.ondatachannel = function(e) {
                    dataChannel = e.channel;

                    dataChannel.onopen = function() {
                        statusEl.textContent = 'Tunnel open — ready to beam!';
                        dot.className        = 'dot active';
                        btnSendText.disabled = false;
                        if (selectedFile) btnSendFile.disabled = false;
                    };
                    dataChannel.onclose = function() {
                        statusEl.textContent = 'Tunnel closed.';
                        dot.className        = 'dot error';
                        btnSendText.disabled = true;
                        btnSendFile.disabled = true;
                    };
                };

                peerConn.onicecandidate = function(e) {
                    if (e.candidate) ws.send(JSON.stringify({ type: 'candidate', candidate: e.candidate }));
                };

                /* ICE connection state logging */
                peerConn.oniceconnectionstatechange = function() {
                    if (peerConn.iceConnectionState === 'failed') {
                        statusEl.textContent = 'P2P failed — check same Wi-Fi network.';
                        dot.className = 'dot error';
                    }
                };

                peerConn.setRemoteDescription(new RTCSessionDescription(data.offer))
                    .then(function() { return peerConn.createAnswer(); })
                    .then(function(answer) {
                        peerConn.setLocalDescription(answer);
                        ws.send(JSON.stringify({ type: 'answer', answer: answer }));
                    });

            } else if (data.type === 'candidate' && peerConn) {
                peerConn.addIceCandidate(new RTCIceCandidate(data.candidate));
            }
        };
    </script>
</body>
</html>`;
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 7 · NETWORK CONFIGURATION & CLI ROUTING
// ═══════════════════════════════════════════════════════════════════════════════

/** HTTP/WS server port. */
const PORT     = 8080;
/** Local IPv4 address for the share URL. */
const LOCAL_IP = getLocalIP();
/** Base URL reachable by devices on the same LAN. */
const BASE_URL = `http://${LOCAL_IP}:${PORT}`;

/**
 * Parse CLI arguments.
 * Supports:
 *   zshare send "payload"
 *   zshare recv [--dir <dir>] [-d <dir>]
 */
const args = process.argv.slice(2);
const command = args[0];

if (command === 'send') {
    const payloadArgs = args.slice(1);
    if (payloadArgs.length === 0) {
        console.error('❌  Usage: zshare send <payload_1> [payload_2] ...');
        console.error('          Provide file paths or text strings.');
        process.exit(1);
    }
    startSenderMode(payloadArgs);
} else if (command === 'recv') {
    let downloadDir = process.cwd();
    const dirIdx = args.findIndex(arg => arg === '--dir' || arg === '-d');
    if (dirIdx !== -1 && args[dirIdx + 1]) {
        downloadDir = path.resolve(args[dirIdx + 1]);
    }
    startReceiverMode(downloadDir);
} else {
    // Print help and exit
    console.log(`
┌──────────────────────────────────────────────┐
│  zshare v2 — Zero-Config Encrypted Transfer  │
└──────────────────────────────────────────────┘

  Usage:
    zshare send "message"              Share text with a nearby device
    zshare send ./file.pdf             Share a file (no size limit)
    zshare send ./pic.png ./doc.pdf    Share multiple files or texts at once
    zshare recv                        Receive text or files (saves to current folder)
    zshare recv --dir /path/to/folder  Receive and save files to a custom folder
    zshare recv -d ./downloads         Receive and save files to a relative folder

  To make the 'zshare' command global:
    1. Clone/download the project: git clone <repo> && cd zshare-project
    2. Link the package globally:  npm link
    Now you can run 'zshare' from any terminal!
    `);
    process.exit(0);
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 8 · SENDER MODE  (PC → phone)
//
// 1. Detect whether the payload arguments are file paths or raw text
// 2. Encrypt the payloads with a fresh session passcode
// 3. Embed the ciphertext in an HTML page served at BASE_URL
// 4. Print the URL + QR code so the user can scan with their phone
// 5. Establish a WebRTC DataChannel (for live connection status in the UI)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Starts the HTTP + WebSocket server for SEND mode.
 * The encrypted payload is embedded in the served HTML page, allowing the
 * receiver to decrypt it entirely client-side without a server round-trip.
 *
 * @param {string[]} payloadArgs - Array of file paths or raw text strings to send
 */
async function startSenderMode(payloadArgs) {
    const passcode = generatePasscode();
    const items = [];

    console.log(''); // New line for cleaner CLI layout

    for (const arg of payloadArgs) {
        const info = detectPayload(arg);
        if (info.type === 'file') {
            const fileBuffer = fs.readFileSync(info.path);
            const fileJson = encryptFile(fileBuffer, info.filename, info.mimeType, passcode);
            items.push(JSON.parse(fileJson));
            console.log(`📁  File detected:  ${info.filename}  (${formatBytes(info.size)})`);
        } else {
            const textJson = encryptText(arg, passcode);
            items.push(JSON.parse(textJson));
            console.log(`💬  Text detected:  "${arg.length > 30 ? arg.slice(0, 30) + '...' : arg}"`);
        }
    }

    const encryptedPayload = JSON.stringify({
        type: 'multi',
        items: items
    });

    // ── HTTP server — serves the receiver HTML page ────────────────────────────
    const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(buildReceiverPage(encryptedPayload, passcode));
    });

    // ── WebSocket server — handles WebRTC signaling ───────────────────────────
    const wss = new WebSocketServer({ server });

    wss.on('connection', async (ws) => {
        console.log('\n📱  Receiver device connected via signaling...');
        const pc = new RTCPeerConnection();

        // Create a DataChannel for connection status signaling only
        // (The payload is already embedded in the HTML page)
        const dc = pc.createDataChannel('zshare-status');
        dc.onopen = () => {
            // Notify the phone that the P2P handshake succeeded
            try { dc.send(JSON.stringify({ type: 'connected' })); } catch (_) {}
            console.log('⚡  P2P handshake complete — receiver has the encrypted payload.');
        };

        // Relay ICE candidates to the phone browser
        pc.onicecandidate = (e) => {
            if (e.candidate) ws.send(JSON.stringify({ type: 'candidate', candidate: e.candidate }));
        };

        // Create and send SDP offer
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        ws.send(JSON.stringify({ type: 'offer', offer }));

        // Handle signaling messages from the phone
        ws.on('message', async (message) => {
            const data = JSON.parse(message);
            if      (data.type === 'answer')    await pc.setRemoteDescription(data.answer);
            else if (data.type === 'candidate') await pc.addIceCandidate(data.candidate);
        });
    });

    // ── Start server and print QR code ────────────────────────────────────────
    server.listen(PORT, () => {
        const url = `${BASE_URL}?key=${passcode}`;
        console.log('\n╔══════════════════════════════════════════╗');
        console.log('║          zshare — SEND MODE              ║');
        console.log('╠══════════════════════════════════════════╣');
        console.log(`║  🔑  Key:  ${passcode.padEnd(30)} ║`);
        console.log(`║  🔗  URL:  ${(BASE_URL + '?key=…').padEnd(30)} ║`);
        console.log('║                                          ║');
        console.log('║  Scan the QR code with your phone:       ║');
        console.log('╚══════════════════════════════════════════╝\n');
        qrcode.generate(url, { small: true });
        console.log(`\n🌐  Full URL: ${url}`);
        console.log('⏳  Waiting for receiver… (Ctrl+C to stop)\n');
    });
}


// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 9 · RECEIVER MODE  (phone → PC)
//
// 1. Serve the transmitter upload UI to the phone browser
// 2. Phone connects → WebRTC DataChannel opens
// 3. Phone encrypts payload and sends in 32 KB chunks using the transfer protocol:
//      {type:'transfer-start', metadata}
//      {type:'chunk', index, data}  × N
//      {type:'transfer-end'}
// 4. PC reassembles all chunks, decrypts, verifies SHA-256 integrity
// 5. Text: printed to terminal; File: saved to current working directory
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Starts the HTTP + WebSocket server for RECV mode.
 * Each connected device gets its own WebRTC peer connection.
 * The server keeps listening after each transfer to allow multiple sends.
 */
async function startReceiverMode(downloadDir) {
    const passcode = generatePasscode();

    // Ensure the download directory exists
    if (!fs.existsSync(downloadDir)) {
        try {
            fs.mkdirSync(downloadDir, { recursive: true });
        } catch (err) {
            console.error(`❌  Failed to create download directory "${downloadDir}": ${err.message}`);
            process.exit(1);
        }
    }

    // ── HTTP server — serves the transmitter upload UI ─────────────────────────
    const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(buildTransmitterPage(passcode));
    });

    // ── WebSocket server — WebRTC signaling + DataChannel chunked receive ──────
    const wss = new WebSocketServer({ server });

    wss.on('connection', async (ws) => {
        console.log('\n📱  Transmitter device connected via signaling...');

        const pc = new RTCPeerConnection();

        /**
         * Per-connection transfer state.
         * Initialised when 'transfer-start' is received and cleared after 'transfer-end'.
         * @type {{ payloadType, filename, mimeType, originalSize, iv, sha256,
         *          totalChunks, chunks: string[], received: number } | null}
         */
        let xfer = null;

        // The SERVER must create the DataChannel so it is included in the SDP offer.
        // Without this, the offer contains no data-channel m-line and the phone's
        // ondatachannel event never fires — leaving the send buttons permanently disabled.
        const dc = pc.createDataChannel('zshare-uplink');

        dc.onopen = () => {
            console.log('⚡  P2P tunnel open — waiting for payload from device...');
        };

            dc.onmessage = (event) => {
                let msg;
                try { msg = JSON.parse(event.data); } catch (_) { return; }

                if (msg.type === 'transfer-start') {
                    // ── Initialise a new transfer session ──────────────────────
                    xfer = {
                        payloadType:  msg.payloadType  || 'text',
                        filename:     msg.filename     || null,
                        mimeType:     msg.mimeType     || null,
                        originalSize: msg.originalSize || null,
                        iv:           msg.iv,
                        sha256:       msg.sha256,
                        totalChunks:  msg.totalChunks,
                        chunks:       new Array(msg.totalChunks).fill(''), // Pre-allocate chunk slots
                        received:     0
                    };
                    const label = xfer.payloadType === 'file' ? `"${xfer.filename}"` : 'text';
                    console.log(`\n📥  Transfer started: ${label}  (${msg.totalChunks} chunk${msg.totalChunks > 1 ? 's' : ''})`);

                } else if (msg.type === 'chunk') {
                    // ── Store incoming chunk by sequence index ─────────────────
                    if (!xfer) return;
                    xfer.chunks[msg.index] = msg.data;
                    xfer.received++;
                    // Display in-place progress percentage
                    const pct = Math.round((xfer.received / xfer.totalChunks) * 100);
                    process.stdout.write(`\r⏳  Receiving… ${pct}%   `);

                } else if (msg.type === 'transfer-end') {
                    // ── Reassemble, decrypt, and handle completed transfer ──────
                    if (!xfer) return;
                    process.stdout.write('\r');

                    // Reconstruct the full ciphertext from ordered chunk array
                    const fullCiphertext = xfer.chunks.join('');
                    const fullPayload    = JSON.stringify({
                        type:         xfer.payloadType,
                        filename:     xfer.filename,
                        mimeType:     xfer.mimeType,
                        originalSize: xfer.originalSize,
                        iv:           xfer.iv,
                        ciphertext:   fullCiphertext,
                        sha256:       xfer.sha256
                    });

                    try {
                        if (xfer.payloadType === 'text') {
                            // ── Text transfer: decrypt and print to terminal ───
                            const text = decryptText(fullPayload, passcode);
                            console.log('\n╔══════════════════════════════════════════╗');
                            console.log('║          RECEIVED TEXT                   ║');
                            console.log('╠══════════════════════════════════════════╣');
                            // Wrap long text to 40 chars per line
                            const lines = text.match(/.{1,40}/g) || [text];
                            lines.forEach(l => console.log(`║  ${l.padEnd(40)} ║`));
                            console.log('╠══════════════════════════════════════════╣');
                            console.log('║  ✅  SHA-256 integrity: VERIFIED         ║');
                            console.log('╚══════════════════════════════════════════╝\n');
                        } else {
                            // ── File transfer: decrypt and save to disk ────────
                            const fileBuffer = decryptFile(fullPayload, passcode);
                            const savePath   = path.join(downloadDir, xfer.filename);
                            fs.writeFileSync(savePath, fileBuffer);
                            console.log('\n╔══════════════════════════════════════════╗');
                            console.log('║          FILE RECEIVED                   ║');
                            console.log('╠══════════════════════════════════════════╣');
                            console.log(`║  📁  Name:  ${xfer.filename.slice(0,30).padEnd(30)} ║`);
                            console.log(`║  📦  Size:  ${formatBytes(fileBuffer.length).padEnd(30)} ║`);
                            console.log(`║  💾  Saved: ${savePath.slice(-30).padEnd(30)} ║`);
                            console.log('╠══════════════════════════════════════════╣');
                            console.log('║  ✅  SHA-256 integrity: VERIFIED         ║');
                            console.log('╚══════════════════════════════════════════╝\n');
                        }
                    } catch (err) {
                        console.error(`\n❌  Decryption failed: ${err.message}\n`);
                    }

                    xfer = null; // Reset state — ready for next transfer
                    console.log('💡  Still listening. Send more or press Ctrl+C to exit.\n');
                }
            };

        dc.onerror = (err) => console.error('❌  DataChannel error:', err);

        // Relay ICE candidates to the phone browser
        pc.onicecandidate = (e) => {
            if (e.candidate) ws.send(JSON.stringify({ type: 'candidate', candidate: e.candidate }));
        };

        // Create SDP offer and send to phone
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        ws.send(JSON.stringify({ type: 'offer', offer }));

        // Handle signaling messages from the phone (answer + ICE candidates)
        ws.on('message', async (message) => {
            const data = JSON.parse(message);
            if      (data.type === 'answer')    await pc.setRemoteDescription(data.answer);
            else if (data.type === 'candidate') await pc.addIceCandidate(data.candidate);
        });

        ws.on('close', () => {
            console.log('📵  Device disconnected.\n');
            try { pc.close(); } catch (_) {}
        });
    });

    // ── Start server and print QR code ────────────────────────────────────────
    server.listen(PORT, () => {
        const url = `${BASE_URL}?key=${passcode}`;
        console.log('\n╔══════════════════════════════════════════╗');
        console.log('║         zshare — RECV MODE               ║');
        console.log('╠══════════════════════════════════════════╣');
        console.log(`║  🔑  Key:  ${passcode.padEnd(30)} ║`);
        console.log(`║  🔗  URL:  ${(BASE_URL + '?key=…').padEnd(30)} ║`);
        console.log(`║  💾  Save: ${downloadDir.slice(-30).padEnd(30)} ║`);
        console.log('║                                          ║');
        console.log('║  Scan QR on the sending device:          ║');
        console.log('╚══════════════════════════════════════════╝\n');
        qrcode.generate(url, { small: true });
        console.log(`\n🌐  Full URL: ${url}`);
        console.log('📥  Waiting for transfers… (Ctrl+C to stop)\n');
    });
}