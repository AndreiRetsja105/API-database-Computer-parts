// FILE: /js/crypto-utils.js
// Purpose: Web Crypto helpers (PBKDF2, AES-GCM, ECDSA), base64 utils, blobs
export const b64 = u8 => btoa(String.fromCharCode(...u8));
export const ub64 = s => new Uint8Array(atob(s).split('').map(c=>c.charCodeAt(0)));
export const enc = new TextEncoder();
export const dec = new TextDecoder();


export async function pbkdf2Key(password, salt, iterations = 150000, usage=['encrypt','decrypt']){
    const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name:'PBKDF2', salt, iterations, hash:'SHA-256' },
        material,
        { name:'AES-GCM', length:256 },
        false,
        usage
        );
}

export async function pbkdf2Bits(password, salt, iterations=150000){
    const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations, hash:'SHA-256' }, material, 256);
    return new Uint8Array(bits);
}

export function randomBytes(n){ const u = new Uint8Array(n); crypto.getRandomValues(u); return u; }

export async function aesGcmEncryptJSON(obj, key){
    const ivB = ub64(iv); const ctB = ub64(ciphertext);
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv: ivB}, key, ctB);
    return JSON.parse(dec.decode(pt));
}


export async function aesGcmEncryptBytes(bytes, key){
    const iv = randomBytes(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, bytes));
    return { iv, ciphertext: ct };
}


export async function aesGcmDecryptBytes(iv, ct, key){
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
    return new Uint8Array(pt);
}


export async function genFileKey(){
    return crypto.subtle.generateKey({ name:'AES-GCM', length:256 }, true, ['encrypt','decrypt']);
}


export async function exportRawKey(key){
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    return raw;
}


export async function importRawAesKey(raw){
    return crypto.subtle.importKey('raw', raw, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}


export async function deriveEncAndMac(password, salt, iterations=150000){
    const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const params = { name:'PBKDF2', salt, iterations, hash:'SHA-256' };
    const aesKey = await crypto.subtle.deriveKey(params, material, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
    const macKey = await crypto.subtle.deriveKey(params, material, {name:'HMAC', hash:'SHA-256', length:256}, false, ['sign','verify']);
    return { aesKey, macKey };
}


export async function hmac(macKey, bytes){
    const sig = await crypto.subtle.sign('HMAC', macKey, bytes);
    return new Uint8Array(sig);
}


export async function hmacVerify(macKey, bytes, sig){
    return crypto.subtle.verify('HMAC', macKey, sig, bytes);
}


export function concatBytes(...arrs){
    const len = arrs.reduce((a,b)=>a+b.length,0);
    const out = new Uint8Array(len); let o=0; for(const a of arrs){ out.set(a,o); o+=a.length; }
    return out;
}


// ECDSA (P-256)
export async function genEcdsaKeyPair(){
    return crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']);
}


export async function ecdsaSign(privateKey, dataBytes){
    return new Uint8Array(await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, privateKey, dataBytes));
}


export async function ecdsaVerify(publicKey, dataBytes, signature){
    return crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, publicKey, signature, dataBytes);
}


export async function exportSpki(pub){
    return new Uint8Array(await crypto.subtle.exportKey('spki', pub));
}
export async function exportPkcs8(priv){
    return new Uint8Array(await crypto.subtle.exportKey('pkcs8', priv));
}
export async function importSpki(spki){
    return crypto.subtle.importKey('spki', spki, {name:'ECDSA', namedCurve:'P-256'}, true, ['verify']);
}
export async function importPkcs8(pkcs8){
    return crypto.subtle.importKey('pkcs8', pkcs8, {name:'ECDSA', namedCurve:'P-256'}, true, ['sign']);
}

export function download(filename, bytes){
    const blob = new Blob([bytes], {type:'application/octet-stream'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
}