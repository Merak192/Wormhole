// ── AES-256-GCM 加密模块（基于 Web Crypto API）─────────────────────────────
// 全程使用浏览器原生 Crypto API，零外部依赖。

/** 将 Uint8Array 转为 base64 字符串 */
export function buf2b64(buf: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
  return btoa(binary);
}

/** 将 base64 字符串转为 Uint8Array */
export function b642buf(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** 将 ArrayBuffer 转为 base64 字符串 */
export function ab2b64(buf: ArrayBuffer): string {
  return buf2b64(new Uint8Array(buf));
}

/** 将 base64 字符串转为 ArrayBuffer */
export function b642ab(b64: string): ArrayBuffer {
  return b642buf(b64).buffer;
}

/** 将 Uint8Array 转为 hex 字符串（用于调试） */
export function ab2hex(buf: Uint8Array): string {
  return Array.from(buf)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── 密钥对（RSA-OAEP 用于密钥交换）──────────────────────────────────────────

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/** 生成 RSA-2048 密钥对 */
export async function generateKeyPair(): Promise<KeyPair> {
  return crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  ) as Promise<KeyPair>;
}

/** 用 RSA-OAEP 加密数据（用于加密 AES 密钥） */
export async function rsaEncrypt(data: ArrayBuffer, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
}

/** 用 RSA-OAEP 解密数据 */
export async function rsaDecrypt(encrypted: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encrypted);
}

// ── AES-256-GCM 会话密钥 ────────────────────────────────────────────────────

export interface SessionKeys {
  aesKey: CryptoKey;
  aesKeyExport: Uint8Array;
}

/** 生成 256-bit AES-GCM 会话密钥 */
export async function generateAesKey(): Promise<SessionKeys> {
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  ) as CryptoKey;
  const raw = await crypto.subtle.exportKey('raw', aesKey);
  return { aesKey, aesKeyExport: new Uint8Array(raw) };
}

/** 从导出的 Uint8Array 重新导入 AES 密钥 */
export async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

// ── 加解密消息 ──────────────────────────────────────────────────────────────

/** 加密消息：生成随机 IV，用 AES-GCM 加密，返回 { iv, ciphertext } */
export async function encryptMessage(plaintext: string, aesKey: CryptoKey): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

/** 解密消息：传入 iv + ciphertext，返回明文。解密失败时抛出错误。 */
export async function decryptMessage(iv: Uint8Array, ciphertext: Uint8Array, aesKey: CryptoKey): Promise<string> {
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
  return new TextDecoder().decode(plaintext);
}

// ── 信令消息格式 ────────────────────────────────────────────────────────────

export type SigType = 'hello' | 'key-exchange' | 'chat' | 'ice' | 'chat-request';

export interface SigHello {
  type: 'hello';
  nick?: string;
  encAesKey: string;   // RSA 加密后的 AES 密钥 (base64)
  publicKey: string;   // 对方 RSA 公钥 JWK (base64)
}

export interface SigKeyExchange {
  type: 'key-exchange';
  encAesKey: string;
  publicKey: string;
}

export interface SigChat {
  type: 'chat';
  iv: string;
  ciphertext: string;
}

export interface SigIce {
  type: 'ice';
  candidate: RTCIceCandidateInit;
}

export type SigMessage = SigHello | SigKeyExchange | SigChat | SigIce;

export function serializeSig(msg: SigMessage): string {
  return JSON.stringify(msg);
}

export function deserializeSig(json: string): SigMessage {
  return JSON.parse(json) as SigMessage;
}
