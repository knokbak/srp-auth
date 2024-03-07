/*
 * BSD 3-Clause License
 * Copyright (c) 2024, Ollie Killean
 * License: https://github.com/knokbak/srp-auth
 */

export function toBigInt (arr: Uint8Array): bigint {
    let hex = '';
    for (let i = 0; i < arr.length; i++) {
        hex += arr[i].toString(16).padStart(2, '0');
    }
    return BigInt('0x' + hex);
}

export function toUint8Array (n: bigint | string): Uint8Array {
    if (typeof n === 'string') {
        n = BigInt(n.startsWith('0x') ? n : '0x' + n);
    }

    const hex = n.toString(16);
    const arr = new Uint8Array(Math.ceil(hex.length / 2));
    for (let i = 0; i < hex.length; i += 2) {
        arr[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return arr;
}

export function toHex (arr: Uint8Array | bigint): string {
    if (typeof arr === 'bigint') {
        arr = toUint8Array(arr);
    }

    let hex = '';
    for (let i = 0; i < arr.length; i++) {
        hex += arr[i].toString(16).padStart(2, '0');
    }
    return hex;
}

export function toString (data: Uint8Array | bigint): string {
    if (data instanceof Uint8Array) {
        return new TextDecoder().decode(data);
    } else {
        return data.toString();
    }
}

export function powMod(base: bigint, exp: bigint, p: bigint): bigint {
    let result = 1n;

    while (exp !== 0n) {
        if (exp % 2n === 1n) {
            result = result * base % p;
        }
        base = base * base % p;
        exp >>= 1n;
    }

    return result;
}

export function doesMatch (a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }

    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }

    return true;
}
