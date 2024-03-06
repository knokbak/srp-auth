/*
 * BSD 3-Clause License
 * Copyright (c) 2024, Ollie Killean
 * License: https://github.com/knokbak/srp-auth
 */

export function random (bits: number): Uint8Array {
    const arr = new Uint8Array(Math.ceil(bits / 8));
    if (typeof window === 'undefined' || !window.crypto || !window.crypto.getRandomValues) {
        require('crypto').randomFillSync(arr);
    } else {
        window.crypto.getRandomValues(arr);
    }
    return arr;
}
