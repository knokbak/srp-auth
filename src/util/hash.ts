/*
 * BSD 3-Clause License
 * Copyright (c) 2024, Ollie Killean
 * License: https://github.com/knokbak/srp-auth
 */

import { createSHA256, createSHA384, createSHA512, createSHA3 } from 'hash-wasm';
import { type IHasher } from 'hash-wasm/dist/lib/WASMInterface';
import { SRPError } from './error';

export enum Algorithm {
    SHA_256 = 'SHA-256',
    SHA_384 = 'SHA-384',
    SHA_512 = 'SHA-512',
    SHA3_256 = 'SHA3-256',
    SHA3_384 = 'SHA3-384',
    SHA3_512 = 'SHA3-512',
}

export type Hashable = Uint8Array | string;

export async function hash (algorithm: Algorithm, input: Hashable[]): Promise<Uint8Array> {
    // convert all strings to Uint8Arrays
    for (let i = 0; i < input.length; i++) {
        if (typeof input[i] === 'string') {
            input[i] = new TextEncoder().encode(input[i] as string);
        }
    }

    const data = input as Uint8Array[];

    // combine all Uint8Arrays into one
    const arr = new Uint8Array(data.reduce((acc, curr) => acc + curr.length, 0));
    let offset = 0;
    for (let i = 0; i < data.length; i++) {
        arr.set(data[i], offset);
        offset += data[i].length;
    }

    // choose the correct hashing algorithm, then hash the combined Uint8Array. return the resulting Uint8Array
    switch (algorithm) {
        case Algorithm.SHA_256:
            return hashBuffer(await createSHA256(), arr);
        case Algorithm.SHA_384:
            return hashBuffer(await createSHA384(), arr);
        case Algorithm.SHA_512:
            return hashBuffer(await createSHA512(), arr);
        case Algorithm.SHA3_256:
            return hashBuffer(await createSHA3(256), arr);
        case Algorithm.SHA3_384:
            return hashBuffer(await createSHA3(384), arr);
        case Algorithm.SHA3_512:
            return hashBuffer(await createSHA3(512), arr);
        default:
            throw new SRPError(`Invalid algorithm "${algorithm}" - available algorithms: ${Object.values(Algorithm).join(', ')}`);
    }
}

function hashBuffer (hasher: IHasher, buffer: Uint8Array): Uint8Array {
    hasher.update(buffer);
    return hasher.digest('binary');
}
