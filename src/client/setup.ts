/*
 * BSD 3-Clause License
 * Copyright (c) 2024, Ollie Killean
 * License: https://github.com/knokbak/srp-auth
 */

import { SRPError } from '../util/error';
import { Group } from '../util/groups';
import { Algorithm, hash } from '../util/hash';
import { powMod, toBigInt, toHex, toString, toUint8Array } from '../util/math';
import { random } from '../util/random';

export type ClientSetupConfig = {
    /**
     * The username used for authentication.
     */
    username: string;
    /**
     * The plain text password. There is no need to hash this beforehand!
     */
    password: string;
    /**
     * The salt to use. If undefined, one will be securely generated.
     */
    salt?: Uint8Array;
    /**
     * The amount of bits to be used in the generated salt. Defaults to `192` bits. Ignored when `config.salt` is provided.
     */
    saltLength?: number;
    /**
     * The SRP group to use. The built-in groups are from [RFC 5054](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A).
     */
    group: Group;
    /**
     * The hashing algorithm to use.
     */
    algorithm: Algorithm;
}

export type ClientSetupResult = {
    /**
     * The username in plain text. This should be sent to the server, **not the original username provided to the library**!
     */
    I: string;
    raw: {
        /**
         * The verifier (`v`) as a Uint8Array.
         */
        v: Uint8Array;
        /**
         * The salt generated by the client (`s`) as a Uint8Array.
         */
        s: Uint8Array;
    }
    encoded: {
        /**
         * The verifier (`v`) encoded as hex.
         */
        v: string;
        /**
         * The salt generated by the client (`s`) encoded as hex.
         */
        s: string;
    }
}

export class ClientSetup {
    /**
     * `I` is an identifying username.
     */
    public readonly I: Uint8Array;
    /**
     * `p` is the user's password.
     */
    public readonly p: Uint8Array;
    /**
     * `s` is a salt value.
     */
    public readonly s: Uint8Array;
    public readonly group: Group;
    public readonly algorithm: Algorithm;

    /**
     * `x` is a combination of the salt (`s`) and the hashed identity (`I` and `p`).   
     * **Computed as:** `H(s | H ( I | ":" | p) )` where `H(...)` is the chosen hashing algorithm.
     */
    private x?: bigint;
    /**
     * `v` is the server's password verifier, `v = gx` (mod `N`).   
     * **Computed as:** `g^x % N` where `g` is the chosen group's generator, `x` is the computed `x` value, and `N` is the chosen group's prime modulus.   
     * **Note:** Due to limitations with BigInt, `g^x % N` must be calculated using `powMod(g, x, N)` from `util/math`.
     */
    private v?: bigint;

    constructor (config: ClientSetupConfig) {
        this.I = new TextEncoder().encode(config.username);
        this.p = new TextEncoder().encode(config.password);
        this.s = config.salt || random(config.saltLength ?? 192);
        this.group = config.group;
        this.algorithm = config.algorithm;
    }

    /**
     * Computes `v` and `s`, to be used by the server. You can send `encoded.v` and `encoded.s` to the server, along with `I`.
     */
    public async init (): Promise<ClientSetupResult> {
        // compute x and v
        this.x = await this.computeX();
        this.v = await this.computeV();

        const uintV = toUint8Array(this.v);
        return {
            // I is decoded when provided, then encoded again when returned
            // this ensures that the client and server will decode to the same Uint8Array
            I: toString(this.I),
            raw: {
                v: toUint8Array(this.v),
                s: this.s,
            },
            encoded: {
                v: toHex(uintV),
                s: toHex(this.s),
            },
        };
    }

    /**
     * @internal
     */
    private async computeX (): Promise<bigint> {
        // the identity is a combination of: <username>:<password>
        // this is then hashed using the chosen algorithm
        const identity = await hash(this.algorithm, [ this.I, ':', this.p ]);

        // the salt is then appended to the beginning of the hashed identity
        // the result is then hashed again
        const x = await hash(this.algorithm, [ this.s, identity ]);

        // the result is then converted to a bigint for internal processing
        return toBigInt(x);
    }

    /**
     * @internal
     */
    private async computeV (): Promise<bigint> {
        // x is required to compute v
        if (!this.x) {
            throw new SRPError('X has not been computed yet');
        }

        // the verifier is calculated as g ^ x % N
        // powMod must be used, otherwise we will exceed bigint's maximum value
        return powMod(this.group.g, this.x, this.group.N);
    }
}
