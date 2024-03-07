/*
 * BSD 3-Clause License
 * Copyright (c) 2024, Ollie Killean
 * License: https://github.com/knokbak/srp-auth
 */

import { SRPError, SRPSecurityViolation } from '../util/error';
import { Group } from '../util/groups';
import { Algorithm, hash } from '../util/hash';
import { doesMatch, powMod, toBigInt, toHex, toString, toUint8Array } from '../util/math';
import { random } from '../util/random';

export type ClientAuthenticateConfig = {
    /**
     * The username used for authentication.
     */
    username: string;
    /**
     * The plain text password. There is no need to hash this beforehand!
     */
    password: string;
    /**
     * The SRP group to use. The built-in groups are from [RFC 5054](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A).
     */
    group: Group;
    /**
     * The hashing algorithm to use.
     */
    algorithm: Algorithm;
}

export type ClientAuthenticateInit = {
    /**
     * The username in plain text. This should be sent to the server, **not the original username provided to the library**!
     */
    I: string;
    raw: {
        /**
         * The client's ephemeral session key (`A`) as a Uint8Array.
         */
        A: Uint8Array;
    }
    encoded: {
        /**
         * The client's ephemeral session key (`A`) encoded as hex.
         */
        A: string;
    }
}

export type ClientAuthenticateResult = {
    raw: {
        /**
         * The client's authentication key (`M1`), derived from `N`, `g`, `s`, `A`, `B`, `I` and `K`, as a Uint8Array.
         */
        M1: Uint8Array;
    }
    encoded: {
        /**
         * The client's authentication key (`M1`) encoded as hex.
         */
        M1: string;
    }
}

export class ClientAuthenticate {
    public readonly I: Uint8Array;
    public readonly p: Uint8Array;
    public readonly group: Group;
    public readonly algorithm: Algorithm;

    private a?: bigint;
    private A?: bigint;
    private B?: bigint;
    private u?: bigint;
    private s?: bigint;

    private S?: bigint;
    private K?: Uint8Array;
    private M1?: Uint8Array;

    constructor (config: ClientAuthenticateConfig) {
        this.I = new TextEncoder().encode(config.username);
        this.p = new TextEncoder().encode(config.password);
        this.group = config.group;
        this.algorithm = config.algorithm;
    }

    /**
     * Computes `A`, the client's ephemeral session key. This should be sent to the server, along with `I`.
     */
    public async init (): Promise<ClientAuthenticateInit> {
        // generate a random 256 bit value (session key)
        const A = this.computeA();
        this.A = A;

        return {
            I: toString(this.I),
            raw: {
                A: toUint8Array(A),
            },
            encoded: {
                A: toHex(toUint8Array(A)),
            },
        };
    }

    private computeA (): bigint {
        // generate a random 256 bit value (ephemeral session key)
        const a = random(256);
        this.a = toBigInt(a);

        // A = g ^ a % N
        const A = powMod(this.group.g, this.a, this.group.N);
        return A;
    }

    /**
     * Computes `u` (a combination of both the client and server's ephemeral session keys `A` and `B`), `S` (the session key) and `K` (the client's key).
     * @param B The server's ephemeral session key (`B`), which should be provided by the server. If a string is provided, it must be hex encoded.
     * @param s The salt (`s`) which was originally calculated by the client but is now stored by the server. If a string is provided, it must be hex encoded.
     */
    public async exchange (B: string | Uint8Array, s: string | Uint8Array): Promise<void> {
        if (!this.A) {
            throw new SRPError('A must be set before exchanging B');
        }

        if (typeof B === 'string') {
            B = toUint8Array(B);
        }
        this.B = toBigInt(B);

        if (typeof s === 'string') {
            s = toUint8Array(s);
        }
        this.s = toBigInt(s);

        if (this.B === 0n) {
            throw new SRPError('Invalid server-supplied public key: B = 0\nThis is probably a misconfiguration, but possibly a MitM attack!');
        }

        this.u = await this.computeU();
        if (this.u === 0n) {
            throw new SRPError('Invalid keys: u = 0\nThis is probably a misconfiguration, but possibly a MitM attack!');
        }

        this.S = await this.computeS();
        this.K = await hash(this.algorithm, [ toUint8Array(this.S) ]);
    }

    private async computeU (): Promise<bigint> {
        if (!this.A || !this.B) {
            throw new SRPError('A and B must be set before computing u');
        }

        // U = H(A, B)
        const u = await hash(this.algorithm, [ toUint8Array(this.A), toUint8Array(this.B) ]);
        return toBigInt(u);
    }

    private async computeS (): Promise<bigint> {
        if (!this.a || !this.B || !this.u) {
            throw new SRPError('a, B, and u must be set before computing S');
        }

        // S = (B - k * g^x) ^ (a + u * x) % N
        const k = await this.computeK();
        const x = await this.computeX();
        return powMod(this.B - k * powMod(this.group.g, x, this.group.N), this.a + this.u * x, this.group.N);
    }

    private async computeK (): Promise<bigint> {
        const k = await hash(this.algorithm, [ toUint8Array(this.group.N), toUint8Array(this.group.g) ]);
        return toBigInt(k);
    }

    private async computeX (): Promise<bigint> {
        if (!this.s) {
            throw new SRPError('s must be set before computing x');
        }

        const identity = await hash(this.algorithm, [ this.I, ':', this.p ]);
        const x = await hash(this.algorithm, [ toUint8Array(this.s), identity ]);
        return toBigInt(x);
    }

    /**
     * Computes `M1` which can be used by the server to verify the client's authenticity, without sending the user's password in plain text.
     */
    public async authenticate (): Promise<ClientAuthenticateResult> {
        if (!this.s || !this.A || !this.B || !this.K) {
            throw new SRPError('s, A, B, and K must be set before authenticating');
        }

        // M1 = H(H(N) XOR H(g), H(I), s, A, B, K)
        const N = toUint8Array(this.group.N);
        const g = toUint8Array(this.group.g);
        const s = toUint8Array(this.s);
        const A = toUint8Array(this.A);
        const B = toUint8Array(this.B);

        const [HN, Hg] = await Promise.all([hash(this.algorithm, [ N ]), hash(this.algorithm, [ g ])]);
        const HX = new Uint8Array(HN.length);
        for (let i = 0; i < HN.length; i++) {
            HX[i] = HN[i] ^ Hg[i];
        }

        const M1 = await hash(this.algorithm, [ HX, this.I, s, A, B, this.K ]);
        this.M1 = M1;
        return {
            raw: {
                M1,
            },
            encoded: {
                M1: toHex(M1),
            },
        };
    }

    /**
     * Verifies that the server holds the verifier (`v`) that was originally created by the client during setup. This authenticates the server.
     * > ⚠️ **Warning**: `verifyServer(...)` will throw an `SRPSecurityViolation` if `M2` does not match its expected value. If an error is thrown, the client may still have passed authentication, but the server **cannot** be trusted. The server is either misconfigured, or is a malicious attacker who is blindly accepting anything you throw at them. You may be caught in the middle of a MitM attack!
     * @param M2 The server's authentication key (`M2`), which should be provided by the server. If a string is provided, it must be hex encoded.
     * @throws {SRPSecurityViolation} if `M2` does not match its expected value.
     */
    public async verifyServer (M2: string | Uint8Array): Promise<void> {
        if (!this.A || !this.M1 || !this.K) {
            throw new SRPError('A, M1, and K must be set before verifying the server');
        }

        const A = toUint8Array(this.A);
        const expected = await hash(this.algorithm, [ A, this.M1, this.K ]);

        if (typeof M2 === 'string') {
            M2 = toUint8Array(M2);
        }

        if (doesMatch(expected, M2)) {
            throw new SRPSecurityViolation('Server-supplied M2 does not match the expected value\nThis is probably a misconfiguration, but possibly a MitM attack!');
        }
    }
}
