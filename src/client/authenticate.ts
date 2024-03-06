/*
 * BSD 3-Clause License
 * Copyright (c) 2024, Ollie Killean
 * License: https://github.com/knokbak/srp-auth
 */

import { SRPError } from '../util/error';
import { Group } from '../util/groups';
import { Algorithm, hash } from '../util/hash';
import { doesMatch, powMod, toBigInt, toHex, toString, toUint8Array } from '../util/math';
import { random } from '../util/random';

export type ClientAuthenticateConfig = {
    username: string;
    password: string;
    group: Group;
    algorithm: Algorithm;
}

export type ClientAuthenticateInit = {
    I: string;
    raw: {
        A: Uint8Array;
    }
    encoded: {
        A: string;
    }
}

export type ClientAuthenticateResult = {
    raw: {
        M1: Uint8Array;
    }
    encoded: {
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
            throw new SRPError('Server-supplied M2 does not match the expected value\nThis is probably a misconfiguration, but possibly a MitM attack!');
        }
    }
}
