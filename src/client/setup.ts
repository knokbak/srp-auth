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
    username: string;
    password: string;
    salt?: Uint8Array;
    saltLength?: number;
    group: Group;
    algorithm: Algorithm;
}

export type ClientSetupResult = {
    I: string;
    raw: {
        v: Uint8Array;
        s: Uint8Array;
    }
    encoded: {
        v: string;
        s: string;
    }
}

export class ClientSetup {
    public readonly I: Uint8Array;
    public readonly p: Uint8Array;
    public readonly s: Uint8Array;
    public readonly group: Group;
    public readonly algorithm: Algorithm;

    private x?: bigint;
    private v?: bigint;

    constructor (config: ClientSetupConfig) {
        this.I = new TextEncoder().encode(config.username);
        this.p = new TextEncoder().encode(config.password);
        this.s = config.salt || random(config.saltLength ?? 192);
        this.group = config.group;
        this.algorithm = config.algorithm;
    }

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
