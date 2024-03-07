/*
 * BSD 3-Clause License
 * Copyright (c) 2024, Ollie Killean
 * License: https://github.com/knokbak/srp-auth
 */

import { SRPError, SRPSecurityViolation } from '../util/error';
import { toBigInt, toHex, toUint8Array } from '../util/math';

export type ServerSetupConfig = {
    I: string;
    s: string | Uint8Array;
    v: string | Uint8Array;
}

export type ServerSetupResult = {
    username: string;
    salt: string;
    verifier: string;
}

export class ServerSetup {
    /**
     * The user's identity (`I`) in plain text. Usually a username.
     */
    private I: string;
    /**
     * The user's salt (`s`).
     */
    private s: Uint8Array;
    /**
     * The user's verifier (`v`).
     */
    private v: bigint;

    constructor (config: ServerSetupConfig) {
        this.I = config.I;
        this.s = typeof config.s === 'string' ? toUint8Array(config.s) : config.s;
        this.v = typeof config.v === 'string' ? BigInt(`0x${config.v}`) : toBigInt(config.v);
    }

    /**
     * Verify the user's credentials meet the requirements.
     */
    public async verify (): Promise<ServerSetupResult> {
        if (this.I.length === 0) {
            throw new SRPError('I must not be empty');
        }

        if (this.s.length === 0 || toBigInt(this.s) === 0n) {
            throw new SRPSecurityViolation('s must not be empty or equal zero');
        }

        if (this.v === 0n) {
            throw new SRPSecurityViolation('v must not be zero');
        }

        return this.getCredentials();
    }

    /**
     * Get the user's credentials. These should be stored to the database.
     */
    public getCredentials (): ServerSetupResult {
        return {
            username: this.I,
            salt: toHex(this.s),
            verifier: toHex(this.v),
        };
    }
}
