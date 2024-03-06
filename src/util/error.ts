/*
 * BSD 3-Clause License
 * Copyright (c) 2024, Ollie Killean
 * License: https://github.com/knokbak/srp-auth
 */

export class SRPError extends Error {
    constructor (message: string) {
        super(message);
        this.name = 'SRPError';
    }
}

export class SRPSecurityViolation extends SRPError {
    constructor (message: string) {
        super(message);
        this.name = 'SRPSecurityViolation';
    }
}
