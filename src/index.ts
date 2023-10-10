import * as crypto from 'crypto';

// Input for QR code:
// otpauth://totp/Example%20Provider-1:user@example.com?secret=JJJJJJJJJJ&issuer=Example%20Provider
// otpauth://totp/Example%20Provider-2:user@example.com?secret=JJJJJJJJJJ&issuer=Example%20Provider&digits=8
// See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
// See e.g. https://www.npmjs.com/package/qrcode for creating QR codes

const Base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const X = 30; // 30 seconds default time window for a TOTP code
const ModulusForDigits = { 6: 1_000_000, 8: 100_000_000, };

const Secret = 'JJJJJJJJJJ';
const DecodedSecret = base32Decode(Secret);

function decodeChar(char: string) {
    const idx = Base32Alphabet.indexOf(char);

    if (idx === -1) {
        throw new Error('invalid base32 character: ' + char);
    }

    return idx;
}

function base32Decode(input: string) {
    input = input.replace(/=+$/, '');

    const length = input.length;

    let curBits = 0;
    let curValue = 0;

    const output = new Uint8Array((length * 5 / 8) | 0);
    let outputOffset = 0;

    for (var i = 0; i < length; i++) {
        curValue = (curValue << 5) | decodeChar(input[i]);
        curBits += 5;

        if (curBits >= 8) {
            output[outputOffset++] = (curValue >>> (curBits - 8)) & 255;
            curBits -= 8;
        }
    }

    return output;
}

function getTimeId() {
    return Math.floor(new Date().valueOf() / 1000 / X);
}

function createTotpInput(time: number) {
    const b = Buffer.allocUnsafe(8);
    b.writeBigUint64BE(BigInt(time));

    return b;
}

async function generateTotpHash(secret: Uint8Array, timeId: Uint8Array) {
    const key = await crypto.subtle.importKey(
        'raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const hmac = await crypto.subtle.sign('HMAC', key, timeId);

    return Buffer.from(hmac);
}

function extractOtp(otpHash: Uint8Array, numDigits: 6 | 8) {
    const offset = otpHash[otpHash.length - 1] & 0x0f;
    const binCode =
        (otpHash[offset] & 0x7f) << 24 |
        (otpHash[offset + 1] & 0xff) << 16 |
        (otpHash[offset + 2] & 0xff) << 8 |
        (otpHash[offset + 3] & 0xff);

    const rawOtp = binCode % ModulusForDigits[numDigits];
    let otpStr = rawOtp.toString();

    while (otpStr.length < numDigits) {
        otpStr = "0" + otpStr;
    }

    const result = otpStr.substring(0, numDigits / 2) + ' ' +
        otpStr.substring(numDigits / 2);

    return result;
}

async function run() {
    for (; ;) {
        const totpHashInput = createTotpInput(getTimeId());
        const hash = await generateTotpHash(DecodedSecret, totpHashInput);
        const totp6 = extractOtp(hash, 6);
        const totp8 = extractOtp(hash, 8);

        console.info(new Date(), '\t', 'totp6:', totp6, '\t', 'totp8:', totp8);

        // Calculate the time to sleep until the next token is issued.
        const curTime = new Date();
        const curMs = curTime.getSeconds() * 1000 + curTime.getMilliseconds();
        const timeToSleep = (X * 1000) - (curMs % (X * 1000));

        await sleep(timeToSleep);
    }
}

function sleep(timeMs: number) {
    return new Promise<void>((resolve, _) => {
        setTimeout(() => resolve(), timeMs);
    });
}

run();
