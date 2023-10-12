# Sample TOTP generation

This repository holds TypeScript code to illustrate how to easily generate
time-based one-time passwords (TOTP) based on a shared secret. The algorithm has
been defined in [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) and is
used in many MFA applications.

The code has a hard-coded secret that matches the secrets used for the following
two QR codes that can be used with any standard TOTP authenticator app to
register the sample accounts, one providing a 6-digit TOTP, the other providing
an 8-digit TOTP, every 30 seconds.

## Sample 6-digit TOTP QR Code for Registration

![6-digits TOTP](6-digits.png)

## Sample 8-digit TOTP QR Code for Registration

![8-digits TOTP](8-digits.png)

## Usage

To continuously produce current TOTP codes for the above accounts, run

```bash
yarn start
```

This will print out the 6-digit and 8-digit codes for the above accounts with
the start of every new time window.
