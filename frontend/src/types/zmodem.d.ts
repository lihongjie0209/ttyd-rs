declare module 'zmodem.js/src/zmodem_browser' {
    // zmodem.js has no bundled TypeScript declarations.
    // We keep this broad to avoid unsafe runtime assumptions.
    const Zmodem: any;
    export = Zmodem;
}
