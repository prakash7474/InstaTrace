# TODO

- [ ] Add Instagram DM encrypt/decrypt module using AES-256-GCM (`InstagramDMEncryptor`).
- [ ] Integrate into packet analysis flow (trigger when traffic looks like a potential DM payload; initially a safe metadata-based trigger).
- [ ] Extend packet parser/detectors to surface a trigger signal (e.g., suspicious HTTP host/path + TLS presence) without decrypting traffic.
- [x] Implement encryption demo output into alerts log when trigger fires (payload encrypted/decrypted locally for verification).

- [x] Add dependency `cryptography` to `requirements.txt`.

- [x] Update README with new behavior/feature explanation.

- [ ] Run a quick CLI sanity test (no capture required): encrypt/decrypt demo path.

