# Check Receipt

A public, standalone page that lets anyone check an Agent Pay receipt for themselves, in their own browser. It is part of the Agent Pay demo, but it is its own project: no server of its own, no dependencies, nothing to install or build. The demo app serves its five public files at **`/check-receipt`**, and any static web server would serve them the same way.

## What it does

It guides a visitor through the chain of trust behind one purchase, and checks each link:

| # | Link | Checked with |
|---|------|--------------|
| 1 | The purchase (store, item, price, order id) | Used by the later steps |
| 2 | **What the user allowed**: the open mandate | The user's public key |
| 3 | **What the agent committed to**: the closed mandate, and whether the order is inside the user's limits | The agent key named *inside* the open mandate |
| 4 | **What the store accepted**: the mandate receipt and payment receipt | The store's public key (fetchable from the store's own catalog) |
| 5 | **Who called the store**: the agent's signed HTTP request (RFC 9421, as in Visa's TAP) | The same agent key |
| 6 | **Did the person really say yes?**: the Keycloak ID tokens from granting the mandate and approving the purchase, each bound to the exact terms | Keycloak's public keys (fetchable from the realm) |
| 7 | **Did the money move?**: the transfer on the network | The transaction receipt (fetchable from a node) |

Two ways in:

- **One file.** Load an evidence bundle (`evidence-ord_….json`) and every field fills in and every link is checked at once.
- **A series of proofs.** Provide the pieces one at a time. Whatever has been given is checked; the page says what is still missing. A public receipt link alone is enough for step 4. The page can fetch the order, the store's key and Keycloak's keys itself, from the servers that publish them, so the check does not rely on the bundle's own copies.

"Try an example" loads a synthetic bundle (made with throwaway keys, including a stand-in for Keycloak), and "Try to break it" changes a price, swaps a key or corrupts a signature so you can see which link fails and why.

## Privacy and safety

- Everything pasted or loaded stays in the tab. The page only contacts a server when a button says it will (fetching a key, an order or a transaction), and it never sends cookies to any server but its own.
- It loads no third-party scripts, fonts or images; a Content-Security-Policy in the page enforces that.
- It shows every user-supplied value as text, never as markup.

## What it cannot tell you

Written on the page too: where a key came from (keys inside a bundle are only as trustworthy as the bundle, so the page labels each key's source), whether a sign-in was a passkey, whether the user's signing key was used only with consent, which purchase mode the store ran (a bundle with no approval reads as an autonomous purchase), the total budget, and revocation after the fact.

## Files

| File | What it is |
|------|------------|
| `index.html`, `check.css` | The page and its styles |
| `app.js` | The interface: collects the pieces, runs the checks, explains each one |
| `verify.js` | The verifier: plain functions over WebCrypto (Ed25519 and RSA-SHA256). Runs in a browser and under Node 20+ |
| `example-bundle.json` | The synthetic example, made by `tools/make-example.mjs` |
| `test/` | Tests (see below) |

## Tests

```bash
cd check-receipt && node --test test/
```

`verify.js` is a second, independent implementation of `agent-wallet-demo/wallet-service/evidence.mjs`. `test/parity.test.mjs` builds bundles with the wallet service's own signing code, honest and tampered in more than twenty-five ways (prices, keys, signatures, receipts, requests, sign-in proofs, chain receipts), and requires both verifiers to reach the same verdict step by step. The tests and `tools/make-example.mjs` need the sibling `agent-wallet-demo` folder; the page itself does not.

Real data was checked too: a purchase with real Keycloak sign-ins and a real transfer on the test network verifies end to end, and gets the same verdict from both verifiers.

## Hosting

The demo app serves `index.html`, `check.css`, `app.js`, `verify.js` and `example-bundle.json` at `/check-receipt/` (and redirects `/check-receipt`), with no login. Nothing else in this folder is reachable. To host it elsewhere, copy those five files to any static host. Fetching keys from another site needs that site to allow it (CORS); where it does not, the page says so and you can paste the key instead.
