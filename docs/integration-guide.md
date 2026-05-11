# Pruv dApp Integration Guide

> **Development Status (April 2026):** Pruv is not yet deployed to any public network. There is no hosted RPC endpoint, no published npm package, and no live API service.
>
> This guide documents the **intended integration API** and **local self-hosted** setup that works today. Sections that describe future hosted services are clearly marked.

---

## 1. Use the SDK (Local / Monorepo)

The `@pruv/sdk` package lives in `sdk/` and is not yet published to npm. To use it from another package in this monorepo:

```bash
# From the repo root
pnpm install
pnpm --filter @pruv/sdk build
```

Then reference it from your package:

```jsonc
// package.json
{
  "dependencies": {
    "@pruv/sdk": "workspace:*"
  }
}
```

> **Planned:** Once the network launches, `@pruv/sdk` will be published to npm and installable via `npm install @pruv/sdk`.

---

## 2. Replace Your Connection

The simplest integration is a one-line swap of your Solana `Connection`. This works today against a **locally running** Pruv RPC proxy (see [Section 7](#7-run-the-rpc-proxy-locally)).

```ts
// Before
import { Connection } from "@solana/web3.js";
const connection = new Connection("https://api.mainnet-beta.solana.com");

// After
import { PruvConnection } from "@pruv/sdk";
const connection = PruvConnection.create(
  "http://localhost:8899",  // locally running Pruv RPC proxy
  "dev-api-key-000"         // any string works in BYPASS_AUTH=true mode
);
```

All existing code using `connection` works without changes. The proxy transparently blocks any transaction that targets an un-attested program before it reaches Solana.

---

## 3. Check Attestation Status

Display a trust badge in your UI before a user signs a transaction:

```ts
import { PruvClient } from "@pruv/sdk";

const client = new PruvClient({
  rpcProxyUrl: "http://localhost:8899",
  apiKey: "dev-api-key-000",
});

// In your transaction handler:
async function sendWithTrustCheck(programId: string) {
  const status = await client.getAttestationStatus(programId);

  if (!status.isAttested) {
    // Show warning UI
    throw new Error(`⚠️ Program not attested. Trust score: ${status.trustScore}/100`);
  }

  console.log(`✅ Program attested by ${status.nodeCount} nodes. Score: ${status.trustScore}/100`);
  // Proceed with transaction...
}
```

---

## 4. Hard-Gate with assertAttested

For maximum safety, throw before building the transaction:

```ts
// This throws with a descriptive error if the program is not attested.
await client.assertAttested("YourProgramIdHere...");

// Safe to continue — the program is ZK-attested.
const tx = await program.methods.myInstruction(args).rpc();
```

---

## 5. Display dApp Info

Show users information about a dApp from the Pruv registry:

```ts
const info = await client.getDappInfo("YourProgramIdHere...");

if (info) {
  console.log(`Name: ${info.name}`);
  console.log(`Attested: ${info.attestation?.isAttested}`);
  console.log(`Expires: ${new Date(info.attestation!.expiresAt * 1000).toLocaleDateString()}`);
}
```

---

## 6. React Hook Example

```tsx
import { useState, useEffect } from "react";
import { PruvClient, type AttestationStatus } from "@pruv/sdk";

const client = new PruvClient({
  rpcProxyUrl: process.env.NEXT_PUBLIC_PRUV_RPC!,
  apiKey: process.env.NEXT_PUBLIC_PRUV_API_KEY,
});

function TrustBadge({ programId }: { programId: string }) {
  const [status, setStatus] = useState<AttestationStatus | null>(null);

  useEffect(() => {
    client.getAttestationStatus(programId).then(setStatus);
  }, [programId]);

  if (!status) return <span>Checking trust…</span>;

  return status.isAttested ? (
    <span style={{ color: "green" }}>
      ✅ ZK Attested ({status.nodeCount} nodes, score {status.trustScore}/100)
    </span>
  ) : (
    <span style={{ color: "red" }}>
      ⚠️ Not Attested — interact at your own risk
    </span>
  );
}
```

---

## 7. Run the RPC Proxy Locally

```bash
git clone https://github.com/nzengi/pruv-solana.git
cd pruv-solana/rpc-client

cp ../.env.example .env
# Edit .env:
#   UPSTREAM_RPC_URL=https://api.devnet.solana.com
#   BYPASS_AUTH=true   (skips credit checks in dev mode)

pnpm install
pnpm dev
```

Point your dApp at `http://localhost:8899`.

---

## 8. Register Your dApp On-Chain

> **Not yet available.** On-chain programs are planned for Q3 2026. The interface below shows the intended workflow.

```bash
# anchor build  (from repo root)
# Once programs are deployed to devnet, registration will work via:
#
# npx @pruv/cli register-dapp \
#   --program-id <YOUR_PROGRAM_ID> \
#   --name "My dApp" \
#   --cluster devnet \
#   --keypair ~/.config/solana/id.json
```

Once registered, Pruv nodes will automatically detect your program, generate a ZK code integrity proof, and submit it on-chain within one attestation interval (default: 1 hour).

---

## 9. Environment Variables (Next.js / Vite)

```bash
# .env.local — local development
NEXT_PUBLIC_PRUV_RPC=http://localhost:8899
NEXT_PUBLIC_PRUV_API_KEY=dev-api-key-000
```

```ts
import { PruvClient } from "@pruv/sdk";
const client = new PruvClient({
  rpcProxyUrl: process.env.NEXT_PUBLIC_PRUV_RPC!,
  apiKey: process.env.NEXT_PUBLIC_PRUV_API_KEY,
});
```

---

## Source

- GitHub: https://github.com/nzengi/pruv-solana