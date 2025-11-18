import express from "express";
import cors from "cors";
import Database from "better-sqlite3";
import { createHash, randomBytes } from "crypto";
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  LAMPORTS_PER_SOL,
  Keypair,
} from "@solana/web3.js";
import bs58 from "bs58";
import dotenv from "dotenv";

dotenv.config();

// ------------------ CONFIG ------------------

const PORT = process.env.PORT || 3000;

// RPC (Tatum mainnet)
const RPC_ENDPOINT =
  process.env.RPC_ENDPOINT || "https://solana-mainnet.gateway.tatum.io/";
const TATUM_API_KEY = process.env.TATUM_API_KEY;

// Pool keypair (from env)
let poolKeypair = null;
if (process.env.POOL_SECRET_KEY_BASE58) {
  try {
    const secret = bs58.decode(process.env.POOL_SECRET_KEY_BASE58.trim());
    poolKeypair = Keypair.fromSecretKey(secret);
    console.log(
      "[ZKNON] Loaded pool keypair:",
      poolKeypair.publicKey.toBase58()
    );
  } catch (err) {
    console.error("[ZKNON] Failed to decode POOL_SECRET_KEY_BASE58:", err);
  }
} else {
  console.warn(
    "[ZKNON] POOL_SECRET_KEY_BASE58 is not set. Withdrawals will not send SOL."
  );
}

const POOL_ADDRESS =
  process.env.POOL_PUBKEY ||
  (poolKeypair ? poolKeypair.publicKey.toBase58() : null) ||
  "8hGDXBJqpCZvWaDcbvXykRSb1bKbbJ5Ji4c85ubYvkaA";

const connection = new Connection(RPC_ENDPOINT, {
  commitment: "confirmed",
  httpHeaders: TATUM_API_KEY ? { "x-api-key": TATUM_API_KEY } : undefined,
});

// ------------------ DB SETUP ------------------

const db = new Database("zknon.db");
db.pragma("journal_mode = wal");

db.exec(`
  CREATE TABLE IF NOT EXISTS zk_proofs (
    id TEXT PRIMARY KEY,
    wallet_pubkey TEXT NOT NULL,
    note_hash TEXT NOT NULL,
    total REAL NOT NULL DEFAULT 0,
    spent REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_pubkey TEXT NOT NULL,
    zk_proof_id TEXT NOT NULL,
    type TEXT NOT NULL, -- 'DEPOSIT' | 'WITHDRAW'
    amount REAL NOT NULL,
    recipient TEXT,
    tx_signature TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING', -- 'PENDING' | 'CONFIRMED' | 'FAILED'
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// ------------------ HELPERS ------------------

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function generateZkProofId() {
  const partA = randomBytes(4).toString("hex").toUpperCase();
  const partB = randomBytes(3).toString("hex").toUpperCase();
  return `ZKP-${partA}${partB}`;
}

function generateSecretNote() {
  return randomBytes(32).toString("hex");
}

async function sendFromPool(recipientAddress, amountSol) {
  if (!poolKeypair) {
    throw new Error("Pool keypair not configured on server.");
  }

  const recipient = new PublicKey(recipientAddress);
  const lamports = Math.round(amountSol * LAMPORTS_PER_SOL);

  const latest = await connection.getLatestBlockhash("finalized");

  const tx = new Transaction({
    recentBlockhash: latest.blockhash,
    feePayer: poolKeypair.publicKey,
  });

  tx.add(
    SystemProgram.transfer({
      fromPubkey: poolKeypair.publicKey,
      toPubkey: recipient,
      lamports,
    })
  );

  tx.sign(poolKeypair);

  const signature = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
  });

  try {
    await connection.confirmTransaction(
      {
        signature,
        blockhash: latest.blockhash,
        lastValidBlockHeight: latest.lastValidBlockHeight,
      },
      "confirmed"
    );
  } catch (err) {
    console.warn(
      "[ZKNON] confirmTransaction warning (tx may still be valid):",
      err
    );
  }

  return signature;
}

// ------------------ APP & MIDDLEWARE ------------------

const app = express();
app.use(express.json());

// CORS
const allowedOrigins = [
  "https://tnemyap.app",
  "https://tnemyap.app/",
  "https://zknon.com",
  "https://zknon.com/",
  "http://localhost:3000",
  "http://localhost:5173",
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS: " + origin));
    },
  })
);

// ------------------ ROUTES ------------------

// Health
app.get("/health", (req, res) => {
  res.json({ ok: true, poolAddress: POOL_ADDRESS });
});

// Generate zk proof id + secret note
app.post("/api/zkproofs/generate", (req, res) => {
  const { walletPubkey } = req.body || {};
  if (!walletPubkey) {
    return res.status(400).json({ error: "walletPubkey is required" });
  }

  const zkProofId = generateZkProofId();
  const note = generateSecretNote();
  const noteHash = sha256(note);
  const createdAt = new Date().toISOString();

  const existing = db
    .prepare("SELECT id FROM zk_proofs WHERE id = ?")
    .get(zkProofId);
  if (existing) {
    return res.status(500).json({ error: "ID collision, retry request" });
  }

  db.prepare(
    `
    INSERT INTO zk_proofs (id, wallet_pubkey, note_hash, total, spent, created_at)
    VALUES (?, ?, ?, 0, 0, ?)
  `
  ).run(zkProofId, walletPubkey, noteHash, createdAt);

  return res.json({
    zkProofId,
    note,
  });
});

// List zk proofs for a wallet
app.get("/api/zkproofs", (req, res) => {
  const { wallet } = req.query;
  if (!wallet) {
    return res.status(400).json({ error: "wallet is required" });
  }

  const rows = db
    .prepare(
      `
    SELECT id, wallet_pubkey, note_hash, total, spent, created_at
    FROM zk_proofs
    WHERE wallet_pubkey = ?
    ORDER BY datetime(created_at) DESC
  `
    )
    .all(wallet);

  const proofs = rows.map((r) => {
    const total = Number(r.total || 0);
    const spent = Number(r.spent || 0);
    const balance = total - spent;
    return {
      zkProofId: r.id,
      walletPubkey: r.wallet_pubkey,
      total,
      spent,
      balance,
      createdAt: r.created_at,
    };
  });

  res.json({ proofs });
});

// Record deposit (front-end already sent real mainnet tx)
app.post("/api/deposits", (req, res) => {
  const { walletPubkey, zkProofId, amount, txSignature } = req.body || {};
  if (!walletPubkey || !zkProofId || !amount || !txSignature) {
    return res.status(400).json({
      error: "walletPubkey, zkProofId, amount, txSignature are required",
    });
  }

  const proof = db
    .prepare("SELECT * FROM zk_proofs WHERE id = ? AND wallet_pubkey = ?")
    .get(zkProofId, walletPubkey);

  if (!proof) {
    return res
      .status(404)
      .json({ error: "zk_proof not found for this wallet" });
  }

  const amt = Number(amount);
  if (!(amt > 0)) {
    return res.status(400).json({ error: "amount must be > 0" });
  }

  const createdAt = new Date().toISOString();

  const tx = db.transaction(() => {
    db.prepare("UPDATE zk_proofs SET total = total + ? WHERE id = ?").run(
      amt,
      zkProofId
    );

    db.prepare(
      `
      INSERT INTO transactions
      (wallet_pubkey, zk_proof_id, type, amount, recipient, tx_signature, status, created_at)
      VALUES (?, ?, 'DEPOSIT', ?, ?, ?, 'CONFIRMED', ?)
    `
    ).run(walletPubkey, zkProofId, amt, "shielded_pool", txSignature, createdAt);
  });

  tx();

  res.json({ ok: true });
});

// Create withdrawal (zk_proof_id + secret_note) + async on-chain send
app.post("/api/withdrawals", async (req, res) => {
  const { zkProofId, note, amount, recipient } = req.body || {};
  if (!zkProofId || !note || !amount || !recipient) {
    return res.status(400).json({
      error: "zkProofId, note, amount, recipient are required",
    });
  }

  if (!poolKeypair) {
    return res
      .status(500)
      .json({ error: "Withdrawals are not configured on this server." });
  }

  const proof = db
    .prepare("SELECT * FROM zk_proofs WHERE id = ?")
    .get(zkProofId);
  if (!proof) {
    return res.status(404).json({ error: "zk_proof not found" });
  }

  const expectedHash = proof.note_hash;
  const givenHash = sha256(note);
  if (expectedHash !== givenHash) {
    return res
      .status(403)
      .json({ error: "Invalid secret_note for this zk_proof_id" });
  }

  const amt = Number(amount);
  if (!(amt > 0)) {
    return res.status(400).json({ error: "amount must be > 0" });
  }

  const currentBalance = Number(proof.total || 0) - Number(proof.spent || 0);
  if (amt > currentBalance + 1e-9) {
    return res.status(400).json({ error: "Insufficient shielded balance" });
  }

  const createdAt = new Date().toISOString();

  // Create DB record with PENDING and lock the shielded funds
  let txId;
  const tx = db.transaction(() => {
    db.prepare("UPDATE zk_proofs SET spent = spent + ? WHERE id = ?").run(
      amt,
      zkProofId
    );

    const info = db
      .prepare(
        `
        INSERT INTO transactions
        (wallet_pubkey, zk_proof_id, type, amount, recipient, tx_signature, status, created_at)
        VALUES (?, ?, 'WITHDRAW', ?, ?, NULL, 'PENDING', ?)
      `
      )
      .run(proof.wallet_pubkey, zkProofId, amt, recipient, createdAt);

    txId = info.lastInsertRowid;
  });
  tx();

  // Respond immediately: client will see "processing" in history
  res.json({ status: "PENDING", id: txId });

  // Fire-and-forget async job to send SOL from pool to recipient
  (async () => {
    try {
      console.log(
        "[ZKNON] Sending withdraw from pool:",
        POOL_ADDRESS,
        "->",
        recipient,
        "amount:",
        amt
      );
      const signature = await sendFromPool(recipient, amt);
      console.log("[ZKNON] Withdraw tx signature:", signature);

      db.prepare(
        "UPDATE transactions SET status = ?, tx_signature = ? WHERE id = ?"
      ).run("CONFIRMED", signature, txId);
    } catch (err) {
      console.error("[ZKNON] Withdraw send error:", err);

      const tx2 = db.transaction(() => {
        db.prepare("UPDATE transactions SET status = ? WHERE id = ?").run(
          "FAILED",
          txId
        );
        // return shielded funds back to balance if on-chain send failed
        db.prepare("UPDATE zk_proofs SET spent = spent - ? WHERE id = ?").run(
          amt,
          zkProofId
        );
      });
      tx2();
    }
  })();
});

// History for a wallet
app.get("/api/history", (req, res) => {
  const { wallet } = req.query;
  if (!wallet) {
    return res.status(400).json({ error: "wallet is required" });
  }

  const rows = db
    .prepare(
      `
    SELECT id, wallet_pubkey, zk_proof_id, type, amount, recipient,
           tx_signature, status, created_at
    FROM transactions
    WHERE wallet_pubkey = ?
    ORDER BY datetime(created_at) DESC, id DESC
  `
    )
    .all(wallet);

  const history = rows.map((r) => ({
    id: r.id,
    walletPubkey: r.wallet_pubkey,
    zkProofId: r.zk_proof_id,
    type: r.type,
    amount: Number(r.amount || 0),
    recipient: r.recipient,
    txSignature: r.tx_signature,
    status: r.status,
    createdAt: r.created_at,
  }));

  res.json({ history });
});

// ------------------ START ------------------

app.listen(PORT, () => {
  console.log(`[ZKNON] Backend listening on port ${PORT}`);
  console.log("[ZKNON] Pool address:", POOL_ADDRESS);
});
