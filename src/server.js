import "dotenv/config";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import { pool, initDb } from "./db.js";

const app = express();
const PORT = process.env.PORT || 4000;

// ---------- CORS CONFIG ----------
const allowedOrigins = [
  "https://tnemyap.app",
  "https://zknon.com"
];

app.use(
  cors({
    origin: (origin, callback) => {
      // allow non-browser tools (curl, health checks) where origin is undefined
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

// ---------- MIDDLEWARE ----------
app.use(express.json());

// ---------- HELPERS ----------

function sha256Hex(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

// simple numeric conversion, good enough for UI
function toNumber(val) {
  if (val === null || val === undefined) return 0;
  return parseFloat(val);
}

// ---------- ROUTES ----------

// Health check
app.get("/health", (req, res) => {
  res.json({ ok: true, service: "zknon-backend" });
});

/**
 * POST /api/zkproofs/generate
 * body: { walletPubkey: string }
 * return: { zkProofId, note }
 */
app.post("/api/zkproofs/generate", async (req, res) => {
  try {
    const { walletPubkey } = req.body || {};
    if (!walletPubkey || typeof walletPubkey !== "string") {
      return res.status(400).json({ error: "walletPubkey is required" });
    }

    // secret note user keeps
    const note = crypto.randomBytes(32).toString("hex");
    const noteHash = sha256Hex(note);

    // commitment = hash(walletPubkey + ":" + noteHash)
    const rawCommit = `${walletPubkey}:${noteHash}`;
    const commitHash = sha256Hex(rawCommit);
    const zkProofId = "ZKP-" + commitHash.slice(0, 16).toUpperCase();

    await pool.query(
      `
      INSERT INTO zk_proofs (zk_proof_id, wallet_pubkey, note_hash)
      VALUES ($1, $2, $3)
      ON CONFLICT (zk_proof_id) DO NOTHING
      `,
      [zkProofId, walletPubkey, noteHash]
    );

    return res.json({
      zkProofId,
      note
    });
  } catch (err) {
    console.error("generate zkproof error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

/**
 * GET /api/zkproofs?wallet=pubkey
 * return: [{ zkProofId, balance, total, spent, createdAt }]
 */
app.get("/api/zkproofs", async (req, res) => {
  try {
    const wallet = req.query.wallet;
    if (!wallet) {
      return res.status(400).json({ error: "wallet query param is required" });
    }

    const { rows } = await pool.query(
      `
      SELECT zk_proof_id, total_amount, spent_amount, created_at
      FROM zk_proofs
      WHERE wallet_pubkey = $1
      ORDER BY created_at DESC
      `,
      [wallet]
    );

    const result = rows.map((r) => {
      const total = toNumber(r.total_amount);
      const spent = toNumber(r.spent_amount);
      const balance = total - spent;
      return {
        zkProofId: r.zk_proof_id,
        total,
        spent,
        balance,
        createdAt: r.created_at
      };
    });

    res.json({ proofs: result });
  } catch (err) {
    console.error("get zkproofs error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

/**
 * POST /api/deposits
 * body: { walletPubkey, zkProofId, amount, txSignature? }
 */
app.post("/api/deposits", async (req, res) => {
  const client = await pool.connect();
  try {
    const { walletPubkey, zkProofId, amount, txSignature } = req.body || {};

    const amt = Number(amount);
    if (!walletPubkey || !zkProofId || !amt || amt <= 0) {
      return res
        .status(400)
        .json({ error: "walletPubkey, zkProofId and positive amount are required" });
    }

    await client.query("BEGIN");

    const { rows: proofRows } = await client.query(
      `SELECT wallet_pubkey, total_amount, spent_amount FROM zk_proofs WHERE zk_proof_id = $1 FOR UPDATE`,
      [zkProofId]
    );

    if (proofRows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "zk_proof not found" });
    }

    const proof = proofRows[0];

    if (proof.wallet_pubkey !== walletPubkey) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "walletPubkey does not own this zk_proof_id" });
    }

    await client.query(
      `UPDATE zk_proofs SET total_amount = total_amount + $1 WHERE zk_proof_id = $2`,
      [amt, zkProofId]
    );

    await client.query(
      `
      INSERT INTO zk_transfers
      (zk_proof_id, wallet_pubkey, direction, amount, recipient, tx_signature)
      VALUES ($1, $2, 'DEPOSIT', $3, NULL, $4)
      `,
      [zkProofId, walletPubkey, amt, txSignature || null]
    );

    const { rows: updated } = await client.query(
      `SELECT total_amount, spent_amount FROM zk_proofs WHERE zk_proof_id = $1`,
      [zkProofId]
    );

    await client.query("COMMIT");

    const total = toNumber(updated[0].total_amount);
    const spent = toNumber(updated[0].spent_amount);
    const balance = total - spent;

    res.json({ ok: true, zkProofId, balance, total, spent });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("deposit error:", err);
    res.status(500).json({ error: "internal_error" });
  } finally {
    client.release();
  }
});

/**
 * POST /api/withdrawals
 * body: { zkProofId, note, amount, recipient, txSignature? }
 */
app.post("/api/withdrawals", async (req, res) => {
  const client = await pool.connect();
  try {
    const { zkProofId, note, amount, recipient, txSignature } = req.body || {};

    const amt = Number(amount);
    if (!zkProofId || !note || !recipient || !amt || amt <= 0) {
      return res.status(400).json({
        error: "zkProofId, note, recipient and positive amount are required"
      });
    }

    const noteHash = sha256Hex(note);

    await client.query("BEGIN");

    const { rows: proofRows } = await client.query(
      `
      SELECT wallet_pubkey, total_amount, spent_amount, note_hash
      FROM zk_proofs
      WHERE zk_proof_id = $1
      FOR UPDATE
      `,
      [zkProofId]
    );

    if (proofRows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "zk_proof not found" });
    }

    const proof = proofRows[0];

    if (proof.note_hash !== noteHash) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "invalid note for this zk_proof_id" });
    }

    const total = toNumber(proof.total_amount);
    const spent = toNumber(proof.spent_amount);
    const available = total - spent;

    if (available < amt) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "insufficient balance" });
    }

    await client.query(
      `UPDATE zk_proofs SET spent_amount = spent_amount + $1 WHERE zk_proof_id = $2`,
      [amt, zkProofId]
    );

    await client.query(
      `
      INSERT INTO zk_transfers
      (zk_proof_id, wallet_pubkey, direction, amount, recipient, tx_signature)
      VALUES ($1, $2, 'WITHDRAW', $3, $4, $5)
      `,
      [zkProofId, proof.wallet_pubkey, amt, recipient, txSignature || null]
    );

    const { rows: updated } = await client.query(
      `SELECT total_amount, spent_amount FROM zk_proofs WHERE zk_proof_id = $1`,
      [zkProofId]
    );

    await client.query("COMMIT");

    const newTotal = toNumber(updated[0].total_amount);
    const newSpent = toNumber(updated[0].spent_amount);
    const balance = newTotal - newSpent;

    res.json({ ok: true, zkProofId, balance, total: newTotal, spent: newSpent });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("withdraw error:", err);
    res.status(500).json({ error: "internal_error" });
  } finally {
    client.release();
  }
});

/**
 * GET /api/history?wallet=pubkey
 */
app.get("/api/history", async (req, res) => {
  try {
    const wallet = req.query.wallet;
    if (!wallet) {
      return res.status(400).json({ error: "wallet query param is required" });
    }

    const { rows } = await pool.query(
      `
      SELECT zk_proof_id, direction, amount, recipient, tx_signature, created_at
      FROM zk_transfers
      WHERE wallet_pubkey = $1
      ORDER BY created_at DESC
      LIMIT 200
      `,
      [wallet]
    );

    const result = rows.map((r) => ({
      zkProofId: r.zk_proof_id,
      type: r.direction,
      amount: toNumber(r.amount),
      recipient: r.recipient,
      txSignature: r.tx_signature,
      createdAt: r.created_at
    }));

    res.json({ history: result });
  } catch (err) {
    console.error("history error:", err);
    res.status(500).json({ error: "internal_error" });
  }
});

// ---------- START SERVER ----------
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`ZKNON backend listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("DB init error:", err);
    process.exit(1);
  });
