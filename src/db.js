import pg from "pg";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

export async function initDb() {
  // Table komitmen ZK
  await pool.query(`
    CREATE TABLE IF NOT EXISTS zk_proofs (
      id SERIAL PRIMARY KEY,
      zk_proof_id TEXT UNIQUE NOT NULL,
      wallet_pubkey TEXT NOT NULL,
      note_hash TEXT NOT NULL,
      total_amount NUMERIC(36,9) NOT NULL DEFAULT 0,
      spent_amount NUMERIC(36,9) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Log deposit / withdraw
  await pool.query(`
    CREATE TABLE IF NOT EXISTS zk_transfers (
      id SERIAL PRIMARY KEY,
      zk_proof_id TEXT NOT NULL REFERENCES zk_proofs(zk_proof_id),
      wallet_pubkey TEXT NOT NULL,
      direction TEXT NOT NULL CHECK (direction IN ('DEPOSIT','WITHDRAW')),
      amount NUMERIC(36,9) NOT NULL,
      recipient TEXT,
      tx_signature TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}
