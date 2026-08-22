import { eq, desc, and, ne, lte, isNotNull } from "drizzle-orm";
import { getDb } from "../queries/connection";
import {
  secrets,
  targets,
  rotationRuns,
  auditLog,
  type Secret,
  type Target,
  type RotationRun,
} from "@db/schema";
import {
  policySchema,
  DEFAULT_POLICY,
  type RotationStep,
  type RotationPolicy,
  type RunTrigger,
  type ChainVerification,
  type FileTargetConfig,
  type InfisicalTargetConfig,
  type WebhookTargetConfig,
} from "@contracts/topspin";
import { decryptJson, fingerprint, sha256Hex } from "./crypto";
import { getConnector } from "./connectors";
import { isDemoMode, demoMessage, demoLatency } from "./demo";
import { hasInfisicalConfig, upsertSecret, readSecret } from "./infisical";
import { writeFileTarget, readFileTarget } from "./files";

// ── Rotation pipeline (architecture.md §2) ──────────────────────
// LOCK -> ROTATE -> PUSH (per enabled target) -> VERIFY -> COMMIT -> AUDIT.
// Plaintext values exist only in this module's memory during a run.

export class RotationLockedError extends Error {
  constructor(secretId: number) {
    super(`Secret ${secretId} already has a rotation run in progress`);
    this.name = "RotationLockedError";
  }
}

export class SecretNotFoundError extends Error {
  constructor(secretId: number) {
    super(`Secret ${secretId} not found`);
    this.name = "SecretNotFoundError";
  }
}

const locks = new Set<number>();

export function isLocked(secretId: number): boolean {
  return locks.has(secretId);
}

function parsePolicy(secret: Secret): RotationPolicy {
  const parsed = policySchema.partial().safeParse(secret.policyJson ?? {});
  return { ...DEFAULT_POLICY, ...(parsed.success ? parsed.data : {}) };
}

/**
 * Infisical key used for both PUSH and VERIFY.
 * The Track Secret wizard defaults `secretName` to "" and treats it as
 * optional, so PUSH already falls back to the secret record name. VERIFY
 * must use the same fallback — using the value fingerprint as a name
 * always misses the just-written key.
 */
export function infisicalSecretName(
  cfg: Pick<InfisicalTargetConfig, "secretName">,
  fallbackName: string,
): string {
  const named = cfg.secretName?.trim();
  return named ? named : fallbackName;
}

/**
 * Probe name used by targets.test.  A canary must never land on the live
 * Infisical secret or file key — TopSpin does not keep the old plaintext,
 * so overwriting the production slot is unrecoverable.
 */
export function canaryDeliveryName(liveName: string): string {
  const base = liveName.trim() || "SECRET";
  return /_CANARY$/i.test(base) ? base : `${base}_CANARY`;
}

// ── Hash-chained audit log ──────────────────────────────────────
// entryHash = sha256(prevHash + canonical(entry))[0:16], genesis prevHash = "0"*16

const GENESIS_HASH = "0000000000000000";

type AuditCanonical = {
  ts: string;
  actor: string;
  action: string;
  secretId: number | null;
  detail: unknown;
};

/** Deep key-sorted stringify — immune to MySQL JSON key reordering. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`)
    .join(",")}}`;
}

export function canonicalEntry(entry: AuditCanonical): string {
  // Stable key order everywhere — must match verifyAuditChain.
  return `{"action":${JSON.stringify(entry.action)},"actor":${JSON.stringify(
    entry.actor,
  )},"detail":${stableStringify(entry.detail ?? null)},"secretId":${JSON.stringify(
    entry.secretId,
  )},"ts":${JSON.stringify(entry.ts)}}`;
}

export function computeEntryHash(prevHash: string, entry: AuditCanonical): string {
  return sha256Hex(prevHash + canonicalEntry(entry)).slice(0, 16);
}

export async function appendAudit(
  actor: string,
  action: string,
  secretId: number | null,
  detail: unknown,
  ts: Date = new Date(),
): Promise<void> {
  const db = getDb();
  const [last] = await db
    .select({ entryHash: auditLog.entryHash })
    .from(auditLog)
    .orderBy(desc(auditLog.id))
    .limit(1);
  const prevHash = last?.entryHash ?? GENESIS_HASH;
  const canonical: AuditCanonical = {
    ts: ts.toISOString(),
    actor,
    action,
    secretId,
    detail: detail ?? null,
  };
  await db.insert(auditLog).values({
    ts,
    actor,
    action,
    secretId,
    detailJson: (detail ?? null) as never,
    prevHash,
    entryHash: computeEntryHash(prevHash, canonical),
  });
}

export async function verifyAuditChain(): Promise<ChainVerification> {
  const db = getDb();
  const entries = await db.select().from(auditLog).orderBy(auditLog.id);
  let prevHash = GENESIS_HASH;
  for (const entry of entries) {
    const canonical: AuditCanonical = {
      ts: entry.ts.toISOString(),
      actor: entry.actor,
      action: entry.action,
      secretId: entry.secretId ?? null,
      detail: entry.detailJson ?? null,
    };
    const expected = computeEntryHash(prevHash, canonical);
    if (entry.prevHash !== prevHash || entry.entryHash !== expected) {
      return { valid: false, checked: entries.length, brokenAtId: entry.id };
    }
    prevHash = entry.entryHash;
  }
  return { valid: true, checked: entries.length, brokenAtId: null };
}

// ── Target delivery ─────────────────────────────────────────────

async function pushToTarget(
  target: Target,
  secret: Secret,
  value: string,
): Promise<string> {
  const cfg = (target.configJson ?? {}) as Record<string, unknown>;
  switch (target.kind) {
    case "infisical": {
      const icfg = cfg as InfisicalTargetConfig;
      const secretName = infisicalSecretName(icfg, secret.name);
      if (!isDemoMode() && hasInfisicalConfig(icfg)) {
        await upsertSecret(icfg, secretName, value);
        return `upserted ${secretName} to Infisical (${icfg.environment || "prod"}:${icfg.secretPath || "/"})`;
      }
      const ms = await demoLatency();
      return demoMessage(
        `upserted ${secretName} to Infisical ${icfg.environment || "prod"}:${icfg.secretPath || "/"} (simulated, ${ms}ms)`,
      );
    }
    case "file": {
      // File targets always execute for real (inside the sandbox).
      const fcfg = cfg as unknown as FileTargetConfig;
      await writeFileTarget(fcfg, value);
      return `wrote ${fcfg.key} to ${fcfg.path} (${fcfg.format})`;
    }
    case "webhook": {
      const wcfg = cfg as unknown as WebhookTargetConfig;
      if (!isDemoMode() && wcfg.url) {
        const res = await fetch(wcfg.url, {
          method: wcfg.method || "POST",
          headers: {
            "Content-Type": "application/json",
            ...(wcfg.headers ?? {}),
          },
          body: JSON.stringify({
            name: secret.name,
            valueRef: `topspin://secrets/${secret.id}/v${secret.version + 1}`,
            ...(wcfg.includeValue ? { value } : {}),
          }),
        });
        if (!res.ok) {
          throw new Error(`webhook ${wcfg.url} returned HTTP ${res.status}`);
        }
        return `POSTed rotation notice to ${wcfg.url}`;
      }
      const ms = await demoLatency();
      return demoMessage(
        `POSTed rotation notice to ${wcfg.url ?? "(unconfigured)"} (simulated, ${ms}ms)`,
      );
    }
    case "keychain": {
      const kcfg = cfg as { service?: string; account?: string };
      // On web, Keychain writes are handled by the native companion app.
      return `delegated to companion app (keychain item ${kcfg.service ?? "?"}/${kcfg.account ?? secret.name})`;
    }
  }
}

async function verifyTarget(
  target: Target,
  expectedValue: string,
  secret: Secret,
): Promise<string> {
  const cfg = (target.configJson ?? {}) as Record<string, unknown>;
  const expectedFp = fingerprint(expectedValue);
  switch (target.kind) {
    case "infisical": {
      const icfg = cfg as InfisicalTargetConfig;
      if (!isDemoMode() && hasInfisicalConfig(icfg)) {
        const read = await readSecret(icfg, infisicalSecretName(icfg, secret.name));
        if (read === null || fingerprint(read) !== expectedFp) {
          throw new Error("Infisical read-back fingerprint mismatch");
        }
        return "read-back verified against Infisical";
      }
      await demoLatency();
      return demoMessage("read-back verified against Infisical (simulated)");
    }
    case "file": {
      const fcfg = cfg as unknown as FileTargetConfig;
      const read = await readFileTarget(fcfg);
      if (read === null || fingerprint(read) !== expectedFp) {
        throw new Error(`file read-back mismatch at ${fcfg.path}`);
      }
      return `read-back verified ${fcfg.path}`;
    }
    case "webhook":
      return "no read-back available for webhook targets";
    case "keychain":
      return "read-back delegated to companion app";
  }
}

// ── Main entry ──────────────────────────────────────────────────

export async function rotateSecret(
  secretId: number,
  trigger: RunTrigger,
  actor = "system",
): Promise<RotationRun> {
  const db = getDb();
  const secret = await db.query.secrets.findFirst({
    where: eq(secrets.id, secretId),
  });
  if (!secret) throw new SecretNotFoundError(secretId);
  if (locks.has(secretId)) throw new RotationLockedError(secretId);
  locks.add(secretId);

  const steps: RotationStep[] = [];
  const record = async (
    step: RotationStep["step"],
    fn: () => Promise<string>,
    extra?: Pick<RotationStep, "targetKind" | "targetId">,
  ): Promise<boolean> => {
    const startedAt = new Date();
    try {
      const message = await fn();
      steps.push({
        step,
        status: "ok",
        startedAt: startedAt.toISOString(),
        durationMs: Date.now() - startedAt.getTime(),
        message,
        ...extra,
      });
      return true;
    } catch (err) {
      steps.push({
        step,
        status: "failed",
        startedAt: startedAt.toISOString(),
        durationMs: Date.now() - startedAt.getTime(),
        message: (err as Error).message,
        ...extra,
      });
      return false;
    }
  };

  const [runRow] = await db
    .insert(rotationRuns)
    .values({
      secretId,
      trigger,
      status: "running",
      startedAt: new Date(),
      stepsJson: [] as never,
    })
    .$returningId();
  const runId = runRow.id;

  await db
    .update(secrets)
    .set({ status: "rotating" })
    .where(eq(secrets.id, secretId));

  let runStatus: "committed" | "partial" | "failed" = "failed";
  let runError: string | null = null;
  let newFp: string | null = null;

  try {
    // 1. LOCK
    await record("lock", async () => "acquired in-process rotation lock");

    // 2. ROTATE
    const connectorRow = await db.query.connectors.findFirst({
      where: (c, { eq: eqOp }) => eqOp(c.id, secret.connectorId),
    });
    const connector = connectorRow
      ? getConnector(connectorRow.platform)
      : undefined;
    let newValue: string | null = null;
    const rotateOk = await record("rotate", async () => {
      if (!connectorRow || !connector) {
        throw new Error(
          `no connector registered for platform "${connectorRow?.platform ?? "?"}"`,
        );
      }
      const config = decryptJson(connectorRow.configEnc);
      const result = await connector.rotate(config);
      if (!result.value) throw new Error("connector returned no value");
      newValue = result.value;
      return result.demo ? demoMessage(result.message) : result.message;
    });

    if (rotateOk && newValue) {
      const value: string = newValue;
      newFp = fingerprint(value);

      // 3. PUSH — every enabled target
      const targetRows = await db
        .select()
        .from(targets)
        .where(eq(targets.secretId, secretId));
      const enabledTargets = targetRows.filter((t) => t.enabled);

      if (enabledTargets.length === 0) {
        await record("push", async () => "no enabled targets — nothing to deliver");
      }

      const pushedTargets: Target[] = [];
      let pushFailures = 0;
      for (const target of enabledTargets) {
        const ok = await record(
          "push",
          () => pushToTarget(target, secret, value),
          { targetKind: target.kind, targetId: target.id },
        );
        await db
          .update(targets)
          .set({
            lastStatus: ok ? "ok" : "failed",
            lastDeliveredAt: ok ? new Date() : target.lastDeliveredAt,
          })
          .where(eq(targets.id, target.id));
        if (ok) pushedTargets.push(target);
        else pushFailures++;
      }

      // 4. VERIFY — optional read-back per successfully pushed target
      const policy = parsePolicy(secret);
      let verifyFailures = 0;
      if (policy.verifyAfterWrite && pushedTargets.length > 0) {
        for (const target of pushedTargets) {
          const ok = await record("verify", () => verifyTarget(target, value, secret), {
            targetKind: target.kind,
            targetId: target.id,
          });
          if (!ok) {
            verifyFailures++;
            await db
              .update(targets)
              .set({ lastStatus: "failed" })
              .where(eq(targets.id, target.id));
          }
        }
      } else {
        await record(
          "verify",
          async () => "skipped (verifyAfterWrite disabled or no pushed targets)",
        );
      }

      // 5. COMMIT
      const totalFailures = pushFailures + verifyFailures;
      const committed =
        totalFailures === 0 &&
        (enabledTargets.length === 0 || pushedTargets.length > 0);
      runStatus = committed
        ? "committed"
        : pushedTargets.length > 0
          ? "partial"
          : "failed";
      await record("commit", async () => {
        if (!committed && pushedTargets.length === 0) {
          throw new Error("all target deliveries failed — old value retained");
        }
        if (committed) {
          const now = new Date();
          const nextDue = new Date(
            now.getTime() + policy.intervalHours * 3600 * 1000,
          );
          await db
            .update(secrets)
            .set({
              status: "healthy",
              version: secret.version + 1,
              lastRotatedAt: now,
              nextDueAt: nextDue,
              fingerprint: newFp,
            })
            .where(eq(secrets.id, secretId));
          return `committed version ${secret.version + 1}; next rotation due ${nextDue.toISOString()}`;
        }
        await db
          .update(secrets)
          .set({ status: "healthy", fingerprint: newFp })
          .where(eq(secrets.id, secretId));
        return `partial commit: ${pushedTargets.length}/${enabledTargets.length} targets updated — flagged for retry`;
      });
      if (!committed && runStatus !== "partial") {
        runError = steps.find((s) => s.status === "failed")?.message ?? null;
        await db
          .update(secrets)
          .set({ status: "failed" })
          .where(eq(secrets.id, secretId));
      }
    } else {
      runStatus = "failed";
      runError = steps.find((s) => s.status === "failed")?.message ?? "rotate step failed";
      await record("push", async () => {
        throw new Error("skipped — rotation produced no value");
      });
      await record("commit", async () => {
        throw new Error("skipped — nothing to commit");
      });
      await db
        .update(secrets)
        .set({ status: "failed" })
        .where(eq(secrets.id, secretId));
    }

    // 6. AUDIT — hash-chained, fingerprints only, never values
    await record("audit", async () => {
      await appendAudit(
        actor,
        runStatus === "committed"
          ? "rotation.committed"
          : runStatus === "partial"
            ? "rotation.partial"
            : "rotation.failed",
        secretId,
        {
          runId,
          trigger,
          status: runStatus,
          version: runStatus === "committed" ? secret.version + 1 : secret.version,
          fingerprint: newFp,
          failedSteps: steps
            .filter((s) => s.status === "failed")
            .map((s) => s.step),
        },
      );
      return "audit entry appended (hash-chained)";
    });
  } finally {
    locks.delete(secretId);
    // Ensure the secret never stays stuck in "rotating" if something crashed.
    await db
      .update(secrets)
      .set({ status: "failed" })
      .where(and(eq(secrets.id, secretId), eq(secrets.status, "rotating")));
    await db
      .update(rotationRuns)
      .set({
        status: runStatus,
        finishedAt: new Date(),
        stepsJson: steps as never,
        newFingerprint: newFp,
        error: runError,
      })
      .where(eq(rotationRuns.id, runId));
  }

  const run = await db.query.rotationRuns.findFirst({
    where: eq(rotationRuns.id, runId),
  });
  return run!;
}

// ── Due-status maintenance ──────────────────────────────────────

const DUE_SOON_WINDOW_MS = 24 * 3600 * 1000;

/** Recompute due_soon/overdue/healthy from nextDueAt for non-exempt secrets. */
export async function refreshDueStatuses(now = new Date()): Promise<void> {
  const db = getDb();
  const rows = await db
    .select({
      id: secrets.id,
      status: secrets.status,
      nextDueAt: secrets.nextDueAt,
    })
    .from(secrets)
    .where(
      and(
        ne(secrets.status, "rotating"),
        ne(secrets.status, "paused"),
        ne(secrets.status, "failed"),
      ),
    );
  for (const row of rows) {
    let next: "healthy" | "due_soon" | "overdue" = "healthy";
    if (row.nextDueAt) {
      const diff = row.nextDueAt.getTime() - now.getTime();
      if (diff < 0) next = "overdue";
      else if (diff < DUE_SOON_WINDOW_MS) next = "due_soon";
    }
    if (next !== row.status) {
      await db
        .update(secrets)
        .set({ status: next })
        .where(eq(secrets.id, row.id));
    }
  }
}

/** Secrets due for scheduled rotation right now. */
export async function findDueSecrets(now = new Date()): Promise<Secret[]> {
  const db = getDb();
  const rows = await db
    .select()
    .from(secrets)
    .where(and(isNotNull(secrets.nextDueAt), lte(secrets.nextDueAt, now)));
  return rows.filter((row) => {
    if (row.status === "rotating" || row.status === "paused") return false;
    const policy = parsePolicy(row);
    return policy.autoRotate;
  });
}
