import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { eq, desc, and, like, gte, sql, type SQL } from "drizzle-orm";
import { createRouter, publicQuery } from "../middleware";
import { getDb } from "../queries/connection";
import {
  connectors,
  secrets,
  targets,
  rotationRuns,
  auditLog,
} from "@db/schema";
import {
  connectorCreateInput,
  connectorUpdateInput,
  secretCreateInput,
  secretUpdateInput,
  secretListFilter,
  targetUpsertInput,
  policySchema,
  DEFAULT_POLICY,
  infisicalTargetConfigSchema,
  fileTargetConfigSchema,
  webhookTargetConfigSchema,
  keychainTargetConfigSchema,
  type StatsOverview,
  type RotationPolicy,
  type FileTargetConfig,
  type InfisicalTargetConfig,
  type WebhookTargetConfig,
  type KeychainTargetConfig,
} from "@contracts/topspin";
import { encryptJson, decryptJson, fingerprint, randomToken } from "../topspin/crypto";
import { isDemoMode, demoLatency, demoMessage } from "../topspin/demo";
import { connectorRegistry, getConnector, testConnection } from "../topspin/connectors";
import { hasInfisicalConfig, upsertSecret } from "../topspin/infisical";
import { writeFileTarget } from "../topspin/files";
import {
  rotateSecret,
  appendAudit,
  verifyAuditChain,
  infisicalSecretName,
  canaryDeliveryName,
  RotationLockedError,
  SecretNotFoundError,
} from "../topspin/engine";

const ACTOR = "web-user";

function toTrpcError(err: unknown): never {
  if (err instanceof TRPCError) throw err;
  if (err instanceof RotationLockedError) {
    throw new TRPCError({ code: "CONFLICT", message: err.message });
  }
  if (err instanceof SecretNotFoundError) {
    throw new TRPCError({ code: "NOT_FOUND", message: err.message });
  }
  throw new TRPCError({
    code: "INTERNAL_SERVER_ERROR",
    message: (err as Error).message,
  });
}

// ── connectors ──────────────────────────────────────────────────

export const connectorsRouter = createRouter({
  list: publicQuery.query(async () => {
    const db = getDb();
    const rows = await db.select().from(connectors).orderBy(connectors.id);
    const counts = await db
      .select({ connectorId: secrets.connectorId, count: sql<number>`count(*)` })
      .from(secrets)
      .groupBy(secrets.connectorId);
    const countMap = new Map(counts.map((c) => [c.connectorId, Number(c.count)]));
    return rows.map((row) => ({
      ...row,
      hasConfig: !!row.configEnc,
      configEnc: undefined as never, // never leak encrypted config to clients
      secretCount: countMap.get(row.id) ?? 0,
      registry: getConnector(row.platform)
        ? {
            known: true,
            capability: getConnector(row.platform)!.capability,
          }
        : { known: false },
    }));
  }),

  registry: publicQuery.query(() =>
    connectorRegistry.map((c) => ({
      platform: c.platform,
      displayName: c.displayName,
      capability: c.capability,
    })),
  ),

  create: publicQuery
    .input(connectorCreateInput)
    .mutation(async ({ input }) => {
      const db = getDb();
      const existing = await db.query.connectors.findFirst({
        where: eq(connectors.platform, input.platform),
      });
      if (existing) {
        throw new TRPCError({
          code: "CONFLICT",
          message: `connector for platform "${input.platform}" already exists`,
        });
      }
      const known = getConnector(input.platform);
      const capability = input.capability ?? known?.capability ?? "programmatic";
      const configEnc = input.config ? encryptJson(input.config) : null;
      const [{ id }] = await db
        .insert(connectors)
        .values({
          platform: input.platform,
          displayName: input.displayName,
          capability,
          configEnc,
          status: configEnc ? "connected" : "disconnected",
          lastCheckedAt: configEnc ? new Date() : null,
        })
        .$returningId();
      await appendAudit(ACTOR, "connector.created", null, {
        connectorId: id,
        platform: input.platform,
        hasConfig: !!configEnc,
      });
      return db.query.connectors.findFirst({ where: eq(connectors.id, id) });
    }),

  update: publicQuery
    .input(connectorUpdateInput)
    .mutation(async ({ input }) => {
      const db = getDb();
      const row = await db.query.connectors.findFirst({
        where: eq(connectors.id, input.id),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "connector not found" });
      const patch: Partial<typeof connectors.$inferInsert> = {};
      if (input.displayName !== undefined) patch.displayName = input.displayName;
      if (input.capability !== undefined) patch.capability = input.capability;
      if (input.status !== undefined) patch.status = input.status;
      if (input.config !== undefined) {
        patch.configEnc = encryptJson(input.config);
        patch.status = "connected";
        patch.lastCheckedAt = new Date();
      }
      await db.update(connectors).set(patch).where(eq(connectors.id, input.id));
      await appendAudit(ACTOR, "connector.updated", null, {
        connectorId: input.id,
        fields: Object.keys(patch),
      });
      return db.query.connectors.findFirst({ where: eq(connectors.id, input.id) });
    }),

  delete: publicQuery
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDb();
      const row = await db.query.connectors.findFirst({
        where: eq(connectors.id, input.id),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "connector not found" });
      const [{ count }] = await db
        .select({ count: sql<number>`count(*)` })
        .from(secrets)
        .where(eq(secrets.connectorId, input.id));
      if (Number(count) > 0) {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: `connector still manages ${count} secret(s) — delete them first`,
        });
      }
      await db.delete(connectors).where(eq(connectors.id, input.id));
      await appendAudit(ACTOR, "connector.deleted", null, {
        connectorId: input.id,
        platform: row.platform,
      });
      return { ok: true };
    }),

  test: publicQuery
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDb();
      const row = await db.query.connectors.findFirst({
        where: eq(connectors.id, input.id),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "connector not found" });
      try {
        const config = decryptJson(row.configEnc);
        const message = await testConnection(row.platform, config);
        await db
          .update(connectors)
          .set({ status: "connected", lastCheckedAt: new Date() })
          .where(eq(connectors.id, row.id));
        await appendAudit(ACTOR, "connector.tested", null, {
          connectorId: row.id,
          platform: row.platform,
          ok: true,
        });
        return { ok: true, message };
      } catch (err) {
        await db
          .update(connectors)
          .set({ status: "error", lastCheckedAt: new Date() })
          .where(eq(connectors.id, row.id));
        await appendAudit(ACTOR, "connector.tested", null, {
          connectorId: row.id,
          platform: row.platform,
          ok: false,
          error: (err as Error).message,
        });
        return { ok: false, message: (err as Error).message };
      }
    }),
});

// ── secrets ─────────────────────────────────────────────────────

export const secretsRouter = createRouter({
  list: publicQuery.input(secretListFilter).query(async ({ input }) => {
    const db = getDb();
    const conditions: SQL[] = [];
    if (input?.status) conditions.push(eq(secrets.status, input.status));
    if (input?.connectorId) conditions.push(eq(secrets.connectorId, input.connectorId));
    if (input?.environment) conditions.push(eq(secrets.environment, input.environment));
    if (input?.search) conditions.push(like(secrets.name, `%${input.search}%`));
    return db.query.secrets.findMany({
      where: conditions.length ? and(...conditions) : undefined,
      with: { connector: true, targets: true },
      orderBy: desc(secrets.id),
    });
  }),

  get: publicQuery
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = getDb();
      const row = await db.query.secrets.findFirst({
        where: eq(secrets.id, input.id),
        with: { connector: true, targets: true },
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "secret not found" });
      return row;
    }),

  create: publicQuery
    .input(secretCreateInput)
    .mutation(async ({ input }) => {
      const db = getDb();
      const connector = await db.query.connectors.findFirst({
        where: eq(connectors.id, input.connectorId),
      });
      if (!connector) {
        throw new TRPCError({ code: "NOT_FOUND", message: "connector not found" });
      }
      const policy: RotationPolicy = { ...DEFAULT_POLICY, ...(input.policy ?? {}) };
      const now = new Date();
      const [{ id }] = await db
        .insert(secrets)
        .values({
          name: input.name,
          connectorId: input.connectorId,
          environment: input.environment,
          notes: input.notes ?? null,
          status: "healthy",
          policyJson: policy as never,
          nextDueAt: new Date(now.getTime() + policy.intervalHours * 3600 * 1000),
        })
        .$returningId();
      await appendAudit(ACTOR, "secret.created", id, {
        name: input.name,
        connectorId: input.connectorId,
        environment: input.environment,
      });
      return db.query.secrets.findFirst({
        where: eq(secrets.id, id),
        with: { connector: true, targets: true },
      });
    }),

  update: publicQuery
    .input(secretUpdateInput)
    .mutation(async ({ input }) => {
      const db = getDb();
      const row = await db.query.secrets.findFirst({
        where: eq(secrets.id, input.id),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "secret not found" });
      const patch: Partial<typeof secrets.$inferInsert> = {};
      if (input.name !== undefined) patch.name = input.name;
      if (input.environment !== undefined) patch.environment = input.environment;
      if (input.notes !== undefined) patch.notes = input.notes;
      if (input.status !== undefined) patch.status = input.status;
      if (input.policy !== undefined) {
        const current = policySchema.partial().safeParse(row.policyJson ?? {});
        const merged: RotationPolicy = {
          ...DEFAULT_POLICY,
          ...(current.success ? current.data : {}),
          ...input.policy,
        };
        patch.policyJson = merged as never;
      }
      await db.update(secrets).set(patch).where(eq(secrets.id, input.id));
      await appendAudit(ACTOR, "secret.updated", input.id, {
        fields: Object.keys(patch),
      });
      return db.query.secrets.findFirst({
        where: eq(secrets.id, input.id),
        with: { connector: true, targets: true },
      });
    }),

  delete: publicQuery
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDb();
      const row = await db.query.secrets.findFirst({
        where: eq(secrets.id, input.id),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "secret not found" });
      await db.delete(targets).where(eq(targets.secretId, input.id));
      await db.delete(rotationRuns).where(eq(rotationRuns.secretId, input.id));
      await db.delete(secrets).where(eq(secrets.id, input.id));
      await appendAudit(ACTOR, "secret.deleted", input.id, { name: row.name });
      return { ok: true };
    }),

  rotateNow: publicQuery
    .input(z.object({ secretId: z.number() }))
    .mutation(async ({ input }) => {
      try {
        return await rotateSecret(input.secretId, "manual", ACTOR);
      } catch (err) {
        toTrpcError(err);
      }
    }),
});

// ── targets ─────────────────────────────────────────────────────

function validateTargetConfig(
  kind: "infisical" | "file" | "webhook" | "keychain",
  config: Record<string, unknown>,
): Record<string, unknown> {
  const schema = {
    infisical: infisicalTargetConfigSchema,
    file: fileTargetConfigSchema,
    webhook: webhookTargetConfigSchema,
    keychain: keychainTargetConfigSchema,
  }[kind];
  const parsed = schema.safeParse(config);
  if (!parsed.success) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `invalid ${kind} target config: ${parsed.error.issues
        .map((i) => `${i.path.join(".")}: ${i.message}`)
        .join("; ")}`,
    });
  }
  return parsed.data as Record<string, unknown>;
}

export const targetsRouter = createRouter({
  upsert: publicQuery
    .input(targetUpsertInput)
    .mutation(async ({ input }) => {
      const db = getDb();
      const secret = await db.query.secrets.findFirst({
        where: eq(secrets.id, input.secretId),
      });
      if (!secret) throw new TRPCError({ code: "NOT_FOUND", message: "secret not found" });
      const config = validateTargetConfig(input.kind, input.config);
      let id = input.id;
      if (id) {
        const existing = await db.query.targets.findFirst({
          where: eq(targets.id, id),
        });
        if (!existing) {
          throw new TRPCError({ code: "NOT_FOUND", message: "target not found" });
        }
        await db
          .update(targets)
          .set({ kind: input.kind, configJson: config as never, enabled: input.enabled })
          .where(eq(targets.id, id));
      } else {
        const [row] = await db
          .insert(targets)
          .values({
            secretId: input.secretId,
            kind: input.kind,
            configJson: config as never,
            enabled: input.enabled,
          })
          .$returningId();
        id = row.id;
      }
      await appendAudit(ACTOR, input.id ? "target.updated" : "target.created", input.secretId, {
        targetId: id,
        kind: input.kind,
      });
      return db.query.targets.findFirst({ where: eq(targets.id, id!) });
    }),

  remove: publicQuery
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDb();
      const row = await db.query.targets.findFirst({
        where: eq(targets.id, input.id),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "target not found" });
      await db.delete(targets).where(eq(targets.id, input.id));
      await appendAudit(ACTOR, "target.removed", row.secretId, {
        targetId: input.id,
        kind: row.kind,
      });
      return { ok: true };
    }),

  test: publicQuery
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDb();
      const target = await db.query.targets.findFirst({
        where: eq(targets.id, input.id),
      });
      if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "target not found" });
      const secret = await db.query.secrets.findFirst({
        where: eq(secrets.id, target.secretId),
      });
      const canary = `topspin-canary-${randomToken(12)}`;
      const cfg = (target.configJson ?? {}) as Record<string, unknown>;
      let ok = true;
      let message: string;
      try {
        switch (target.kind) {
          case "infisical": {
            const icfg = cfg as InfisicalTargetConfig;
            const canaryName = canaryDeliveryName(
              infisicalSecretName(icfg, secret?.name ?? "SECRET"),
            );
            if (!isDemoMode() && hasInfisicalConfig(icfg)) {
              await upsertSecret(icfg, canaryName, canary);
              message = `canary written to Infisical as ${canaryName}`;
            } else {
              const ms = await demoLatency();
              message = demoMessage(
                `canary written to Infisical as ${canaryName} (simulated, ${ms}ms)`,
              );
            }
            break;
          }
          case "file": {
            const fcfg = cfg as unknown as FileTargetConfig;
            const canaryCfg: FileTargetConfig = {
              ...fcfg,
              key: canaryDeliveryName(fcfg.key),
            };
            await writeFileTarget(canaryCfg, canary);
            message = `canary written to ${canaryCfg.path} key ${canaryCfg.key}`;
            break;
          }
          case "webhook": {
            const wcfg = cfg as unknown as WebhookTargetConfig;
            if (!isDemoMode() && wcfg.url) {
              const res = await fetch(wcfg.url, {
                method: wcfg.method || "POST",
                headers: { "Content-Type": "application/json", ...(wcfg.headers ?? {}) },
                body: JSON.stringify({
                  name: secret?.name,
                  valueRef: `topspin://targets/${target.id}/canary`,
                  canary: fingerprint(canary),
                }),
              });
              if (!res.ok) throw new Error(`webhook returned HTTP ${res.status}`);
              message = `canary delivered to ${wcfg.url}`;
            } else {
              const ms = await demoLatency();
              message = demoMessage(`canary delivered to webhook (simulated, ${ms}ms)`);
            }
            break;
          }
          case "keychain": {
            const kcfg = cfg as unknown as KeychainTargetConfig;
            message = `canary delegated to companion app (${kcfg.service}/${kcfg.account})`;
            break;
          }
        }
      } catch (err) {
        ok = false;
        message = (err as Error).message;
      }
      await db
        .update(targets)
        .set({
          lastStatus: ok ? "ok" : "failed",
          lastDeliveredAt: ok ? new Date() : target.lastDeliveredAt,
        })
        .where(eq(targets.id, target.id));
      await appendAudit(ACTOR, "target.tested", target.secretId, {
        targetId: target.id,
        kind: target.kind,
        ok,
        canaryFingerprint: fingerprint(canary),
      });
      return { ok, message };
    }),
});

// ── policies ────────────────────────────────────────────────────

export const policiesRouter = createRouter({
  set: publicQuery
    .input(
      z.object({
        secretId: z.number(),
        intervalHours: z.number().min(1).max(24 * 365),
        autoRotate: z.boolean(),
        verifyAfterWrite: z.boolean(),
      }),
    )
    .mutation(async ({ input }) => {
      const db = getDb();
      const row = await db.query.secrets.findFirst({
        where: eq(secrets.id, input.secretId),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "secret not found" });
      const policy: RotationPolicy = {
        intervalHours: input.intervalHours,
        autoRotate: input.autoRotate,
        verifyAfterWrite: input.verifyAfterWrite,
      };
      const base = row.lastRotatedAt ?? new Date();
      const nextDueAt = new Date(base.getTime() + policy.intervalHours * 3600 * 1000);
      await db
        .update(secrets)
        .set({ policyJson: policy as never, nextDueAt })
        .where(eq(secrets.id, input.secretId));
      await appendAudit(ACTOR, "policy.updated", input.secretId, {
        ...policy,
        nextDueAt: nextDueAt.toISOString(),
      });
      return db.query.secrets.findFirst({
        where: eq(secrets.id, input.secretId),
        with: { connector: true, targets: true },
      });
    }),
});

// ── runs ────────────────────────────────────────────────────────

export const runsRouter = createRouter({
  list: publicQuery
    .input(
      z
        .object({
          secretId: z.number().optional(),
          limit: z.number().min(1).max(200).default(50),
        })
        .optional(),
    )
    .query(async ({ input }) => {
      const db = getDb();
      return db
        .select()
        .from(rotationRuns)
        .where(input?.secretId ? eq(rotationRuns.secretId, input.secretId) : undefined)
        .orderBy(desc(rotationRuns.id))
        .limit(input?.limit ?? 50);
    }),

  get: publicQuery
    .input(z.object({ id: z.number() }))
    .query(async ({ input }) => {
      const db = getDb();
      const row = await db.query.rotationRuns.findFirst({
        where: eq(rotationRuns.id, input.id),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "run not found" });
      return row;
    }),

  retry: publicQuery
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = getDb();
      const row = await db.query.rotationRuns.findFirst({
        where: eq(rotationRuns.id, input.id),
      });
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "run not found" });
      if (row.status !== "failed" && row.status !== "partial") {
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: `only failed/partial runs can be retried (status: ${row.status})`,
        });
      }
      try {
        // Re-runs the pipeline for the secret; the fresh run records which
        // step previously failed (retry trigger) and resumes delivery.
        return await rotateSecret(row.secretId, "retry", ACTOR);
      } catch (err) {
        toTrpcError(err);
      }
    }),
});

// ── audit ───────────────────────────────────────────────────────

export const auditRouter = createRouter({
  list: publicQuery
    .input(
      z
        .object({
          limit: z.number().min(1).max(500).default(100),
          action: z.string().optional(),
        })
        .optional(),
    )
    .query(async ({ input }) => {
      const db = getDb();
      return db
        .select()
        .from(auditLog)
        .where(input?.action ? eq(auditLog.action, input.action) : undefined)
        .orderBy(desc(auditLog.id))
        .limit(input?.limit ?? 100);
    }),

  verifyChain: publicQuery.query(() => verifyAuditChain()),
});

// ── stats ───────────────────────────────────────────────────────

export const statsRouter = createRouter({
  overview: publicQuery.query(async (): Promise<StatsOverview> => {
    const db = getDb();
    const allSecrets = await db.select().from(secrets);
    const allConnectors = await db.select().from(connectors).orderBy(connectors.id);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 3600 * 1000);
    const recentRuns = await db
      .select({ status: rotationRuns.status })
      .from(rotationRuns)
      .where(gte(rotationRuns.startedAt, thirtyDaysAgo));
    const recentActivity = await db
      .select()
      .from(auditLog)
      .orderBy(desc(auditLog.id))
      .limit(10);

    const total = allSecrets.length;
    const countBy = (s: string) => allSecrets.filter((r) => r.status === s).length;
    const healthy = countBy("healthy");
    const secretCountByConnector = new Map<number, number>();
    for (const s of allSecrets) {
      secretCountByConnector.set(
        s.connectorId,
        (secretCountByConnector.get(s.connectorId) ?? 0) + 1,
      );
    }

    return {
      demoMode: isDemoMode(),
      totalSecrets: total,
      healthPct: total === 0 ? 100 : Math.round((healthy / total) * 100),
      dueSoonCount: countBy("due_soon"),
      overdueCount: countBy("overdue"),
      pausedCount: countBy("paused"),
      failedCount: countBy("failed"),
      rotationsLast30d: recentRuns.length,
      failedRunsLast30d: recentRuns.filter((r) => r.status === "failed").length,
      coverageByConnector: allConnectors.map((c) => ({
        connectorId: c.id,
        platform: c.platform,
        displayName: c.displayName,
        capability: c.capability,
        status: c.status,
        secretCount: secretCountByConnector.get(c.id) ?? 0,
      })),
      recentActivity,
    };
  }),
});

export const topspinRouters = {
  connectors: connectorsRouter,
  secrets: secretsRouter,
  targets: targetsRouter,
  policies: policiesRouter,
  runs: runsRouter,
  audit: auditRouter,
  stats: statsRouter,
};
