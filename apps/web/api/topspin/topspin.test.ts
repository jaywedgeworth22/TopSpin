import { describe, it, expect } from "vitest";
import { encryptJson, decryptJson, fingerprint } from "./crypto";
import {
  computeEntryHash,
  canonicalEntry,
  infisicalSecretName,
  shouldMintProviderCredential,
} from "./engine";
import { renderUpdated } from "./files";
import { parseGlobalApiKeys, serializeGlobalApiKeys } from "./env-parse";
import { getConnector } from "./connectors";

describe("crypto", () => {
  it("encryptJson/decryptJson round-trips", () => {
    const payload = { adminKey: "sk-test-123", nested: { a: [1, 2] } };
    const enc = encryptJson(payload);
    expect(enc).not.toContain("sk-test-123");
    expect(decryptJson(enc)).toEqual(payload);
  });

  it("decryptJson returns null for garbage", () => {
    expect(decryptJson("not-a-payload")).toBeNull();
    expect(decryptJson(null)).toBeNull();
  });

  it("fingerprint is a 16-char sha256 prefix", () => {
    expect(fingerprint("hello")).toBe("2cf24dba5fb0a30e");
    expect(fingerprint("hello")).toHaveLength(16);
  });
});

describe("audit hash chain", () => {
  it("is deterministic and chain-dependent", () => {
    const entry = {
      ts: "2025-01-01T00:00:00.000Z",
      actor: "web-user",
      action: "rotation.committed",
      secretId: 7,
      detail: { runId: 3 },
    };
    const h1 = computeEntryHash("0000000000000000", entry);
    expect(h1).toHaveLength(16);
    expect(computeEntryHash("0000000000000000", entry)).toBe(h1);
    expect(computeEntryHash("1111111111111111", entry)).not.toBe(h1);
    expect(canonicalEntry(entry)).toBe(canonicalEntry({ ...entry }));
  });
});

describe("dry-run mint guard", () => {
  it("never mints or revokes a provider credential during dry-run", () => {
    expect(shouldMintProviderCredential(true)).toBe(false);
    expect(shouldMintProviderCredential(false)).toBe(true);
  });
});

describe("infisicalSecretName", () => {
  it("uses the secret record name when wizard secretName is empty", () => {
    expect(infisicalSecretName({}, "CLOUDFLARE_API_TOKEN")).toBe(
      "CLOUDFLARE_API_TOKEN",
    );
    expect(infisicalSecretName({ secretName: "" }, "CLOUDFLARE_API_TOKEN")).toBe(
      "CLOUDFLARE_API_TOKEN",
    );
    expect(
      infisicalSecretName({ secretName: "   " }, "CLOUDFLARE_API_TOKEN"),
    ).toBe("CLOUDFLARE_API_TOKEN");
  });

  it("does not fall back to a value fingerprint", () => {
    const fp = fingerprint("rotated-value");
    expect(infisicalSecretName({ secretName: "" }, "CLOUDFLARE_API_TOKEN")).not.toBe(
      fp,
    );
  });

  it("keeps an explicit Infisical secret name", () => {
    expect(
      infisicalSecretName({ secretName: "prod/cf-token" }, "CLOUDFLARE_API_TOKEN"),
    ).toBe("prod/cf-token");
  });
});

describe("file target renderers", () => {
  it("updates .env keys in place", () => {
    const out = renderUpdated(
      { path: "x/.env", format: "env", key: "API_KEY" },
      "FOO=1\nAPI_KEY=old\n",
      "new-value",
    );
    expect(out).toBe("FOO=1\nAPI_KEY=new-value\n");
  });

  it("appends missing .env keys", () => {
    const out = renderUpdated(
      { path: "x/.env", format: "env", key: "NEW_KEY" },
      "FOO=1\n",
      "v",
    );
    expect(out).toBe("FOO=1\nNEW_KEY=v\n");
  });

  it("updates JSON via dot path", () => {
    const out = renderUpdated(
      { path: "x/config.json", format: "json", key: "credentials.npmToken" },
      JSON.stringify({ credentials: { npmToken: "old" }, keep: 1 }),
      "npm_new",
    );
    expect(JSON.parse(out)).toEqual({
      credentials: { npmToken: "npm_new" },
      keep: 1,
    });
  });

  it("updates YAML flat keys", () => {
    const out = renderUpdated(
      { path: "x/p.yaml", format: "yaml", key: "aws_access_key_id" },
      "aws_access_key_id: AKIA_OLD\nother: 1\n",
      "AKIA_NEW",
    );
    expect(out).toContain("aws_access_key_id: AKIA_NEW");
    expect(out).toContain("other: 1");
  });

  it("updates INI section keys", () => {
    const out = renderUpdated(
      { path: "x/credentials", format: "ini", key: "prod.aws_access_key_id" },
      "[default]\naws_access_key_id = A\n\n[prod]\naws_access_key_id = B\n",
      "C",
    );
    expect(out).toContain("[default]\naws_access_key_id = A");
    expect(out).toContain("[prod]\naws_access_key_id = C");
  });
});

describe("global-api-keys parser (Grok merge)", () => {
  it("parses KEY=value, comments, and a trailing agent token", () => {
    const parsed = parseGlobalApiKeys(
      [
        "# TopSpin managed",
        "# username: mac-collab",
        "OPENAI_API_KEY=sk-test-1",
        'GITHUB_TOKEN="ghp_abc 123"',
        "TOPSPIN_AGENT_TOKEN=agent-secret-token",
        "bare-trailing-token-value",
      ].join("\n"),
    );
    expect(parsed.keys.map((k) => k.key)).toEqual(["OPENAI_API_KEY", "GITHUB_TOKEN"]);
    expect(parsed.keys[1].value).toBe("ghp_abc 123");
    expect(parsed.agentToken).toBe("bare-trailing-token-value");
    expect(parsed.macUsername).toBe("mac-collab");
  });

  it("round-trips keys without embedding the agent token as a secret", () => {
    const text = serializeGlobalApiKeys(
      [{ key: "XAI_API_KEY", value: "xai-demo" }],
      "agent-token",
    );
    const parsed = parseGlobalApiKeys(text);
    expect(parsed.keys).toEqual([{ key: "XAI_API_KEY", value: "xai-demo" }]);
    expect(parsed.agentToken).toBe("agent-token");
    expect(text).not.toMatch(/sk-live|BEGIN .* PRIVATE/);
  });
});

describe("merged live connectors", () => {
  it("registers Resend, Hugging Face, Neon, and live Vercel/Slack", () => {
    expect(getConnector("resend")?.capability).toBe("programmatic");
    expect(getConnector("huggingface")?.capability).toBe("programmatic");
    expect(getConnector("neon")?.capability).toBe("programmatic");
    expect(getConnector("vercel")?.capability).toBe("programmatic");
    expect(getConnector("slack")?.capability).toBe("partial");
  });

  it("registers the Grok/Kimi extra catalog", () => {
    expect(getConnector("coolify")?.capability).toBe("update_only");
    expect(getConnector("xai")?.capability).toBe("update_only");
    expect(getConnector("vault")?.capability).toBe("update_only");
    expect(getConnector("jwt")?.capability).toBe("programmatic");
    expect(getConnector("database")?.capability).toBe("programmatic");
    expect(getConnector("generic_secret")?.capability).toBe("programmatic");
  });
});
