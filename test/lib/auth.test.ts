// test/lib/auth.test.ts
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import { readFile } from "fs/promises";
import { execFile } from "child_process";
import * as os from "os";
import {
  resolveToken,
  exchangeSessionToken,
  getAuthenticatedHeaders,
  createDefaultAuthProvider,
  clearSessionCache,
} from "../../src/lib/auth.js";
import { AuthError } from "../../src/lib/types.js";

// Mock fs/promises and child_process
vi.mock("fs/promises", () => ({ readFile: vi.fn() }));
vi.mock("child_process", () => ({ execFile: vi.fn() }));

const mockReadFile = vi.mocked(readFile);
const mockExecFile = vi.mocked(execFile);

// Store original env
let originalEnv: typeof process.env;

beforeEach(() => {
  vi.resetAllMocks();
  originalEnv = process.env;
  process.env = { ...originalEnv };
  delete process.env.GITHUB_TOKEN;

  // Clear module-level cache
  clearSessionCache();
  vi.unstubAllGlobals();
});

afterEach(() => {
  process.env = originalEnv;
});

describe("resolveToken", () => {
  it("returns $GITHUB_TOKEN when set and skips other sources", async () => {
    process.env.GITHUB_TOKEN = "ghp_test1234567890abcdefghij";
    const token = await resolveToken();
    expect(token).toBe("ghp_test1234567890abcdefghij");
    expect(mockReadFile).not.toHaveBeenCalled();
    expect(mockExecFile).not.toHaveBeenCalled();
  });

  it("falls through to Copilot config when env var missing", async () => {
    delete process.env.GITHUB_TOKEN;
    const homeDir = os.homedir();

    mockReadFile.mockRejectedValueOnce(new Error("ENOENT")); // hosts.json not found
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({
        "github.com": { oauth_token: "gho_config1234567890" },
      })
    );

    const token = await resolveToken();
    expect(token).toBe("gho_config1234567890");
    expect(mockReadFile).toHaveBeenCalledWith(
      `${homeDir}/.config/github-copilot/hosts.json`,
      "utf-8"
    );
  });

  it("parses hosts.json for github.com oauth_token and skips gh CLI", async () => {
    delete process.env.GITHUB_TOKEN;
    const homeDir = os.homedir();

    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({
        "github.com": { oauth_token: "gho_hosts1234567890" },
      })
    );

    const token = await resolveToken();
    expect(token).toBe("gho_hosts1234567890");
    expect(mockReadFile).toHaveBeenCalledWith(
      `${homeDir}/.config/github-copilot/hosts.json`,
      "utf-8"
    );
    expect(mockExecFile).not.toHaveBeenCalled();
  });

  it("parses apps.json for github.com oauth_token", async () => {
    delete process.env.GITHUB_TOKEN;
    const homeDir = os.homedir();

    mockReadFile.mockRejectedValueOnce(new Error("ENOENT")); // hosts.json not found
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({
        "github.com": { oauth_token: "gho_apps1234567890" },
      })
    );

    const token = await resolveToken();
    expect(token).toBe("gho_apps1234567890");
    expect(mockReadFile).toHaveBeenNthCalledWith(
      2,
      `${homeDir}/.config/github-copilot/apps.json`,
      "utf-8"
    );
  });

  it("falls through to gh CLI when config files missing", async () => {
    delete process.env.GITHUB_TOKEN;

    mockReadFile.mockRejectedValue(new Error("ENOENT"));
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(null, { stdout: "gho_ghcli1234567890\n", stderr: "" });
      return {} as any;
    });

    const token = await resolveToken();
    expect(token).toBe("gho_ghcli1234567890");
    expect(mockExecFile).toHaveBeenCalledWith(
      "gh",
      ["auth", "token", "-h", "github.com"],
      expect.any(Function)
    );
  });

  it("calls gh auth token via safe process spawning (not shell-based)", async () => {
    delete process.env.GITHUB_TOKEN;

    mockReadFile.mockRejectedValue(new Error("ENOENT"));
    mockExecFile.mockImplementation((file, args, callback: any) => {
      // Verify args are passed as array, not shell string
      expect(args).toEqual(["auth", "token", "-h", "github.com"]);
      callback(null, { stdout: "gho_test\n", stderr: "" });
      return {} as any;
    });

    await resolveToken();
    expect(mockExecFile).toHaveBeenCalledWith("gh", expect.any(Array), expect.any(Function));
  });

  it("throws AuthError no_token when all sources fail", async () => {
    delete process.env.GITHUB_TOKEN;

    mockReadFile.mockRejectedValue(new Error("ENOENT"));
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(new Error("gh not found"), { stdout: "", stderr: "gh: command not found" });
      return {} as any;
    });

    await expect(resolveToken()).rejects.toThrow(AuthError);
    await expect(resolveToken()).rejects.toMatchObject({
      code: "no_token",
      recoverable: false,
    });
  });

  it("handles malformed JSON in config files gracefully", async () => {
    delete process.env.GITHUB_TOKEN;

    mockReadFile.mockResolvedValueOnce("{ invalid json }"); // hosts.json malformed
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": { oauth_token: "gho_fallback" } })
    );

    const token = await resolveToken();
    expect(token).toBe("gho_fallback");
    expect(mockReadFile).toHaveBeenCalledTimes(2);
  });

  it("trims whitespace-only GITHUB_TOKEN and falls through", async () => {
    process.env.GITHUB_TOKEN = "   \n  ";

    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": { oauth_token: "gho_after_whitespace" } })
    );

    const token = await resolveToken();
    expect(token).toBe("gho_after_whitespace");
  });

  it("falls through when config has github.com but no oauth_token", async () => {
    delete process.env.GITHUB_TOKEN;
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": { user: "test" } }) // no oauth_token
    );
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": { oauth_token: "" } }) // empty oauth_token
    );
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(null, { stdout: "gho_fallback_oauth\n", stderr: "" });
      return {} as any;
    });

    const token = await resolveToken();
    expect(token).toBe("gho_fallback_oauth");
  });

  it("falls through when config has no github.com entry", async () => {
    delete process.env.GITHUB_TOKEN;
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "gitlab.com": { oauth_token: "should_ignore" } })
    );
    mockReadFile.mockRejectedValueOnce(new Error("ENOENT"));
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(null, { stdout: "gho_ghcli_only\n", stderr: "" });
      return {} as any;
    });

    const token = await resolveToken();
    expect(token).toBe("gho_ghcli_only");
  });

  it("falls through when config entry value is not an object", async () => {
    delete process.env.GITHUB_TOKEN;
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": "just_a_string" })
    );
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": null })
    );
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(null, { stdout: "gho_nonobj_fallback\n", stderr: "" });
      return {} as any;
    });

    const token = await resolveToken();
    expect(token).toBe("gho_nonobj_fallback");
  });

  it("matches github.com:PORT keys (Copilot config format)", async () => {
    delete process.env.GITHUB_TOKEN;
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com:443": { oauth_token: "gho_port_token" } })
    );

    const token = await resolveToken();
    expect(token).toBe("gho_port_token");
    expect(mockExecFile).not.toHaveBeenCalled();
  });

  it("handles config file containing primitive JSON (number, boolean)", async () => {
    delete process.env.GITHUB_TOKEN;
    mockReadFile.mockResolvedValueOnce("42");    // hosts.json = number
    mockReadFile.mockResolvedValueOnce("true");  // apps.json = boolean
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(null, { stdout: "gho_after_primitive\n", stderr: "" });
      return {} as any;
    });

    const token = await resolveToken();
    expect(token).toBe("gho_after_primitive");
  });

  it("skips config entries where oauth_token is not a string", async () => {
    delete process.env.GITHUB_TOKEN;
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": { oauth_token: 12345 } })
    );
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": { oauth_token: true } })
    );
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(null, { stdout: "gho_typed_fallback\n", stderr: "" });
      return {} as any;
    });

    const token = await resolveToken();
    expect(token).toBe("gho_typed_fallback");
  });

  it("only matches exact github.com host, not substrings", async () => {
    delete process.env.GITHUB_TOKEN;
    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "not-github.com": { oauth_token: "should_ignore" } })
    );
    mockReadFile.mockRejectedValueOnce(new Error("ENOENT"));
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(null, { stdout: "gho_exact_match\n", stderr: "" });
      return {} as any;
    });

    const token = await resolveToken();
    expect(token).toBe("gho_exact_match");
  });

  it("throws no_token when gh CLI returns empty stdout", async () => {
    delete process.env.GITHUB_TOKEN;
    mockReadFile.mockRejectedValue(new Error("ENOENT"));
    mockExecFile.mockImplementation((file, args, callback: any) => {
      callback(null, { stdout: "  \n", stderr: "" }); // whitespace only
      return {} as any;
    });

    await expect(resolveToken()).rejects.toMatchObject({
      code: "no_token",
    });
  });

  it("expands ~ via os.homedir() for config paths", async () => {
    delete process.env.GITHUB_TOKEN;
    const homeDir = os.homedir();

    mockReadFile.mockResolvedValueOnce(
      JSON.stringify({ "github.com": { oauth_token: "gho_test" } })
    );

    await resolveToken();

    // Verify that we used absolute path, not ~
    const callPath = mockReadFile.mock.calls[0][0];
    expect(callPath).toBe(`${homeDir}/.config/github-copilot/hosts.json`);
    expect(callPath).not.toContain("~");
  });
});

describe("exchangeSessionToken", () => {
  beforeEach(() => {
    // Reset fetch mock
    vi.stubGlobal("fetch", vi.fn());
  });

  it("exchanges OAuth token for session token via /copilot_internal/v2/token", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_1234567890abcdef",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    } as Response);

    const result = await exchangeSessionToken("gho_oauth1234567890");

    expect(result.token).toBe("sess_1234567890abcdef");
    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.github.com/copilot_internal/v2/token",
      {
        headers: {
          Authorization: "Token gho_oauth1234567890",
          Accept: "application/json",
        },
      }
    );
  });

  it("caches session token in memory", async () => {
    const mockFetch = vi.mocked(global.fetch);
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_cached",
        expires_at: expiresAt,
      }),
    } as Response);

    await exchangeSessionToken("gho_test");
    mockFetch.mockClear();

    // Second call should use cache
    const result = await exchangeSessionToken("gho_test");
    expect(result.token).toBe("sess_cached");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("returns cached token when not expired", async () => {
    const mockFetch = vi.mocked(global.fetch);
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_valid",
        expires_at: expiresAt,
      }),
    } as Response);

    const result1 = await exchangeSessionToken("gho_test");
    const result2 = await exchangeSessionToken("gho_test");

    expect(result1.token).toBe("sess_valid");
    expect(result2.token).toBe("sess_valid");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("re-fetches when token is within expiry buffer", async () => {
    const mockFetch = vi.mocked(global.fetch);

    // First call: token valid but within 60s buffer
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_near_expiry",
        expires_at: Math.floor(Date.now() / 1000) + 10, // Within 60s buffer
      }),
    } as Response);

    await exchangeSessionToken("gho_test");

    // Second call: cache check fails (within buffer), should re-fetch
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_new",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    } as Response);

    const result = await exchangeSessionToken("gho_test");
    expect(result.token).toBe("sess_new");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("concurrent callers share one refresh (mutex)", async () => {
    const mockFetch = vi.mocked(global.fetch);
    let resolveResponse: any;

    // Create a promise that we control
    const responsePromise = new Promise((resolve) => {
      resolveResponse = resolve;
    });

    mockFetch.mockReturnValueOnce(responsePromise as any);

    // Start multiple concurrent calls
    const promise1 = exchangeSessionToken("gho_concurrent");
    const promise2 = exchangeSessionToken("gho_concurrent");
    const promise3 = exchangeSessionToken("gho_concurrent");

    // Resolve the fetch
    resolveResponse({
      ok: true,
      json: async () => ({
        token: "sess_shared",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    });

    const [result1, result2, result3] = await Promise.all([promise1, promise2, promise3]);

    expect(result1.token).toBe("sess_shared");
    expect(result2.token).toBe("sess_shared");
    expect(result3.token).toBe("sess_shared");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("wraps network errors as AuthError exchange_failed", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockRejectedValueOnce(new TypeError("fetch failed"));

    try {
      await exchangeSessionToken("gho_network_test1234");
      expect.fail("Should have thrown AuthError");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthError);
      expect(err).toMatchObject({
        code: "exchange_failed",
        recoverable: false,
      });
      expect((err as AuthError).message).toContain("Network error");
      expect((err as AuthError).cause).toBeInstanceOf(TypeError);
    }
  });

  it("throws AuthError on invalid response schema", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ invalid: "response" }),
    } as Response);

    try {
      await exchangeSessionToken("gho_schema_test1234");
      expect.fail("Should have thrown AuthError");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthError);
      expect(err).toMatchObject({
        code: "exchange_failed",
        recoverable: false,
      });
      expect((err as AuthError).message).toContain("Invalid token exchange response schema");
    }
  });

  it.each([
    { value: null, label: "null" },
    { value: [1, 2, 3], label: "array" },
    { value: "string", label: "string" },
  ])("rejects non-object JSON response: $label", async ({ value }) => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => value,
    } as Response);

    await expect(exchangeSessionToken("gho_nonobj_test1234")).rejects.toMatchObject({
      code: "exchange_failed",
    });
  });

  it("clears stale cache on exchange error", async () => {
    const mockFetch = vi.mocked(global.fetch);

    // First: successful exchange with token within buffer
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_will_expire",
        expires_at: Math.floor(Date.now() / 1000) + 10, // Within buffer
      }),
    } as Response);
    await exchangeSessionToken("gho_test1234567890");

    // Second: exchange fails (HTTP error) — triggered because token is within buffer
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    } as Response);

    try {
      await exchangeSessionToken("gho_test1234567890");
    } catch {
      // expected
    }

    // Third: should attempt fresh fetch (cache was cleared on error)
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_fresh",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    } as Response);

    const result = await exchangeSessionToken("gho_test1234567890");
    expect(result.token).toBe("sess_fresh");
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it("handles non-Error thrown by fetch", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockRejectedValueOnce("string error");

    const err = await exchangeSessionToken("gho_nonError_test1234").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect((err as AuthError).message).toContain("string error");
    expect((err as AuthError).cause).toBeUndefined();
  });

  it.each([
    { value: NaN, label: "NaN" },
    { value: Infinity, label: "Infinity" },
    { value: -Infinity, label: "-Infinity" },
  ])("rejects non-finite expires_at: $label", async ({ value }) => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ token: "valid_token", expires_at: value }),
    } as Response);

    await expect(exchangeSessionToken("gho_finite_test1234")).rejects.toMatchObject({
      code: "exchange_failed",
    });
  });

  it("redacts short tokens to **** in error messages", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
    } as Response);

    try {
      await exchangeSessionToken("short_tok");
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.message).not.toContain("short_tok");
      expect(err.message).toContain("****");
    }
  });

  it("throws AuthError when response body is not valid JSON", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => { throw new SyntaxError("Unexpected token"); },
    } as unknown as Response);

    try {
      await exchangeSessionToken("gho_json_parse_test1");
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err).toBeInstanceOf(AuthError);
      expect(err.code).toBe("exchange_failed");
      expect(err.message).toContain("Invalid JSON response");
      expect(err.cause).toBeInstanceOf(SyntaxError);
    }
  });

  it.each([
    { token: "", expires_at: 9999999999, label: "empty token" },
    { token: "valid", expires_at: 0, label: "zero expires_at" },
    { token: "valid", expires_at: -1, label: "negative expires_at" },
  ])("rejects invalid schema: $label", async ({ token, expires_at }) => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ token, expires_at }),
    } as Response);

    await expect(exchangeSessionToken("gho_boundary_test1234")).rejects.toMatchObject({
      code: "exchange_failed",
    });
  });

  it("rejects already-expired token from API", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_past",
        expires_at: Math.floor(Date.now() / 1000) - 100,
      }),
    } as Response);

    await expect(exchangeSessionToken("gho_expired_test1234")).rejects.toMatchObject({
      code: "exchange_failed",
    });
  });

  it("invalidates cache when OAuth token changes", async () => {
    const mockFetch = vi.mocked(global.fetch);

    // First call with token A
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_user_a",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    } as Response);
    const resultA = await exchangeSessionToken("gho_user_a_1234567890");
    expect(resultA.token).toBe("sess_user_a");

    // Second call with different token B — should NOT use cache
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_user_b",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    } as Response);
    const resultB = await exchangeSessionToken("gho_user_b_1234567890");
    expect(resultB.token).toBe("sess_user_b");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("falls back to OAuth token on 404 (org/enterprise plan)", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
    } as Response);

    const result = await exchangeSessionToken("gho_org_token_1234567890");
    expect(result.token).toBe("gho_org_token_1234567890");
    expect(result.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("caches the 404 fallback token", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: "Not Found",
    } as Response);

    await exchangeSessionToken("gho_org_cached_12345678");
    mockFetch.mockClear();

    const result = await exchangeSessionToken("gho_org_cached_12345678");
    expect(result.token).toBe("gho_org_cached_12345678");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("still throws AuthError on non-404 HTTP errors", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
    } as Response);

    try {
      await exchangeSessionToken("gho_bad");
      expect.fail("Should have thrown AuthError");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthError);
      expect(err).toMatchObject({
        code: "exchange_failed",
        recoverable: false,
      });
    }
  });

  it("never includes raw token values in error messages", async () => {
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
    } as Response);

    try {
      await exchangeSessionToken("gho_secret1234567890abcdef");
    } catch (err: any) {
      expect(err.message).not.toContain("gho_secret1234567890abcdef");
      // Should contain redacted version: first 4 + ... + last 4
      expect(err.message).toMatch(/gho_.*\.\.\..*(cdef|abcdef)/);
    }
  });
});

describe("getAuthenticatedHeaders", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("returns headers with Bearer session_token", async () => {
    process.env.GITHUB_TOKEN = "gho_test1234567890";

    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_bearer",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    } as Response);

    const headers = await getAuthenticatedHeaders();

    expect(headers).toEqual({
      Authorization: "Bearer sess_bearer",
    });
  });

  it("never includes raw OAuth token in exchange error messages", async () => {
    process.env.GITHUB_TOKEN = "gho_secret1234567890abcdefghijklmnop";
    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: "Forbidden",
    } as Response);

    try {
      await getAuthenticatedHeaders();
      expect.fail("Should have thrown");
    } catch (err: any) {
      expect(err.message).not.toContain("gho_secret1234567890abcdefghijklmnop");
      // Should contain redacted form (first 4 + ... + last 4)
      expect(err.message).toContain("gho_...mnop");
    }
  });
});

describe("createDefaultAuthProvider", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("returns AuthProvider interface implementation", () => {
    const provider = createDefaultAuthProvider();

    expect(provider).toHaveProperty("getAuthenticatedHeaders");
    expect(typeof provider.getAuthenticatedHeaders).toBe("function");
  });

  it("getAuthenticatedHeaders returns proper headers", async () => {
    process.env.GITHUB_TOKEN = "gho_provider";

    const mockFetch = vi.mocked(global.fetch);
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        token: "sess_provider",
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }),
    } as Response);

    const provider = createDefaultAuthProvider();
    const headers = await provider.getAuthenticatedHeaders();

    expect(headers).toEqual({
      Authorization: "Bearer sess_provider",
    });
  });
});
