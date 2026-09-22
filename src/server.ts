import { serve } from "@hono/node-server";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "./app.js";
import { MemoryStore } from "./store.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const store = new MemoryStore();
const port = Number(process.env.PORT ?? 8787);
const publicBase = process.env.LATCH_BASE_URL ?? `http://127.0.0.1:${port}`;

const app = createApp({
  store,
  publicBase,
  webhookRetries: 3,
  opsSecret: process.env.LATCH_OPS_SECRET,
  joinCode: process.env.LATCH_JOIN_CODE,
});

app.get("/", (c) => {
  const index = join(root, "index.html");
  if (existsSync(index)) {
    return c.html(readFileSync(index, "utf8"));
  }
  return c.json({ protocol: "latch", v: 0, health: "/v0/health" });
});

app.get("/styles.css", (c) => {
  const css = join(root, "styles.css");
  if (!existsSync(css)) return c.body("not found", 404);
  return c.body(readFileSync(css, "utf8"), 200, {
    "content-type": "text/css; charset=utf-8",
  });
});

setInterval(() => store.expireDue(), 60_000).unref();

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`Latch v0 listening on http://127.0.0.1:${info.port}`);
  console.log("Communication only. No autonomy. Forget by default.");
});
