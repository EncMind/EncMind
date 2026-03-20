/**
 * @encmind/skill-sdk — TypeScript SDK for EncMind WASM skills (Javy ABI).
 *
 * Usage:
 *   import { registerTool } from '@encmind/skill-sdk';
 *
 *   registerTool((input) => {
 *     return { result: `Hello from ${input.name}!` };
 *   });
 *
 * Build with javy:
 *   npx tsc && javy compile dist/index.js -o skill.wasm
 *
 * Note: this package entrypoint is intentionally tool-only for Javy ABI.
 * Timer/transform type aliases live in `./types.js` for shared typing, but
 * Javy runtime execution supports tool handlers only.
 */

export type {
  SkillInput,
  SkillOutput,
  ToolHandler,
} from "./types.js";

import type { SkillInput, SkillOutput, ToolHandler } from "./types.js";
import { setHandler, main } from "./runtime.js";

/**
 * Register the main tool handler for this skill.
 * Only one tool handler can be registered per skill.
 *
 * IMPORTANT: Call this once at module top level (typically as the last line
 * after setup). Registration triggers one invocation cycle: read stdin,
 * dispatch to your handler, write stdout.
 */
export function registerTool(handler: ToolHandler): void {
  // Javy runs module top-level code once per invocation. Keep registration
  // and execution coupled so we never execute before a handler is set.
  setHandler((raw: unknown) => handler(raw as SkillInput));
  main();
}
