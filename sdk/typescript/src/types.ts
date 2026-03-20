/**
 * Input received by a skill tool handler.
 *
 * This is the raw tool-argument object provided by the caller.
 * Example: `{ "message": "hello" }`
 */
export type SkillInput = Record<string, unknown>;

/**
 * Output returned by a skill tool handler.
 */
export interface SkillOutput {
  /** Result string returned to the agent */
  result: string;
}

/**
 * Context provided to timer tick handlers.
 *
 * Native ABI only: Javy skills do not support timers.
 */
export interface TimerContext {
  /** Timer name as declared in the manifest */
  timer_name: string;
  /** Skill ID */
  skill_id: string;
  /** Timestamp of the tick (RFC3339) */
  tick_at: string;
}

/**
 * Context provided to channel transform handlers.
 *
 * Native ABI only: Javy skills do not support transforms.
 */
export interface TransformContext {
  /** Direction of the transform */
  direction: "inbound" | "outbound";
  /** Channel name (e.g., "telegram", "slack") */
  channel: string;
}

/**
 * Inbound message structure passed to transform_inbound.
 */
export interface InboundMessage {
  channel: string;
  sender_id: string;
  content: ContentBlock[];
  attachments: Attachment[];
  timestamp: string;
}

/**
 * Outbound message structure passed to transform_outbound.
 */
export interface OutboundMessage {
  content: ContentBlock[];
  attachments: Attachment[];
}

/**
 * A content block in a message.
 */
export type ContentBlock =
  | { type: "text"; text: string }
  | { type: "image"; url: string; alt?: string };

/**
 * An attachment in a message.
 */
export interface Attachment {
  filename: string;
  mime_type: string;
  data_base64: string;
}

/**
 * Handler function type for tool invocations.
 * Javy ABI execution is synchronous; async handlers are not supported.
 */
export type ToolHandler = (input: SkillInput) => SkillOutput;

/**
 * Handler function type for timer ticks.
 *
 * Native ABI only: Javy skills do not support timers.
 */
export type TimerHandler = (ctx: TimerContext) => void | Promise<void>;

/**
 * Handler function type for inbound message transforms.
 * Return null/undefined to drop the message.
 *
 * Native ABI only: Javy skills do not support transforms.
 */
export type InboundTransformHandler = (
  msg: InboundMessage,
  ctx: TransformContext,
) => InboundMessage | null | undefined | Promise<InboundMessage | null | undefined>;

/**
 * Handler function type for outbound message transforms.
 * Return null/undefined to drop the message.
 *
 * Native ABI only: Javy skills do not support transforms.
 */
export type OutboundTransformHandler = (
  msg: OutboundMessage,
  ctx: TransformContext,
) => OutboundMessage | null | undefined | Promise<OutboundMessage | null | undefined>;
