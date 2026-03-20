// EncMind Skill: calc — Precise Calculator & Unit Converter (Javy ABI)
//
// Handles: arithmetic, unit conversion, percentage, date math.
// Uses Javy stdin/stdout JSON protocol.

// ---------------------------------------------------------------------------
// Javy ABI I/O
// ---------------------------------------------------------------------------

const MAX_STDIN_BYTES = 16 * 1024 * 1024;
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder();

function readAll(fd: number): Uint8Array {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const buf = new Uint8Array(4096);
  while (true) {
    const n = Javy.IO.readSync(fd, buf);
    if (n === 0) break;
    total += n;
    if (total > MAX_STDIN_BYTES) {
      throw new Error(`stdin exceeds ${MAX_STDIN_BYTES} bytes`);
    }
    chunks.push(buf.slice(0, n));
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function writeJson(value: unknown): void {
  const json = JSON.stringify(value);
  Javy.IO.writeSync(1, ENCODER.encode(json));
}

function writeError(message: string): void {
  writeJson({ _encmind: { runtime_error: message } });
}

// ---------------------------------------------------------------------------
// Unit conversion tables
// ---------------------------------------------------------------------------

type ConversionValue = number | ((v: number) => number);
type UnitTable = Record<string, Record<string, ConversionValue>>;

const UNITS: UnitTable = {
  // Length
  km:    { miles: 0.621371, m: 1000, ft: 3280.84, yd: 1093.61 },
  miles: { km: 1.60934, m: 1609.34, ft: 5280, yd: 1760 },
  m:     { km: 0.001, miles: 0.000621371, ft: 3.28084, cm: 100, mm: 1000, yd: 1.09361 },
  ft:    { m: 0.3048, km: 0.0003048, miles: 0.000189394, inches: 12, cm: 30.48, yd: 0.333333 },
  inches: { cm: 2.54, ft: 1 / 12, m: 0.0254 },
  cm:    { m: 0.01, inches: 0.393701, mm: 10, ft: 0.0328084 },
  mm:    { cm: 0.1, m: 0.001, inches: 0.0393701 },
  yd:    { m: 0.9144, ft: 3, miles: 0.000568182 },

  // Weight
  kg:  { lbs: 2.20462, g: 1000, oz: 35.274 },
  lbs: { kg: 0.453592, g: 453.592, oz: 16 },
  g:   { kg: 0.001, lbs: 0.00220462, oz: 0.035274, mg: 1000 },
  oz:  { g: 28.3495, kg: 0.0283495, lbs: 0.0625 },

  // Temperature (functions)
  celsius:    { fahrenheit: (c: number) => c * 9 / 5 + 32, kelvin: (c: number) => c + 273.15 },
  fahrenheit: { celsius: (f: number) => (f - 32) * 5 / 9, kelvin: (f: number) => (f - 32) * 5 / 9 + 273.15 },
  kelvin:     { celsius: (k: number) => k - 273.15, fahrenheit: (k: number) => (k - 273.15) * 9 / 5 + 32 },
  c: { f: (c: number) => c * 9 / 5 + 32, k: (c: number) => c + 273.15 },
  f: { c: (f: number) => (f - 32) * 5 / 9, k: (f: number) => (f - 32) * 5 / 9 + 273.15 },

  // Data
  bytes: { kb: 1 / 1024, mb: 1 / 1048576, gb: 1 / 1073741824, tb: 1 / 1099511627776 },
  kb:    { bytes: 1024, mb: 1 / 1024, gb: 1 / 1048576 },
  mb:    { bytes: 1048576, kb: 1024, gb: 1 / 1024, tb: 1 / 1048576 },
  gb:    { bytes: 1073741824, kb: 1048576, mb: 1024, tb: 1 / 1024 },
  tb:    { bytes: 1099511627776, kb: 1073741824, mb: 1048576, gb: 1024 },

  // Speed
  mph: { kph: 1.60934, mps: 0.44704, knots: 0.868976 },
  kph: { mph: 0.621371, mps: 0.277778, knots: 0.539957 },

  // Volume
  liters:  { gallons: 0.264172, ml: 1000, cups: 4.22675 },
  gallons: { liters: 3.78541, ml: 3785.41, cups: 16 },
  ml:      { liters: 0.001, cups: 0.00422675 },
};

// Aliases for unit names
const UNIT_ALIASES: Record<string, string> = {
  kilometer: "km", kilometers: "km",
  mile: "miles",
  meter: "m", meters: "m", metre: "m", metres: "m",
  foot: "ft", feet: "ft",
  inch: "inches",
  centimeter: "cm", centimeters: "cm",
  millimeter: "mm", millimeters: "mm",
  yard: "yd", yards: "yd",
  kilogram: "kg", kilograms: "kg",
  pound: "lbs", pounds: "lbs", lb: "lbs",
  gram: "g", grams: "g",
  ounce: "oz", ounces: "oz",
  liter: "liters", litre: "liters", litres: "liters",
  gallon: "gallons",
  milliliter: "ml", milliliters: "ml", millilitre: "ml",
  cup: "cups",
  byte: "bytes",
  kilobyte: "kb", kilobytes: "kb",
  megabyte: "mb", megabytes: "mb",
  gigabyte: "gb", gigabytes: "gb",
  terabyte: "tb", terabytes: "tb",
};

function normalizeUnit(unit: string): string {
  const lower = unit.toLowerCase();
  return UNIT_ALIASES[lower] ?? lower;
}

// ---------------------------------------------------------------------------
// Arithmetic parser (recursive descent — no eval())
// ---------------------------------------------------------------------------

class Parser {
  private pos = 0;
  private readonly expr: string;

  constructor(expr: string) {
    this.expr = expr;
  }

  parse(): number {
    const result = this.parseAddSub();
    this.skipWhitespace();
    if (this.pos < this.expr.length) {
      throw new Error(`unexpected character '${this.expr[this.pos]}' at position ${this.pos}`);
    }
    return result;
  }

  private skipWhitespace(): void {
    while (this.pos < this.expr.length && /\s/.test(this.expr[this.pos])) {
      this.pos++;
    }
  }

  private parseAddSub(): number {
    let left = this.parseMulDiv();
    this.skipWhitespace();
    while (this.pos < this.expr.length && (this.expr[this.pos] === "+" || this.expr[this.pos] === "-")) {
      const op = this.expr[this.pos];
      this.pos++;
      const right = this.parseMulDiv();
      left = op === "+" ? left + right : left - right;
      this.skipWhitespace();
    }
    return left;
  }

  private parseMulDiv(): number {
    let left = this.parsePower();
    this.skipWhitespace();
    while (this.pos < this.expr.length && (this.expr[this.pos] === "*" || this.expr[this.pos] === "/" || this.expr[this.pos] === "%")) {
      const op = this.expr[this.pos];
      this.pos++;
      const right = this.parsePower();
      if (op === "*") left *= right;
      else if (op === "/") {
        if (right === 0) throw new Error("division by zero");
        left /= right;
      } else {
        if (right === 0) throw new Error("modulo by zero");
        left %= right;
      }
      this.skipWhitespace();
    }
    return left;
  }

  private parsePower(): number {
    let base = this.parseUnary();
    this.skipWhitespace();
    if (this.pos < this.expr.length && (this.expr[this.pos] === "^" || this.expr.substring(this.pos, this.pos + 2) === "**")) {
      if (this.expr[this.pos] === "^") {
        this.pos++;
      } else {
        this.pos += 2;
      }
      const exp = this.parsePower(); // right-associative
      base = Math.pow(base, exp);
    }
    return base;
  }

  private parseUnary(): number {
    this.skipWhitespace();
    if (this.pos < this.expr.length && this.expr[this.pos] === "-") {
      this.pos++;
      return -this.parseUnary();
    }
    if (this.pos < this.expr.length && this.expr[this.pos] === "+") {
      this.pos++;
      return this.parseUnary();
    }
    return this.parseAtom();
  }

  private parseAtom(): number {
    this.skipWhitespace();

    // Parentheses
    if (this.pos < this.expr.length && this.expr[this.pos] === "(") {
      this.pos++;
      const val = this.parseAddSub();
      this.skipWhitespace();
      if (this.pos >= this.expr.length || this.expr[this.pos] !== ")") {
        throw new Error("missing closing parenthesis");
      }
      this.pos++;
      return val;
    }

    // Named constants & functions
    const funcMatch = this.expr.substring(this.pos).match(/^([a-zA-Z_]\w*)\s*\(/);
    if (funcMatch) {
      const name = funcMatch[1].toLowerCase();
      this.pos += funcMatch[0].length;
      const arg = this.parseAddSub();
      this.skipWhitespace();
      if (this.pos >= this.expr.length || this.expr[this.pos] !== ")") {
        throw new Error(`missing closing parenthesis for ${name}()`);
      }
      this.pos++;
      return this.callFunction(name, arg);
    }

    // Named constants (pi, e)
    const constMatch = this.expr.substring(this.pos).match(/^(pi|e)\b/i);
    if (constMatch) {
      this.pos += constMatch[0].length;
      const name = constMatch[1].toLowerCase();
      switch (name) {
        case "pi":
          return Math.PI;
        case "e":
          return Math.E;
        default:
          throw new Error(`unsupported constant '${name}'`);
      }
    }

    // Number
    const numMatch = this.expr.substring(this.pos).match(
      /^((?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)/
    );
    if (numMatch) {
      this.pos += numMatch[0].length;
      return parseFloat(numMatch[0]);
    }

    throw new Error(`unexpected token at position ${this.pos}: '${this.expr.substring(this.pos, this.pos + 10)}'`);
  }

  private callFunction(name: string, arg: number): number {
    switch (name) {
      case "sqrt": return Math.sqrt(arg);
      case "abs": return Math.abs(arg);
      case "ceil": return Math.ceil(arg);
      case "floor": return Math.floor(arg);
      case "round": return Math.round(arg);
      case "log": return Math.log(arg);
      case "log2": return Math.log2(arg);
      case "log10": return Math.log10(arg);
      case "ln": return Math.log(arg);
      case "sin": return Math.sin(arg);
      case "cos": return Math.cos(arg);
      case "tan": return Math.tan(arg);
      case "asin": return Math.asin(arg);
      case "acos": return Math.acos(arg);
      case "atan": return Math.atan(arg);
      case "exp": return Math.exp(arg);
      default: throw new Error(`unknown function '${name}'`);
    }
  }
}

function evaluateArithmetic(expr: string): number {
  return new Parser(expr).parse();
}

// ---------------------------------------------------------------------------
// Format numbers nicely
// ---------------------------------------------------------------------------

function formatNumber(n: number): string {
  if (Number.isInteger(n) && Math.abs(n) < 1e15) {
    return n.toString();
  }
  // Up to 10 decimal places, strip trailing zeros
  const s = n.toFixed(10).replace(/\.?0+$/, "");
  return s;
}

function parseIsoDateStrict(input: string): Date | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(input);
  if (!match) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) {
    return null;
  }
  if (month < 1 || month > 12 || day < 1 || day > 31) {
    return null;
  }

  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return null;
  }
  return date;
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

function handle(input: Record<string, unknown>): { result: string } {
  const expr = ((input.expression as string) ?? "").trim();
  if (!expr) {
    return { result: "error: 'expression' is required" };
  }

  // 1. Unit conversion: "100 km to miles"
  const unitMatch = expr.match(/^(-?[\d.,]+)\s+(\w+)\s+(?:to|in|as)\s+(\w+)$/i);
  if (unitMatch) {
    const value = parseFloat(unitMatch[1].replace(/,/g, ""));
    const from = normalizeUnit(unitMatch[2]);
    const to = normalizeUnit(unitMatch[3]);

    if (isNaN(value)) {
      return { result: `error: invalid number '${unitMatch[1]}'` };
    }

    const fromTable = UNITS[from];
    if (!fromTable) {
      return { result: `error: unknown unit '${unitMatch[2]}'` };
    }

    const converter = fromTable[to];
    if (converter === undefined) {
      return { result: `error: cannot convert ${from} to ${to}` };
    }

    const converted = typeof converter === "function" ? converter(value) : value * converter;
    return { result: `${formatNumber(value)} ${from} = ${formatNumber(converted)} ${to}` };
  }

  // 2. Percentage: "15% of 847.50"
  const pctMatch = expr.match(/^([\d.,]+)\s*%\s+of\s+([\d.,]+)$/i);
  if (pctMatch) {
    const pct = parseFloat(pctMatch[1].replace(/,/g, ""));
    const base = parseFloat(pctMatch[2].replace(/,/g, ""));
    if (isNaN(pct) || isNaN(base)) {
      return { result: "error: invalid numbers in percentage expression" };
    }
    const result = (pct / 100) * base;
    return { result: `${formatNumber(pct)}% of ${formatNumber(base)} = ${formatNumber(result)}` };
  }

  // 3. "What percentage is X of Y"
  const whatPctMatch = expr.match(/^what\s+(?:percent(?:age)?|%)\s+(?:is\s+)?([\d.,]+)\s+of\s+([\d.,]+)/i);
  if (whatPctMatch) {
    const part = parseFloat(whatPctMatch[1].replace(/,/g, ""));
    const whole = parseFloat(whatPctMatch[2].replace(/,/g, ""));
    if (isNaN(part) || isNaN(whole) || whole === 0) {
      return { result: "error: invalid numbers or division by zero" };
    }
    const pct = (part / whole) * 100;
    return { result: `${formatNumber(part)} is ${formatNumber(pct)}% of ${formatNumber(whole)}` };
  }

  // 4. Date math: "days between 2024-01-15 and 2024-12-31"
  const dateMatch = expr.match(
    /days?\s+between\s+(\d{4}-\d{2}-\d{2})\s+and\s+(\d{4}-\d{2}-\d{2})/i
  );
  if (dateMatch) {
    const d1 = parseIsoDateStrict(dateMatch[1]);
    const d2 = parseIsoDateStrict(dateMatch[2]);
    if (!d1 || !d2) {
      return { result: "error: invalid date format (use YYYY-MM-DD)" };
    }
    const diffMs = Math.abs(d2.getTime() - d1.getTime());
    const days = Math.round(diffMs / (1000 * 60 * 60 * 24));
    return { result: `${days} days between ${dateMatch[1]} and ${dateMatch[2]}` };
  }

  // 5. Arithmetic expression
  try {
    const result = evaluateArithmetic(expr);
    if (!isFinite(result)) {
      return { result: `${expr} = Infinity` };
    }
    return { result: `${expr} = ${formatNumber(result)}` };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { result: `error: ${msg}` };
  }
}

// ---------------------------------------------------------------------------
// Javy ABI entry point
// ---------------------------------------------------------------------------

function main(): void {
  try {
    const stdinBytes = readAll(0);
    if (stdinBytes.length === 0) {
      writeError("no input received on stdin");
      return;
    }

    const inputStr = DECODER.decode(stdinBytes);
    let input: Record<string, unknown>;
    try {
      input = JSON.parse(inputStr);
    } catch {
      writeError("invalid JSON input");
      return;
    }

    const output = handle(input);
    writeJson(output);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    writeError(msg);
  }
}

main();
