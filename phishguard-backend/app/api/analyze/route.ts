import { NextRequest, NextResponse } from "next/server";
import { analyzeEmail } from "@/lib/analyzer";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const MAX_FIELD = 50_000;

export async function POST(request: NextRequest) {
  try {
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > 250_000) return NextResponse.json({ error: "Request is too large. Keep the submitted email under 250 KB." }, { status: 413 });
    const data = await request.json();
    const fields = ["sender", "displayName", "subject", "body", "attachments", "headers"] as const;
    const input: { sender: string; displayName: string; subject: string; body: string; attachments: string; headers: string } = { sender: "", displayName: "", subject: "", body: "", attachments: "", headers: "" };
    for (const field of fields) {
      const value = data?.[field] == null ? "" : String(data[field]);
      if (value.length > MAX_FIELD) return NextResponse.json({ error: `${field} is too long. Each field must be 50,000 characters or less.` }, { status: 400 });
      input[field] = value;
    }
    const hashes = Array.isArray(data?.attachmentHashes) ? data.attachmentHashes.slice(0, 10).map((v: unknown) => String(v).trim().toLowerCase()).filter((v: string) => /^[a-f0-9]{64}$/.test(v)) : [];
    if (!input.sender && !input.subject && !input.body && !input.headers && !input.attachments) return NextResponse.json({ error: "Enter at least one email field to analyze." }, { status: 400 });
    // Hash-only lookup avoids uploading private attachment contents. API keys remain server-side.
    const report = await analyzeEmail({ ...input, attachmentHashes: hashes });
    return NextResponse.json(report, { headers: { "Cache-Control": "no-store, max-age=0", "X-Content-Type-Options": "nosniff" } });
  } catch {
    return NextResponse.json({ error: "Could not analyze this request. Check that the input is valid and try again." }, { status: 400, headers: { "Cache-Control": "no-store" } });
  }
}
