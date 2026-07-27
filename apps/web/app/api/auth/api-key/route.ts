import { NextRequest, NextResponse } from "next/server";

const API_URL = process.env.API_URL || "http://localhost:3001";

/**
 * Issue a fresh API key for the signed-in user. The API stores only a hash, so
 * the plaintext in this response is the single time it can ever be read.
 */
export async function POST(request: NextRequest) {
  const session = request.cookies.get("cg_session")?.value;
  if (!session) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  try {
    const res = await fetch(`${API_URL}/api/v1/auth/api-key`, {
      method: "POST",
      headers: { Cookie: `cg_session=${session}` },
      cache: "no-store",
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { error: "Failed to generate API key" },
      { status: 502 }
    );
  }
}
