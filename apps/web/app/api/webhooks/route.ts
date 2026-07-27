import { NextRequest, NextResponse } from "next/server";

const API_URL = process.env.API_URL || "http://localhost:3001";

// The dashboard authenticates with its session cookie, not the API key: keys
// are now stored hashed and shown only once, so the browser never holds one.
function getAuthHeaders(request: NextRequest): Record<string, string> | null {
  const session = request.cookies.get("cg_session")?.value;
  if (session) return { Cookie: `cg_session=${session}` };
  const apiKey = request.headers.get("x-api-key");
  return apiKey ? { Authorization: `Bearer ${apiKey}` } : null;
}

export async function GET(request: NextRequest) {
  const auth = getAuthHeaders(request);
  if (!auth) {
    return NextResponse.json({ webhooks: [] }, { status: 200 });
  }

  try {
    const res = await fetch(`${API_URL}/api/v1/webhooks`, {
      headers: auth,
      cache: "no-store",
    });

    if (!res.ok) {
      return NextResponse.json({ webhooks: [] }, { status: 200 });
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ webhooks: [] }, { status: 200 });
  }
}

export async function POST(request: NextRequest) {
  const auth = getAuthHeaders(request);
  if (!auth) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  try {
    const body = await request.json();
    const res = await fetch(`${API_URL}/api/v1/webhooks`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...auth,
      },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { error: "Failed to create webhook" },
      { status: 502 }
    );
  }
}
