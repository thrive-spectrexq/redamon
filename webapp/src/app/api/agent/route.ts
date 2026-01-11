import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_BASE_URL = process.env.AGENT_API_URL || process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:8080'

export interface QueryRequest {
  question: string
  user_id: string
  project_id: string
  session_id: string
}

export interface QueryResponse {
  answer: string
  tool_used: string | null
  tool_output: string | null
  session_id: string
  message_count: number
  error: string | null
}

export async function POST(request: NextRequest) {
  try {
    const body: QueryRequest = await request.json()

    if (!body.question || !body.project_id || !body.session_id) {
      return NextResponse.json(
        { error: 'question, project_id, and session_id are required' },
        { status: 400 }
      )
    }

    const response = await fetch(`${AGENT_API_BASE_URL}/query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      const errorText = await response.text()
      return NextResponse.json(
        { error: `Agent API error: ${response.status} - ${errorText}` },
        { status: response.status }
      )
    }

    const data: QueryResponse = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    console.error('Agent query error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  }
}
