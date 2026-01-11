'use client'

import { useState, useRef, useEffect, useCallback, KeyboardEvent } from 'react'
import { Send, Bot, User, Loader2, AlertCircle, Sparkles, RotateCcw } from 'lucide-react'
import styles from './AIAssistantDrawer.module.css'

interface QueryResponse {
  answer: string
  tool_used: string | null
  tool_output: string | null
  session_id: string
  message_count: number
  error: string | null
}

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  toolUsed?: string | null
  toolOutput?: string | null
  error?: string | null
  timestamp: Date
}

interface AIAssistantDrawerProps {
  isOpen: boolean
  onClose: () => void
  userId: string
  projectId: string
  sessionId: string
  onResetSession?: () => void
}

export function AIAssistantDrawer({
  isOpen,
  onClose,
  userId,
  projectId,
  sessionId,
  onResetSession,
}: AIAssistantDrawerProps) {
  const [messages, setMessages] = useState<Message[]>([])
  const [inputValue, setInputValue] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [messages, scrollToBottom])

  useEffect(() => {
    if (isOpen && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 300)
    }
  }, [isOpen])

  // Reset messages when session changes
  useEffect(() => {
    setMessages([])
  }, [sessionId])

  const handleSend = async () => {
    const question = inputValue.trim()
    if (!question || isLoading) return

    const userMessage: Message = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: question,
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInputValue('')
    setIsLoading(true)

    try {
      const res = await fetch('/api/agent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          question,
          user_id: userId,
          project_id: projectId,
          session_id: sessionId,
        }),
      })

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}))
        throw new Error(errorData.error || `Agent API error: ${res.status}`)
      }

      const response: QueryResponse = await res.json()

      const assistantMessage: Message = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        content: response.answer,
        toolUsed: response.tool_used,
        toolOutput: response.tool_output,
        error: response.error,
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, assistantMessage])
    } catch (error) {
      const errorMessage: Message = {
        id: `error-${Date.now()}`,
        role: 'assistant',
        content: 'Sorry, I encountered an error while processing your request.',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value)
    // Auto-resize textarea
    e.target.style.height = 'auto'
    e.target.style.height = `${Math.min(e.target.scrollHeight, 120)}px`
  }

  const handleNewChat = () => {
    setMessages([])
    onResetSession?.()
  }

  return (
    <div
      className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`}
      aria-hidden={!isOpen}
    >
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <div className={styles.headerIcon}>
            <Sparkles size={16} />
          </div>
          <div className={styles.headerText}>
            <h2 className={styles.title}>AI Assistant</h2>
            <span className={styles.subtitle}>Powered by RedAmon Agent</span>
          </div>
        </div>
        <div className={styles.headerActions}>
          <button
            className={styles.iconButton}
            onClick={handleNewChat}
            title="New conversation"
            aria-label="Start new conversation"
          >
            <RotateCcw size={14} />
          </button>
          <button
            className={styles.closeButton}
            onClick={onClose}
            aria-label="Close assistant"
          >
            &times;
          </button>
        </div>
      </div>

      {/* Messages */}
      <div className={styles.messages}>
        {messages.length === 0 && (
          <div className={styles.emptyState}>
            <div className={styles.emptyIcon}>
              <Bot size={32} />
            </div>
            <h3 className={styles.emptyTitle}>How can I help you?</h3>
            <p className={styles.emptyDescription}>
              Ask me about vulnerabilities, scan results, or query the graph database.
            </p>
            <div className={styles.suggestions}>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('What vulnerabilities were found?')}
              >
                What vulnerabilities were found?
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('Show me all CVEs with critical severity')}
              >
                Show me critical CVEs
              </button>
              <button
                className={styles.suggestion}
                onClick={() => setInputValue('What technologies are in use?')}
              >
                What technologies are in use?
              </button>
            </div>
          </div>
        )}

        {messages.map((message) => (
          <div
            key={message.id}
            className={`${styles.message} ${
              message.role === 'user' ? styles.messageUser : styles.messageAssistant
            }`}
          >
            <div className={styles.messageIcon}>
              {message.role === 'user' ? <User size={14} /> : <Bot size={14} />}
            </div>
            <div className={styles.messageContent}>
              <div className={styles.messageText}>
                {message.content.split('\n').map((line, i) => (
                  <p key={i}>{line || '\u00A0'}</p>
                ))}
              </div>

              {message.error && (
                <div className={styles.errorBadge}>
                  <AlertCircle size={12} />
                  <span>{message.error}</span>
                </div>
              )}

            </div>
          </div>
        ))}

        {isLoading && (
          <div className={`${styles.message} ${styles.messageAssistant}`}>
            <div className={styles.messageIcon}>
              <Bot size={14} />
            </div>
            <div className={styles.messageContent}>
              <div className={styles.loadingIndicator}>
                <Loader2 size={14} className={styles.spinner} />
                <span>Thinking...</span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className={styles.inputContainer}>
        <div className={styles.inputWrapper}>
          <textarea
            ref={inputRef}
            className={styles.input}
            value={inputValue}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder="Ask a question..."
            rows={1}
            disabled={isLoading}
          />
          <button
            className={styles.sendButton}
            onClick={handleSend}
            disabled={!inputValue.trim() || isLoading}
            aria-label="Send message"
          >
            {isLoading ? <Loader2 size={16} className={styles.spinner} /> : <Send size={16} />}
          </button>
        </div>
        <span className={styles.inputHint}>Press Enter to send, Shift+Enter for new line</span>
      </div>
    </div>
  )
}
