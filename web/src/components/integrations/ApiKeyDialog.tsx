// ============================================================================
// Operator OS — API Key Dialog
// Modal for entering an API key to connect an integration.
// Includes show/hide toggle, paste from clipboard, and security note.
// ============================================================================

import { useState, useCallback } from 'react'
import { Key, Eye, EyeSlash, ClipboardText, ShieldCheck } from '@phosphor-icons/react'
import { Modal } from '../shared/Modal'
import { Button } from '../shared/Button'
import type { IntegrationSummary } from '../../types/api'

interface ApiKeyDialogProps {
  open: boolean
  onClose: () => void
  integration: IntegrationSummary | null
  onSubmit: (apiKey: string) => void
  loading?: boolean
  error?: string | null
}

export function ApiKeyDialog({
  open,
  onClose,
  integration,
  onSubmit,
  loading,
  error,
}: ApiKeyDialogProps) {
  const [apiKey, setApiKey] = useState('')
  const [showKey, setShowKey] = useState(false)
  const [pasted, setPasted] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (apiKey.trim()) {
      onSubmit(apiKey.trim())
    }
  }

  const handleClose = () => {
    setApiKey('')
    setShowKey(false)
    setPasted(false)
    onClose()
  }

  const handlePaste = useCallback(async () => {
    try {
      const text = await navigator.clipboard.readText()
      if (text) {
        setApiKey(text.trim())
        setPasted(true)
        setTimeout(() => setPasted(false), 2000)
      }
    } catch {
      // Clipboard API not available or permission denied — ignore
    }
  }, [])

  if (!integration) return null

  return (
    <Modal open={open} onClose={handleClose} title={`Connect ${integration.name}`}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        {/* Description */}
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          Enter your API key to connect <strong className="text-[var(--text)]">{integration.name}</strong>.
        </p>

        {/* API Key Input */}
        <div className="flex flex-col gap-1.5">
          <label
            htmlFor="api-key-input"
            className="text-xs font-medium text-[var(--text-secondary)]"
          >
            API Key
          </label>
          <div className="relative flex gap-2">
            <div className="relative flex-1">
              <div className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-dim)]">
                <Key size={16} />
              </div>
              <input
                id="api-key-input"
                type={showKey ? 'text' : 'password'}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk-..."
                autoFocus
                className="w-full h-10 pl-9 pr-10
                  bg-[var(--surface-2)] border border-[var(--border-subtle)]
                  rounded-[var(--radius-md)] text-sm text-[var(--text)] font-mono
                  placeholder:text-[var(--text-dim)]
                  focus:border-[var(--accent)] focus:outline-none
                  transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowKey(!showKey)}
                className="absolute right-3 top-1/2 -translate-y-1/2
                  text-[var(--text-dim)] hover:text-[var(--text)]
                  transition-colors cursor-pointer"
                aria-label={showKey ? 'Hide key' : 'Show key'}
              >
                {showKey ? <EyeSlash size={16} /> : <Eye size={16} />}
              </button>
            </div>

            {/* Paste button */}
            <button
              type="button"
              onClick={handlePaste}
              className={`
                shrink-0 flex items-center gap-1.5 px-3 h-10
                rounded-[var(--radius-md)] border text-xs font-medium
                transition-all cursor-pointer
                ${pasted
                  ? 'bg-[var(--success-subtle)] border-[var(--success)]/30 text-[var(--success)]'
                  : 'bg-[var(--surface-2)] border-[var(--border-subtle)] text-[var(--text-dim)] hover:text-[var(--text)] hover:border-[var(--border)]'
                }
              `}
              aria-label="Paste from clipboard"
            >
              <ClipboardText size={14} />
              {pasted ? 'Pasted' : 'Paste'}
            </button>
          </div>
          <p className="text-[11px] text-[var(--text-dim)]">
            Find your API key in your {integration.name} account settings.
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="text-xs text-[var(--error)] bg-[var(--error-subtle)] px-3 py-2 rounded-lg">
            {error}
          </div>
        )}

        {/* Security note */}
        <div className="text-[11px] text-[var(--text-dim)] bg-[var(--surface-2)] rounded-lg px-3 py-2">
          <ShieldCheck size={12} className="inline mr-1 -mt-0.5" />
          Your key is encrypted at rest and never exposed in the UI after saving.
          You can rotate or remove it at any time.
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-2 pt-1">
          <Button variant="ghost" size="sm" type="button" onClick={handleClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            type="submit"
            loading={loading}
            disabled={!apiKey.trim()}
          >
            Connect
          </Button>
        </div>
      </form>
    </Modal>
  )
}
