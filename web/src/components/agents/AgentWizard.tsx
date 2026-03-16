// ============================================================================
// Operator OS — Agent Creation Wizard
// Step-by-step guided flow for creating a new agent. Designed for new users
// who need more context than the all-at-once AgentEditor modal.
// Steps: Identity → Model → Capabilities → Review & Create
// ============================================================================

import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  Robot,
  Brain,
  Wrench,
  CheckCircle,
  ArrowRight,
  ArrowLeft,
  Sparkle,
} from '@phosphor-icons/react'
import { Modal } from '../shared/Modal'
import { Button } from '../shared/Button'
import { Input } from '../shared/Input'
import { Badge } from '../shared/Badge'
import { ScopeSelector } from './ScopeSelector'
import { api, ApiRequestError } from '../../services/api'
import type {
  AgentIntegrationScope,
  CreateAgentRequest,
  IntegrationSummary,
} from '../../types/api'

// ---------------------------------------------------------------------------
// Available models (could later come from an API endpoint)
// ---------------------------------------------------------------------------

const MODEL_OPTIONS = [
  { id: 'gpt-4o', label: 'GPT-4o', provider: 'OpenAI', desc: 'Fast, capable, multimodal' },
  { id: 'gpt-4o-mini', label: 'GPT-4o Mini', provider: 'OpenAI', desc: 'Affordable everyday tasks' },
  { id: 'claude-sonnet-4-20250514', label: 'Claude Sonnet 4', provider: 'Anthropic', desc: 'Balanced intelligence' },
  { id: 'claude-haiku-3.5', label: 'Claude Haiku 3.5', provider: 'Anthropic', desc: 'Lightning fast' },
  { id: 'gemini-2.0-flash', label: 'Gemini 2.0 Flash', provider: 'Google', desc: 'Speedy and efficient' },
  { id: 'gemini-2.0-pro', label: 'Gemini 2.0 Pro', provider: 'Google', desc: 'Advanced reasoning' },
  { id: 'o3-mini', label: 'o3-mini', provider: 'OpenAI', desc: 'Reasoning specialist' },
  { id: 'deepseek-chat', label: 'DeepSeek Chat', provider: 'DeepSeek', desc: 'Open-weight powerhouse' },
]

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

const STEPS = [
  { key: 'identity', label: 'Identity', icon: Robot },
  { key: 'model', label: 'Model', icon: Brain },
  { key: 'capabilities', label: 'Capabilities', icon: Wrench },
  { key: 'review', label: 'Review', icon: CheckCircle },
] as const

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AgentWizardProps {
  open: boolean
  onClose: () => void
  onSave: (data: CreateAgentRequest) => Promise<void>
  loading?: boolean
}

interface WizardForm {
  name: string
  description: string
  system_prompt: string
  model: string
  temperature: string
  max_tokens: string
  max_iterations: string
  tools: string
  skills: string
  allowed_integrations: AgentIntegrationScope[]
}

const defaultForm: WizardForm = {
  name: '',
  description: '',
  system_prompt: '',
  model: MODEL_OPTIONS[0].id,
  temperature: '0.7',
  max_tokens: '4096',
  max_iterations: '10',
  tools: '',
  skills: '',
  allowed_integrations: [],
}

// ============================================================================
// Component
// ============================================================================

export function AgentWizard({ open, onClose, onSave, loading }: AgentWizardProps) {
  const [step, setStep] = useState(0)
  const [form, setForm] = useState<WizardForm>(defaultForm)
  const [errors, setErrors] = useState<Partial<Record<keyof WizardForm, string>>>({})

  // Integration data for ScopeSelector
  const [integrations, setIntegrations] = useState<IntegrationSummary[]>([])
  const [integrationsLoading, setIntegrationsLoading] = useState(false)
  const [integrationsError, setIntegrationsError] = useState<string | null>(null)

  // Reset when modal opens
  useEffect(() => {
    if (open) {
      setForm(defaultForm)
      setStep(0)
      setErrors({})
    }
  }, [open])

  // Fetch integrations when reaching capabilities step
  useEffect(() => {
    if (!open || step !== 2) return
    let cancelled = false
    setIntegrationsLoading(true)
    setIntegrationsError(null)

    api.integrations
      .list()
      .then((data) => {
        if (!cancelled) setIntegrations(data)
      })
      .catch((err) => {
        if (!cancelled) {
          setIntegrationsError(
            err instanceof ApiRequestError ? err.message : 'Failed to load integrations',
          )
        }
      })
      .finally(() => {
        if (!cancelled) setIntegrationsLoading(false)
      })

    return () => { cancelled = true }
  }, [open, step])

  const update = useCallback(
    (field: keyof WizardForm, value: string) => {
      setForm((prev) => ({ ...prev, [field]: value }))
      if (errors[field]) setErrors((prev) => ({ ...prev, [field]: undefined }))
    },
    [errors],
  )

  // Step validation
  const validateStep = useCallback(
    (stepIndex: number): boolean => {
      const next: Partial<Record<keyof WizardForm, string>> = {}

      if (stepIndex === 0) {
        if (!form.name.trim()) next.name = 'Name is required'
        if (form.name.trim().length > 100) next.name = 'Name must be ≤ 100 characters'
      }
      if (stepIndex === 1) {
        const temp = parseFloat(form.temperature)
        if (isNaN(temp) || temp < 0 || temp > 2) next.temperature = '0–2'
        const tokens = parseInt(form.max_tokens, 10)
        if (isNaN(tokens) || tokens < 1) next.max_tokens = 'Must be ≥ 1'
      }

      setErrors(next)
      return Object.keys(next).length === 0
    },
    [form],
  )

  const goNext = useCallback(() => {
    if (!validateStep(step)) return
    setStep((s) => Math.min(s + 1, STEPS.length - 1))
  }, [step, validateStep])

  const goBack = useCallback(() => {
    setStep((s) => Math.max(s - 1, 0))
  }, [])

  const handleSubmit = useCallback(async () => {
    const payload: CreateAgentRequest = {
      name: form.name.trim(),
      description: form.description.trim() || undefined,
      system_prompt: form.system_prompt.trim() || undefined,
      model: form.model,
      temperature: parseFloat(form.temperature) || 0.7,
      max_tokens: parseInt(form.max_tokens, 10) || 4096,
      max_iterations: parseInt(form.max_iterations, 10) || 10,
      tools: form.tools.split(',').map((s) => s.trim()).filter(Boolean),
      skills: form.skills.split(',').map((s) => s.trim()).filter(Boolean),
      allowed_integrations:
        form.allowed_integrations.length > 0 ? form.allowed_integrations : undefined,
    }
    await onSave(payload)
  }, [form, onSave])

  const selectedModel = useMemo(
    () => MODEL_OPTIONS.find((m) => m.id === form.model),
    [form.model],
  )

  const currentStep = STEPS[step]

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Create Agent"
      maxWidth="max-w-2xl"
    >
      <div className="flex flex-col gap-5">
        {/* ─── Step Indicator ─── */}
        <nav className="flex items-center gap-1 overflow-x-auto scrollbar-none" aria-label="Wizard steps">
          {STEPS.map((s, i) => {
            const Icon = s.icon
            const isActive = i === step
            const isComplete = i < step
            return (
              <div key={s.key} className="flex items-center gap-1">
                {i > 0 && (
                  <div
                    className={`w-6 h-px shrink-0 ${
                      isComplete ? 'bg-[var(--accent)]' : 'bg-[var(--border)]'
                    }`}
                  />
                )}
                <button
                  type="button"
                  onClick={() => {
                    if (i < step) setStep(i)
                  }}
                  disabled={i > step}
                  className={`
                    flex items-center gap-1.5 px-2.5 py-1.5 rounded-full text-xs font-medium
                    transition-colors whitespace-nowrap shrink-0
                    ${isActive
                      ? 'bg-[var(--accent-subtle)] text-[var(--accent-text)]'
                      : isComplete
                        ? 'text-[var(--accent-text)] hover:bg-[var(--surface-2)] cursor-pointer'
                        : 'text-[var(--text-dim)] cursor-default'
                    }
                  `}
                  aria-current={isActive ? 'step' : undefined}
                >
                  {isComplete ? (
                    <CheckCircle size={14} weight="fill" className="text-[var(--success)]" />
                  ) : (
                    <Icon size={14} weight={isActive ? 'fill' : 'regular'} />
                  )}
                  <span className="hidden sm:inline">{s.label}</span>
                </button>
              </div>
            )
          })}
        </nav>

        <div className="border-t border-[var(--border-subtle)]" />

        {/* ─── Step Content ─── */}
        <div className="min-h-[280px]">
          {currentStep.key === 'identity' && (
            <StepIdentity form={form} errors={errors} update={update} />
          )}
          {currentStep.key === 'model' && (
            <StepModel form={form} errors={errors} update={update} />
          )}
          {currentStep.key === 'capabilities' && (
            <StepCapabilities
              form={form}
              update={update}
              setForm={setForm}
              integrations={integrations}
              integrationsLoading={integrationsLoading}
              integrationsError={integrationsError}
            />
          )}
          {currentStep.key === 'review' && (
            <StepReview form={form} selectedModel={selectedModel} />
          )}
        </div>

        {/* ─── Actions ─── */}
        <div className="flex items-center justify-between pt-3 border-t border-[var(--border-subtle)]">
          <div>
            {step > 0 && (
              <Button
                variant="ghost"
                size="sm"
                icon={<ArrowLeft size={14} />}
                onClick={goBack}
                disabled={loading}
              >
                Back
              </Button>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={onClose} disabled={loading}>
              Cancel
            </Button>
            {step < STEPS.length - 1 ? (
              <Button
                size="sm"
                icon={<ArrowRight size={14} />}
                onClick={goNext}
              >
                Continue
              </Button>
            ) : (
              <Button
                size="sm"
                icon={<Sparkle size={14} weight="fill" />}
                onClick={handleSubmit}
                loading={loading}
              >
                Create Agent
              </Button>
            )}
          </div>
        </div>
      </div>
    </Modal>
  )
}

// ============================================================================
// Step 1: Identity
// ============================================================================

function StepIdentity({
  form,
  errors,
  update,
}: {
  form: WizardForm
  errors: Partial<Record<keyof WizardForm, string>>
  update: (field: keyof WizardForm, value: string) => void
}) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h3 className="text-sm font-semibold text-[var(--text)]">
          Name your agent
        </h3>
        <p className="text-xs text-[var(--text-dim)]">
          Give your agent a name and describe what it does. The system prompt
          shapes its personality and behavior.
        </p>
      </div>

      <Input
        label="Name"
        placeholder="e.g. Research Assistant"
        value={form.name}
        onChange={(e) => update('name', e.target.value)}
        error={errors.name}
        autoFocus
      />
      <div className="flex flex-col gap-1.5">
        <label className="text-[13px] font-medium text-[var(--text-secondary)]">
          Description
        </label>
        <textarea
          value={form.description}
          onChange={(e) => update('description', e.target.value)}
          placeholder="A brief summary of what this agent does…"
          rows={2}
          className="resize-none focus-ring"
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <label className="text-[13px] font-medium text-[var(--text-secondary)]">
          System Prompt
        </label>
        <textarea
          value={form.system_prompt}
          onChange={(e) => update('system_prompt', e.target.value)}
          placeholder="You are a helpful assistant that…"
          rows={4}
          className="resize-none font-mono text-xs focus-ring"
        />
        <p className="text-[11px] text-[var(--text-dim)]">
          Defines how the agent behaves, its tone, expertise, and constraints.
        </p>
      </div>
    </div>
  )
}

// ============================================================================
// Step 2: Model
// ============================================================================

function StepModel({
  form,
  errors,
  update,
}: {
  form: WizardForm
  errors: Partial<Record<keyof WizardForm, string>>
  update: (field: keyof WizardForm, value: string) => void
}) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h3 className="text-sm font-semibold text-[var(--text)]">
          Choose a model
        </h3>
        <p className="text-xs text-[var(--text-dim)]">
          Select the AI model that powers your agent. Different models offer
          different speed, cost, and capability trade-offs.
        </p>
      </div>

      {/* Model grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {MODEL_OPTIONS.map((m) => {
          const isSelected = form.model === m.id
          return (
            <button
              key={m.id}
              type="button"
              onClick={() => update('model', m.id)}
              className={`
                flex flex-col gap-0.5 p-3 rounded-[var(--radius-sm)] border text-left
                transition-all cursor-pointer
                ${isSelected
                  ? 'border-[var(--accent)] bg-[var(--accent-subtle)] shadow-[0_0_0_1px_var(--accent)]'
                  : 'border-[var(--border-subtle)] hover:border-[var(--border)] hover:bg-[var(--surface-2)]'
                }
              `}
            >
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-[var(--text)]">{m.label}</span>
                <Badge variant={isSelected ? 'accent' : 'default'}>{m.provider}</Badge>
              </div>
              <span className="text-[11px] text-[var(--text-dim)]">{m.desc}</span>
            </button>
          )
        })}
      </div>

      {/* Advanced model params */}
      <div className="border-t border-[var(--border-subtle)] pt-4">
        <p className="text-xs font-medium text-[var(--text-secondary)] mb-3">
          Advanced parameters
        </p>
        <div className="grid grid-cols-3 gap-4">
          <Input
            label="Temperature"
            type="number"
            step="0.1"
            min="0"
            max="2"
            value={form.temperature}
            onChange={(e) => update('temperature', e.target.value)}
            error={errors.temperature}
            helper="0 = precise, 2 = creative"
          />
          <Input
            label="Max Tokens"
            type="number"
            min="1"
            value={form.max_tokens}
            onChange={(e) => update('max_tokens', e.target.value)}
            error={errors.max_tokens}
            helper="Response length limit"
          />
          <Input
            label="Max Iterations"
            type="number"
            min="1"
            value={form.max_iterations}
            onChange={(e) => update('max_iterations', e.target.value)}
            error={errors.max_iterations}
            helper="Tool-use loops"
          />
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Step 3: Capabilities
// ============================================================================

function StepCapabilities({
  form,
  update,
  setForm,
  integrations,
  integrationsLoading,
  integrationsError,
}: {
  form: WizardForm
  update: (field: keyof WizardForm, value: string) => void
  setForm: React.Dispatch<React.SetStateAction<WizardForm>>
  integrations: IntegrationSummary[]
  integrationsLoading: boolean
  integrationsError: string | null
}) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h3 className="text-sm font-semibold text-[var(--text)]">
          Add capabilities
        </h3>
        <p className="text-xs text-[var(--text-dim)]">
          Equip your agent with tools, skills, and integrations. You can always
          change these later.
        </p>
      </div>

      <Input
        label="Tools"
        placeholder="web_search, code_exec, file_read"
        value={form.tools}
        onChange={(e) => update('tools', e.target.value)}
        helper="Comma-separated function names the agent can call"
      />
      <Input
        label="Skills"
        placeholder="summarizer, coder, researcher"
        value={form.skills}
        onChange={(e) => update('skills', e.target.value)}
        helper="Predefined behavior modules"
      />

      <div className="border-t border-[var(--border-subtle)] pt-3">
        <p className="text-xs font-medium text-[var(--text-secondary)] mb-3">
          Integration access
        </p>
        <ScopeSelector
          value={form.allowed_integrations}
          onChange={(scopes) =>
            setForm((prev) => ({ ...prev, allowed_integrations: scopes }))
          }
          integrations={integrations}
          loading={integrationsLoading}
          error={integrationsError}
        />
      </div>
    </div>
  )
}

// ============================================================================
// Step 4: Review
// ============================================================================

function StepReview({
  form,
  selectedModel,
}: {
  form: WizardForm
  selectedModel: (typeof MODEL_OPTIONS)[number] | undefined
}) {
  const tools = form.tools.split(',').map((s) => s.trim()).filter(Boolean)
  const skills = form.skills.split(',').map((s) => s.trim()).filter(Boolean)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h3 className="text-sm font-semibold text-[var(--text)]">
          Review your agent
        </h3>
        <p className="text-xs text-[var(--text-dim)]">
          Confirm everything looks good before creating.
        </p>
      </div>

      <div className="flex flex-col gap-3 p-4 rounded-[var(--radius-sm)] bg-[var(--surface-2)] border border-[var(--border-subtle)]">
        {/* Name & description */}
        <ReviewRow label="Name" value={form.name} />
        {form.description && <ReviewRow label="Description" value={form.description} />}
        {form.system_prompt && (
          <ReviewRow
            label="System Prompt"
            value={
              form.system_prompt.length > 120
                ? form.system_prompt.slice(0, 120) + '…'
                : form.system_prompt
            }
            mono
          />
        )}

        <div className="border-t border-[var(--border-subtle)]" />

        {/* Model */}
        <ReviewRow
          label="Model"
          value={selectedModel ? `${selectedModel.label} (${selectedModel.provider})` : form.model}
        />
        <div className="flex gap-4">
          <ReviewRow label="Temperature" value={form.temperature} />
          <ReviewRow label="Max Tokens" value={form.max_tokens} />
          <ReviewRow label="Max Iterations" value={form.max_iterations} />
        </div>

        {(tools.length > 0 || skills.length > 0 || form.allowed_integrations.length > 0) && (
          <>
            <div className="border-t border-[var(--border-subtle)]" />
            {tools.length > 0 && (
              <ReviewRow label="Tools">
                <div className="flex gap-1 overflow-x-auto scrollbar-none">
                  {tools.map((t) => (
                    <Badge key={t} variant="default">{t}</Badge>
                  ))}
                </div>
              </ReviewRow>
            )}
            {skills.length > 0 && (
              <ReviewRow label="Skills">
                <div className="flex gap-1 overflow-x-auto scrollbar-none">
                  {skills.map((s) => (
                    <Badge key={s} variant="accent">{s}</Badge>
                  ))}
                </div>
              </ReviewRow>
            )}
            {form.allowed_integrations.length > 0 && (
              <ReviewRow
                label="Integrations"
                value={`${form.allowed_integrations.length} connected`}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Review row helper
// ---------------------------------------------------------------------------

function ReviewRow({
  label,
  value,
  mono,
  children,
}: {
  label: string
  value?: string
  mono?: boolean
  children?: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] font-medium text-[var(--text-dim)] uppercase tracking-wider">
        {label}
      </span>
      {children || (
        <span
          className={`text-xs text-[var(--text)] ${mono ? 'font-mono' : ''}`}
        >
          {value}
        </span>
      )}
    </div>
  )
}
