# Google AI Setup for Agent Dispatch

The `agent-dispatch.yml` workflow uses [Goose](https://block.github.io/goose/) with
a Google AI API key to run Gemini models for automated issue implementation.

## Step 1: Get a Google AI API Key

1. Go to [Google AI Studio](https://aistudio.google.com/apikey)
2. Create an API key (or use an existing one)

## Step 2: Configure GitHub Repository

### Secret (Settings > Secrets and variables > Actions > Secrets)

| Secret | Value |
|--------|-------|
| `GOOGLE_API_KEY` | Your Google AI API key |

### Variable (Settings > Secrets and variables > Actions > Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOSE_MODEL` | `gemini-3.1-pro-preview` | Model for Goose agent |

### Labels (Settings > Labels)

Create these labels for the agent dispatch workflow:

| Label | Color | Purpose |
|-------|-------|---------|
| `agent:implement` | `#0075ca` | Trigger: implement a feature |
| `agent:fix` | `#d73a4a` | Trigger: fix a bug |
| `agent:test` | `#a2eeef` | Trigger: write tests |
| `agent:in-progress` | `#fbca04` | State: agent is working |
| `agent:pr-created` | `#0e8a16` | State: draft PR exists |
| `agent:failed` | `#b60205` | State: agent failed |
| `agent:needs-review` | `#e4e669` | State: PR created but reviewer did not pass |
