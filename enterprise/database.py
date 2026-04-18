import os
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# Acme Corp — Internal Credential Registry (SIMULATED)
# In production: Vault / AWS Secrets Manager / 1Password
# Warden brokers access to these. Agents never read this file.
# ============================================================

CUSTOMER_REGISTRY = [
    {
        "customer_id": "customer_acme_001",
        "company": "Acme Corp",
        "agent_assigned": "TriageBot",
        "github_token": os.getenv("GITHUB_TOKEN"),    # real — brokered via Warden
        "groq_key": os.getenv("GROQ_API_KEY"),         # real — brokered via Warden
        "repo": os.getenv("DEMO_REPO"),
        "tier": "enterprise",
        "permissions": ["issues:read", "issues:write"]
    },
    {
        "customer_id": "customer_beta_002",
        "company": "Beta Industries",
        "agent_assigned": "TriageBot",
        "github_token": "ghp_FAKE_BETA_TOKEN_NOT_REAL",
        "groq_key": "gsk_FAKE_BETA_GROQ_NOT_REAL",
        "repo": "beta-industries/product",
        "tier": "startup",
        "permissions": ["issues:read"]
    },
    {
        "customer_id": "customer_gamma_003",
        "company": "Gamma LLC",
        "agent_assigned": "TriageBot",
        "github_token": "ghp_FAKE_GAMMA_TOKEN_NOT_REAL",
        "groq_key": "gsk_FAKE_GAMMA_GROQ_NOT_REAL",
        "repo": "gamma-llc/backend",
        "tier": "startup",
        "permissions": ["issues:read"]
    },
]

INTERNAL_AGENTS = [
    {
        "agent_id": "oncall-prod-001",
        "agent_name": "IncidentBot",
        "role": "on-call incident response",
        "github_token": os.getenv("GITHUB_TOKEN"),    # real — brokered via Warden
        "groq_key": os.getenv("GROQ_API_KEY"),         # real — brokered via Warden
        "repo": os.getenv("DEMO_REPO"),
        "default_ttl_seconds": 60,                     # short-lived by design
        "permissions": ["issues:read"]                 # read only — blast radius limited
    },
]

DEVELOPER_SESSIONS = [
    {
        "session_id": "engineer_session_001",
        "engineer": "Abe Bhatti",
        "agent_name": "DevAgent",
        "github_token": os.getenv("GITHUB_TOKEN"),    # real — brokered via Warden
        "groq_key": os.getenv("GROQ_API_KEY"),         # real — brokered via Warden
        "repo": os.getenv("DEMO_REPO"),
        "permissions": ["issues:read", "issues:write"]
    },
]

def get_customer(customer_id: str):
    return next((c for c in CUSTOMER_REGISTRY if c["customer_id"] == customer_id), None)

def get_agent(agent_id: str):
    return next((a for a in INTERNAL_AGENTS if a["agent_id"] == agent_id), None)

def get_session(session_id: str):
    return next((s for s in DEVELOPER_SESSIONS if s["session_id"] == session_id), None)

if __name__ == "__main__":
    print("=== Acme Corp Credential Registry ===")
    print(f"Customers: {len(CUSTOMER_REGISTRY)}")
    for c in CUSTOMER_REGISTRY:
        token_preview = c['github_token'][:8] + "..." if c['github_token'] and not c['github_token'].startswith('ghp_FAKE') else c['github_token']
        print(f"  {c['customer_id']} | {c['company']} | token: {token_preview}")
    print(f"\nInternal agents: {len(INTERNAL_AGENTS)}")
    for a in INTERNAL_AGENTS:
        print(f"  {a['agent_id']} | {a['agent_name']} | TTL: {a['default_ttl_seconds']}s")
    print(f"\nDeveloper sessions: {len(DEVELOPER_SESSIONS)}")
    for s in DEVELOPER_SESSIONS:
        print(f"  {s['session_id']} | {s['engineer']} | {s['agent_name']}")
