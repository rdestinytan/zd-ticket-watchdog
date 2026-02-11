import os
import json
import time
import datetime
import urllib.parse
import base64
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple


# =========================
# Configuration
# =========================
HOURS_PENDING_THRESHOLD = float(os.getenv("HOURS_PENDING_THRESHOLD", "48"))
ALERT_COOLDOWN_HOURS = float(os.getenv("ALERT_COOLDOWN_HOURS", "24"))  # don't re-alert same ticket too frequently
STATE_FILE = os.getenv("STATE_FILE", "watchdog_state.json")

ZENDESK_SUBDOMAIN = os.getenv("ZENDESK_SUBDOMAIN", "").strip()
ZENDESK_EMAIL = os.getenv("ZENDESK_EMAIL", "").strip()
ZENDESK_API_TOKEN = os.getenv("ZENDESK_API_TOKEN", "").strip()

SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "").strip()
SLACK_CHANNEL_ID = os.getenv("SLACK_CHANNEL_ID", "").strip()

# If you want to monitor another assignee (service account) instead of "me", set this
# Otherwise it will resolve "me" from the Zendesk credentials provided.
ZENDESK_ASSIGNEE_ID_OVERRIDE = os.getenv("ZENDESK_ASSIGNEE_ID_OVERRIDE", "").strip()

# Optional filters
INCLUDE_TAGS = [t.strip() for t in os.getenv("INCLUDE_TAGS", "").split(",") if t.strip()]
EXCLUDE_TAGS = [t.strip() for t in os.getenv("EXCLUDE_TAGS", "").split(",") if t.strip()]


# =========================
# Small HTTP helper
# =========================
def http_request_json(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[Dict[str, Any]] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers = {**headers, "Content-Type": "application/json; charset=utf-8"}

    req = urllib.request.Request(url=url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return {}
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8")
        except Exception:
            pass
        raise RuntimeError(f"HTTP {e.code} error for {url}: {err_body}") from e


def iso_to_dt(s: str) -> datetime.datetime:
    # Zendesk timestamps look like: 2026-02-04T20:30:25Z
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def dt_to_iso(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# =========================
# Zendesk client
# =========================
class ZendeskClient:
    def __init__(self, subdomain: str, email: str, api_token: str):
        if not subdomain or not email or not api_token:
            raise ValueError("Missing Zendesk credentials. Set ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, ZENDESK_API_TOKEN.")

        self.base = f"https://{subdomain}.zendesk.com"
        # Basic auth: email/token : api_token
        auth_str = f"{email}/token:{api_token}".encode("utf-8")
        b64 = base64.b64encode(auth_str).decode("utf-8")
        self.headers = {
            "Authorization": f"Basic {b64}",
            "Accept": "application/json",
            "User-Agent": "zendesk-ticket-watchdog/1.0",
        }

    def get_me(self) -> Dict[str, Any]:
        url = f"{self.base}/api/v2/users/me.json"
        return http_request_json("GET", url, self.headers)

    def search_tickets(self, query: str, per_page: int = 100) -> List[Dict[str, Any]]:
        # Handles pagination
        results: List[Dict[str, Any]] = []
        url = f"{self.base}/api/v2/search.json?query={urllib.parse.quote(query)}&per_page={per_page}"

        while url:
            payload = http_request_json("GET", url, self.headers)
            items = payload.get("results", [])
            results.extend(items)

            next_page = payload.get("next_page")
            url = next_page if next_page else None

            # gentle throttle
            time.sleep(0.2)

        return results

    def list_audits(self, ticket_id: int, per_page: int = 100) -> List[Dict[str, Any]]:
        audits: List[Dict[str, Any]] = []
        url = f"{self.base}/api/v2/tickets/{ticket_id}/audits.json?per_page={per_page}"

        while url:
            payload = http_request_json("GET", url, self.headers)
            audits.extend(payload.get("audits", []))
            url = payload.get("next_page")
            time.sleep(0.2)

        return audits

    def ticket_link(self, ticket_id: int) -> str:
        return f"{self.base}/agent/tickets/{ticket_id}"


# =========================
# Slack client
# =========================
class SlackClient:
    def __init__(self, bot_token: str):
        if not bot_token:
            raise ValueError("Missing Slack token. Set SLACK_BOT_TOKEN.")
        self.headers = {
            "Authorization": f"Bearer {bot_token}",
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "zendesk-ticket-watchdog/1.0",
        }

    def post_message(self, channel: str, text: str) -> None:
        url = "https://slack.com/api/chat.postMessage"
        payload = {"channel": channel, "text": text, "unfurl_links": False, "unfurl_media": False}
        resp = http_request_json("POST", url, self.headers, payload)

        if not resp.get("ok"):
            raise RuntimeError(f"Slack API error: {resp}")


# =========================
# State store (dedupe)
# =========================
def load_state(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"alerts": {}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_state(path: str, state: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def should_alert(state: Dict[str, Any], ticket_id: int, condition_key: str, cooldown_hours: float) -> bool:
    alerts = state.setdefault("alerts", {})
    key = f"{ticket_id}:{condition_key}"
    last_iso = alerts.get(key)
    if not last_iso:
        return True
    last_dt = iso_to_dt(last_iso)
    return (now_utc() - last_dt).total_seconds() >= cooldown_hours * 3600


def mark_alerted(state: Dict[str, Any], ticket_id: int, condition_key: str) -> None:
    alerts = state.setdefault("alerts", {})
    key = f"{ticket_id}:{condition_key}"
    alerts[key] = dt_to_iso(now_utc())


# =========================
# Core logic
# =========================
def find_pending_since(audits: List[Dict[str, Any]]) -> Optional[datetime.datetime]:
    """
    Find the most recent time the ticket status changed to 'pending' using audits.
    We look for audit events where field_name == 'status' and value == 'pending'.
    """
    pending_times: List[datetime.datetime] = []

    for audit in audits:
        created_at = audit.get("created_at")
        if not created_at:
            continue
        audit_dt = iso_to_dt(created_at)

        events = audit.get("events", [])
        for ev in events:
            if ev.get("field_name") == "status" and ev.get("value") == "pending":
                pending_times.append(audit_dt)

    if not pending_times:
        return None
    pending_times.sort()
    return pending_times[-1]


def tags_match(ticket: Dict[str, Any]) -> bool:
    tags = set(ticket.get("tags", []) or [])
    if INCLUDE_TAGS:
        if not any(t in tags for t in INCLUDE_TAGS):
            return False
    if EXCLUDE_TAGS:
        if any(t in tags for t in EXCLUDE_TAGS):
            return False
    return True


def format_slack_alert(ticket: Dict[str, Any], ticket_url: str, pending_since: datetime.datetime, pending_hours: float) -> str:
    ticket_id = ticket.get("id")
    subject = ticket.get("subject") or "(no subject)"
    priority = ticket.get("priority") or "none"

    pending_since_str = pending_since.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    text = (
        f":warning: Zendesk ticket needs an update (Pending > {int(HOURS_PENDING_THRESHOLD)}h)\n"
        f"- Ticket: #{ticket_id} — {subject}\n"
        f"- Priority: {priority}\n"
        f"- Pending since: {pending_since_str} (~{pending_hours:.1f}h)\n"
        f"- Link: {ticket_url}\n"
    )
    return text


def main() -> None:
    # Validate env
    if not SLACK_CHANNEL_ID:
        raise ValueError("Missing SLACK_CHANNEL_ID. Provide the private channel ID (e.g., C0123... or G0123...).")

    zd = ZendeskClient(ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, ZENDESK_API_TOKEN)
    slack = SlackClient(SLACK_BOT_TOKEN)
    state = load_state(STATE_FILE)

    # Determine assignee id
    if ZENDESK_ASSIGNEE_ID_OVERRIDE:
        assignee_id = ZENDESK_ASSIGNEE_ID_OVERRIDE
    else:
        me = zd.get_me()
        assignee_id = str(me["user"]["id"])

    # Search tickets assigned to me in pending
    # Note: Zendesk search syntax: assignee:<id> status:pending type:ticket
    query = f"type:ticket assignee:{assignee_id} status:pending"

    tickets = zd.search_tickets(query=query)
    stale_count = 0
    alerted_count = 0

    for t in tickets:
        if not tags_match(t):
            continue

        ticket_id = int(t["id"])
        audits = zd.list_audits(ticket_id)

        pending_since = find_pending_since(audits)
        if not pending_since:
            # Can't compute accurately; skip or fallback if you prefer
            continue

        pending_hours = (now_utc() - pending_since).total_seconds() / 3600.0
        if pending_hours < HOURS_PENDING_THRESHOLD:
            continue

        stale_count += 1
        condition_key = "pending48"

        if not should_alert(state, ticket_id, condition_key, ALERT_COOLDOWN_HOURS):
            continue

        ticket_url = zd.ticket_link(ticket_id)
        msg = format_slack_alert(t, ticket_url, pending_since, pending_hours)
        slack.post_message(SLACK_CHANNEL_ID, msg)
        mark_alerted(state, ticket_id, condition_key)
        alerted_count += 1

        # slight throttle to be polite to Slack API
        time.sleep(0.2)

    save_state(STATE_FILE, state)

    print(f"Checked {len(tickets)} pending tickets. Stale={stale_count}. Alerts_sent={alerted_count}.")


if __name__ == "__main__":
    main()
