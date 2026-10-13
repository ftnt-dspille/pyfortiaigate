"""Who am I, what can I see, and does my key work? Runs as-is: no FIXMEs."""

from lab import KEY, WS, connect

with connect() as faig:
    me = faig.me()
    print(f"Logged in as {me['email']} (org role: {me['role']})")

    for ws in faig.my_workspaces():
        print(f"  member of {ws['workspaceName']} as {ws.get('membershipRole')}")

    print(f"\nIn {WS}:")
    for d in faig.detectors(WS):
        print(f"  detector   {d['name']:<36} {d.get('approvalStatus')}")
    for g in faig.guardrails(WS):
        print(f"  guardrail  {g['name']:<36} {len(g.get('detectorIds') or [])} detector(s)")
    for p in faig.policies(WS):
        print(f"  policy     {p['name']:<36} {p.get('status')}")

    check = faig.check_key(KEY)
    print(f"\nKey valid: {check['valid']} (HTTP {check['http_status']})")
    print("Models it may call:", ", ".join(faig.available_models(KEY)))
