from flask import Flask, jsonify, request
import re

app = Flask(__name__)


@app.post("/release-gate")
def release_gate():
    data = request.get_json(silent=True) or {}

    violations = []

    workflow = data.get("workflow", {})
    trigger = workflow.get("trigger", {})
    image = data.get("image", {})

    target = data.get("target")
    event = data.get("event")
    ref = data.get("ref")

    # 1. Permissions
    permissions = workflow.get("permissions", {})

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Event safety
    if event == "pull_request":
        if (
            trigger.get("pull_request") is not True
            or trigger.get("pull_request_target") is not False
        ):
            violations.append("PR_TARGET_UNSAFE")

    elif event == "push":
        if (
            trigger.get("push") is not True
            or trigger.get("pull_request_target") is not False
        ):
            violations.append("PUSH_EVENT_INVALID")

    # 3. Tests
    if not (
        workflow.get("testsPassed") is True
        and workflow.get("testsRequired") is True
        and workflow.get("testsMatrixComplete") is True
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    sha_pattern = re.compile(r"^[0-9a-f]{40}$")

    for action in workflow.get("actions", []):
        owner = action.get("owner")
        action_ref = action.get("ref")

        if owner == "actions":
            continue

        if (
            not isinstance(action_ref, str)
            or not sha_pattern.fullmatch(action_ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Docker image
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") != "none":
        violations.append("SECRET_IN_LAYER")

    if image.get("buildkit") is not True:
        violations.append("LEGACY_BUILDER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 6. Production requirements
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("PROD_BRANCH_INVALID")

        if workflow.get("environmentApproval") is not True:
            violations.append("ENV_APPROVAL_MISSING")

    decision = "promote" if not violations else "block"

    return jsonify({
        "decision": decision,
        "violations": violations,
    })


@app.get("/")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)