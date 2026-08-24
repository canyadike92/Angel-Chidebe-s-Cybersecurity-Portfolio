# Cloud & IAM Security Assessment Report

**Environment:** AWS (CloudGoat `iam_privesc_by_rollback` scenario + manually configured S3 bucket)
**Tools:** AWS CLI, CloudGoat, Terraform

---

## Finding 1: IAM Privilege Escalation via Policy Version Rollback

**What's wrong**
The IAM user `raynor` was attached to a customer-managed policy (`cg-raynor-policy`) that granted `iam:SetDefaultPolicyVersion`, alongside `iam:Get*` and `iam:List*`. The policy had five stored versions (v1–v5). While the active default version (v1) was limited, version v3 granted full administrator access (`"Action": "*"`, `"Resource": "*"`, `"Effect": "Allow"`). Because Raynor could set which version was active, Raynor could self-promote v3 to become the default policy.

*Evidence: `screenshots/02-raynor-caller-identity.png` (authenticated as the limited user), `screenshots/04-attached-policy-list.png` (policy discovered), `screenshots/05-policy-versions-list.png` (v1–v5 listed, v1 default), `screenshots/06-policy-version-inspect.png` (v3 showing full admin access)*

**Why it's dangerous**
`iam:SetDefaultPolicyVersion` is rarely flagged by standard permission reviews, since it doesn't grant access to a resource directly — it grants control over *which version of a policy is enforced*. Any account with this permission can silently reactivate an old, more permissive policy version, even if that version was never deleted, effectively bypassing intentional permission tightening. This was confirmed in testing: as Raynor, `ec2:DescribeInstances` was denied before the rollback and succeeded after; a full IAM user was also created and deleted as Raynor post-rollback, confirming administrator-level access was obtained.

*Evidence: `screenshots/03-access-denied-before.png` (denied before escalation), `screenshots/07-set-default-policy-version.png` (rollback command executed), `screenshots/08-access-granted-after.png` and `screenshots/08b-access-granted-after-iam-create.png` (access confirmed after escalation)*

**Exactly how I fixed it**
- Remove `iam:SetDefaultPolicyVersion` from all non-administrative IAM policies. Only trusted admin roles should hold it.
- Delete unused or outdated policy versions instead of leaving them in version history (`aws iam delete-policy-version`).
- Enable IAM Access Analyzer to flag policies granting unused or excessive permissions.
- Add CloudTrail-based alerting (e.g., via EventBridge) on `SetDefaultPolicyVersion` calls so any rollback attempt is immediately visible.
- Apply least-privilege policy design from the start, so no version in a policy's history ever grants broader access than currently intended.

---

## Finding 2: Publicly Accessible S3 Bucket

**What's wrong**
An S3 bucket was created with "Block all public access" disabled and a bucket policy granting `s3:GetObject` to `Principal: "*"` (i.e., anyone on the internet). A test object uploaded to the bucket was confirmed to load directly in a browser with no AWS authentication required.

*Evidence: `screenshots/10-bucket-block-public-access-disabled.png` (public access unblocked), `screenshots/11-bucket-policy-public.png` (public policy applied), `screenshots/12-bucket-object-public-url-accessible.png` (object loading with no login)*

**Why it's dangerous**
A public bucket policy combined with disabled Block Public Access settings means any object placed in the bucket, including ones added later without a second thought, becomes world-readable. This is a common real-world cause of data exposure incidents, since it often results from a temporary or convenience-driven configuration that's never reverted.

**Exactly how I fixed it**
- Re-enable all four "Block Public Access" settings at the bucket level.
- Remove the public bucket policy; scope any bucket policy to specific, named principals (IAM users/roles) rather than `"*"`.
- Enable the account-level S3 Block Public Access setting so no future bucket can be made public by mistake, even by an authorized user.
- If public access to specific files is genuinely required (e.g., static website assets), use CloudFront with Origin Access Control instead of a public bucket policy, so the bucket itself stays private.

*Evidence: `screenshots/13-bucket-remediated-block-public-access-enabled.png` (Block Public Access re-enabled), `screenshots/14-bucket-object-url-blocked-after-fix.png` (same URL now returning Access Denied)*

---

## Summary

| Finding | Root Cause | Fix |
|---|---|---|
| IAM privilege escalation | Overly broad permission (`iam:SetDefaultPolicyVersion`) plus a retained permissive policy version | Remove the permission from non-admin roles; delete old policy versions; add monitoring |
| Public S3 bucket | Block Public Access disabled + public bucket policy | Re-enable Block Public Access; remove public policy; enforce account-level block |

Both issues were reproduced, exploited, and remediated in an isolated AWS account using CloudGoat (IAM scenario) and a manually configured S3 bucket, with all resources destroyed after testing.

*Deployment and teardown evidence: `screenshots/01-cloudgoat-create-output.png` (scenario deployed), `screenshots/09-cloudgoat-destroy-output.png` (scenario destroyed, no errors)*
