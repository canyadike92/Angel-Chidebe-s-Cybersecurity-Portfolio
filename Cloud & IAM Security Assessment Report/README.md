# Cloud & IAM Security Assessment

For this project I set up an intentionally vulnerable AWS environment and went hunting for two of the most common cloud misconfigurations: over-permissioned IAM roles and publicly exposed S3 buckets. I found both, exploited them the way an attacker would, then walked through fixing each one properly.

**Environment:** AWS, using CloudGoat's `iam_privesc_by_rollback` scenario for the IAM piece, plus a manually configured S3 bucket for the storage piece
**Tools:** AWS CLI, CloudGoat, Terraform

---

## Finding 1: IAM Privilege Escalation via Policy Version Rollback

**What I found**
CloudGoat spun up a limited IAM user named `raynor`, attached to a policy called `cg-raynor-policy`. On the surface, Raynor's active permissions looked reasonable, just `iam:Get*`, `iam:List*`, and `iam:SetDefaultPolicyVersion`. But that policy had five stored versions sitting in its history (v1 through v5), and one of them, v3, granted full administrator access with `"Action": "*"` on `"Resource": "*"`. Since Raynor had permission to change which version was active, Raynor could simply flip the switch back to v3 and instantly become an admin.

*Evidence: [02-raynor-caller-identity.png](screenshots/02-raynor-caller-identity.png) shows me authenticated as the limited user, [04-attached-policy-list.png](screenshots/04-attached-policy-list.png) shows the policy I found attached, [05-policy-versions-list.png](screenshots/05-policy-versions-list.png) shows all five versions with v1 as the active default, and [06-policy-version-inspect.png](screenshots/06-policy-version-inspect.png) shows v3's contents, full admin access.*

**Why this matters**
This one's sneaky because `iam:SetDefaultPolicyVersion` doesn't look dangerous at a glance. It doesn't touch S3, EC2, or anything with obvious "blast radius." What it actually does is let you decide which version of a policy is enforced, which means old, more permissive versions never really go away unless someone deletes them outright. I proved this wasn't just theoretical: as Raynor, I tried `ec2:DescribeInstances` and got denied, rolled back the policy to v3, tried it again and it worked. Then I went further and created a brand-new IAM user (and deleted it right after) just to confirm I had genuine admin control, not just a lucky permission.

*Evidence: [03-access-denied-before.png](screenshots/03-access-denied-before.png) is the denial before escalation, [07-set-default-policy-version.png](screenshots/07-set-default-policy-version.png) is the rollback command running clean, and [08-access-granted-after.png](screenshots/08-access-granted-after.png) plus [08b-access-granted-after-iam-create.png](screenshots/08b-access-granted-after-iam-create.png) show access confirmed after the fact.*

**How I'd fix it**
- Strip `iam:SetDefaultPolicyVersion` out of every policy except the ones meant for actual administrators.
- Don't let old policy versions linger, delete them once they're no longer needed (`aws iam delete-policy-version`).
- Turn on IAM Access Analyzer so permissions like this get flagged before they become a problem.
- Set up CloudTrail alerting on `SetDefaultPolicyVersion` calls, since a rollback attempt should never go unnoticed.
- Build policies with least privilege from day one, so there's never a version in the history that's more permissive than what's currently intended.

---

## Finding 2: Publicly Accessible S3 Bucket

**What I found**
I created an S3 bucket, turned off "Block all public access," and attached a bucket policy granting `s3:GetObject` to `Principal: "*"`, meaning literally anyone on the internet. I uploaded a test file and confirmed it loaded straight up in a browser with zero authentication.

*Evidence: [10-bucket-block-public-access-disabled.png](screenshots/10-bucket-block-public-access-disabled.png) shows public access unblocked, [11-bucket-policy-public.png](screenshots/11-bucket-policy-public.png) shows the public policy I applied, and [12-bucket-object-public-url-accessible.png](screenshots/12-bucket-object-public-url-accessible.png) shows the file loading with no login required.*

**Why this matters**
This is one of the most common real-world causes of data leaks, and it usually doesn't start out malicious. Someone disables Block Public Access "just for a minute" to test something, or writes a policy a little too loosely, and it never gets locked back down. Once that door is open, anything dropped into the bucket later is exposed by default, not because anyone meant for it to be.

**How I'd fix it**
- Re-enable all four Block Public Access settings on the bucket.
- Pull the public policy and replace it with one scoped to specific IAM users or roles, never `"*"`.
- Turn on the account-level Block Public Access setting so this mistake can't happen again, even accidentally, on any future bucket.
- If public access to certain files really is needed (like static site assets), use CloudFront with Origin Access Control instead of exposing the bucket directly.

*Evidence: [13-bucket-remediated-block-public-access-enabled.png](screenshots/13-bucket-remediated-block-public-access-enabled.png) shows Block Public Access back on, and [14-bucket-object-url-blocked-after-fix.png](screenshots/14-bucket-object-url-blocked-after-fix.png) shows the same URL now returning Access Denied.*

---

## Summary

| Finding | Root Cause | Fix |
|---|---|---|
| IAM privilege escalation | An overly broad permission (`iam:SetDefaultPolicyVersion`) combined with an old, more permissive policy version left in history | Remove the permission from non-admin roles, delete stale policy versions, add monitoring |
| Public S3 bucket | Block Public Access disabled plus a wide-open bucket policy | Re-enable Block Public Access, remove the public policy, enforce it account-wide |

Both findings were reproduced end to end in an isolated AWS account, exploited to confirm real impact, then remediated and verified. Everything was torn down afterward so nothing was left running.

*Deployment and teardown evidence: [01-cloudgoat-create-output.png](screenshots/01-cloudgoat-create-output.png) shows the scenario standing up, and [09-cloudgoat-destroy-output.png](screenshots/09-cloudgoat-destroy-output.png) shows it torn down cleanly with no errors.*
