# R11 Node Terminal access and diagnostics

Open **COMMAND CENTER → Node Terminal**, select the intended online node, enter the password used to sign in to NLI as the currently signed-in administrator, add a reason, and connect. This is the same password for controller and client terminals. It is not an SSH key, Linux/root password, Supabase key or a password for the locked `nli-terminal` account. Two browser tabs can hold independent controller/client sessions.

Before connecting for the first time, review the pending host request: notification bell → **Review Node Terminal** → **Approve enable** for the exact node. Host enable by itself does not authorize a Webapp shell. For a Webapp disable, select **Request disable**, review the pending state, then **Approve disable**. Approval closes active terminal sessions on that host; it does not stop NLI parsing/controller/client-control services. A local root administrator can still disable the host broker immediately. Ordinary broker restarts retain an approved opt-in epoch, while a fresh host disable/re-enable requires another approval. Refresh the node list if another administrator changed its request revision.

Controller approval state is stored in `<controller StateDir>/terminal-access.json` (mode 0600). Do not edit it manually or replace it with an older file to bypass a disable decision. It is not a parser asset or a per-node password database. If it cannot be verified, terminal access fails closed and the existing file is preserved. Parser/template restores do not silently enable terminal access.

The controller keeps salted password hashes in `<controller StateDir>/users.json` (default `/var/lib/nli-controller/users.json`). Clients do not receive these passwords. A hash cannot reveal the original password. Do not publish this file: it also contains account/authentication secrets. NLI has no shipped universal terminal password, and support does not need your password.

The password field clears after every attempt. Re-enter it before reconnecting. HTTP 403 means step-up authentication was rejected. A session that was authenticated but then exited is a separate host/runtime failure. If several attempts were made, wait one minute before retrying.

On the affected host, an authorized administrator can run:

```sh
sudo /usr/bin/nli-node-terminal --check-runtime
sudo journalctl -u nli-node-terminal.service -n 60 --no-pager
sudo journalctl -b --no-pager -g 'nli-terminal-session|step STDIN' -n 60
getenforce
```

The runtime check creates and closes only its own short synthetic session; it does not close existing sessions or read user logs. A “no data available” journal filter result does not confirm that a terminal worked. Newly created sessions use `.scope` units; R10 used `.service` units. Keep host enforcement enabled.

Enable explicitly on each selected host:

```sh
sudo /usr/sbin/nli-node-terminal-setup --enable --role controller
# On a client:
sudo /usr/sbin/nli-node-terminal-setup --enable --role client
```

If the NLI administrator password is forgotten, a local root administrator may reset it while the controller is stopped. This changes the admin login password and briefly interrupts controller access. It does not recover the old password. From a root shell, use a private prompt rather than a password in command arguments:

```sh
systemctl stop nli-controller-agent.service
read -r -s -p 'New NLI admin password (at least 12 characters): ' taskNliNewPassword
printf '\n'
printf '%s\n' "$taskNliNewPassword" | /usr/bin/nli-controller-agent --config /etc/nli/controller.json --reset-admin-password-stdin
unset taskNliNewPassword
systemctl start nli-controller-agent.service
```

Check the reset command result, then sign out and sign back in with the new password. Use the actual controller configuration path if customized. Never delete the account store, parser state or Supabase data as a password-reset method.

TLS `unknown certificate` means a peer did not trust the certificate presented on that connection. Use the configured trusted Webapp URL and the intended private CA/trust setup; do not bypass certificate verification. A short connection refusal during a deliberate controller restart is retried by client control. Persistent failures need the actual trust/service diagnostics; do not assume parser data was lost.

A single transient local broker status/read timeout or an existing-session resize timeout no longer immediately destroys a healthy client session. The client retries only these idempotent probes for an already-owned shell within the existing ten-second transport grace, without opening a new shell, renewing unverified leases or replaying stdin. Explicit host disable and controller capability revocation still close sessions immediately; persistent failure still closes within the existing grace. An ambiguous open or stdin error still closes immediately without replay. Qualification pauses the fixture broker for three seconds and verifies the same shell survives after recovery.

An unavailable heartbeat probe without a verified broker generation blocks new terminal connections but does not fabricate a restart or renew existing session leases. Verified host disable or a changed generation still closes the old terminal immediately. Browser, node-transport and host leases continue expiring independently.
