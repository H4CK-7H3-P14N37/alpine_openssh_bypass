# Alpine / musl OpenSSH password-authentication bypass

This repository reproduces, in a throwaway Docker container, the OpenSSH
password-authentication bypass that affects Alpine Linux (musl libc) when
`sshd` is built **without PAM**. It is based on the Alpine advisory:

<https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/>

> ⚠️ **Isolated only.** The container runs a deliberately vulnerable
> `sshd`. Do not expose its port 22 beyond a local/private network, and delete
> it when you are done.

---

## TL;DR

On a vulnerable Alpine build, an attacker who knows the name of a **passwordless
account** (one whose stored password field is `*`) can log in as that account by
sending **any password longer than 256 bytes** — no key, no real password, one
connection, every time.

This repo targets **`root`**:

```bash
./build.sh      # build the pre-patch package and start the container on :2222
./exploit.sh    # log in as root with a 300-byte throwaway password
```

`exploit.sh` succeeds and drops you into a shell as `uid=0(root)`.

---

## Why it works

When `sshd` is built without PAM, it verifies a password by hashing the
submitted value with `crypt()` and comparing the result to the account's stored
password field. Three things combine on musl:

1. **The stored field is `*`.** Accounts with no password set store `*` (or `!`)
   in the password field — normal for key-only accounts, directory/NSS users
   (nslcd / sssd / winbind), and the base image's own `root:*`.

2. **`sshd` borrows another account's salt.** A field like `*` is too short to
   contain a salt, so OpenSSH's `pick_salt()` scans the user database and borrows
   the salt from another account that *does* have a real hash (a `$5$` or `$6$`
   entry). **This is why the repro also creates `otheruser` with a real `$6$`
   hash** — without at least one such account there is no salt to borrow.

3. **musl's `crypt()` fails "open" on long keys.** musl returns the single
   character string `"*"` as an *error indicator* when the key (password) is over
   256 bytes long. That is byte-for-byte what the stored field already contains,
   so `crypt(password, salt) == stored_field` holds and authentication succeeds.

```
stored field:              "*"
crypt(300-byte password):  "*"   ← musl error token for key > 256 bytes
strcmp(...) == 0           → login accepted
```

### A subtlety this PoC had to get right

The `*` must be a **stable** value — it must live in the **passwd database with
no `/etc/shadow` entry** (the shape of an NSS/directory account). If the `*` is
left in `/etc/shadow`, musl's `getspnam()` hands OpenSSH a pointer into a single
static buffer, and `pick_salt()` calls `getspnam()` again while borrowing the
salt — overwriting that buffer *before* the final comparison, so the stored `*`
is gone by the time `crypt()`'s `*` is compared against it. With no shadow entry,
`shadow_pw()` falls back to a stable copy of the passwd field and the `*`
survives to the comparison.

That is why the Dockerfile sets up `root` as `root:*:0:0` in `/etc/passwd` **and
deletes root's `/etc/shadow` line**.

---

## Conditions the repro sets up

| # | Condition | How the Dockerfile sets it |
|---|-----------|----------------------------|
| 1 | Vulnerable, **non-PAM** `openssh-server` | builds the pre-patch `10.3_p1-r1` from aports source (see below) |
| 2 | `PasswordAuthentication yes` | set in `sshd_config` |
| 2b| `PermitRootLogin yes` | required because the target is `root` (default `prohibit-password` would block it) |
| 3 | Target account with a **stable** `*` field | `root:*:0:0` in `/etc/passwd`, root removed from `/etc/shadow` |
| 4 | Another account with a real `$5$`/`$6$` hash | `otheruser`, hashed with `chpasswd` |

## Why it builds the package from source

Alpine's `v3.24` branch is rolling, so a plain `apk add openssh-server` now pulls
the already-**patched** `10.3_p1-r2` regardless of the base image tag. The
Dockerfile therefore builds the **pre-patch** package from aports source, pinned
to the last commit before the fix landed, and installs it from a local repo with
an `@local` pin tag (so apk takes it instead of the newer patched build on the
mirror).

---

## Usage

```bash
./build.sh              # docker build + run, publishes container :22 on host :2222
./exploit.sh            # ssh in as root with a 300-byte password

# tear down
docker rm -f alpine-openssh-bypass
```

Requirements on the host: `docker`, `sshpass`, `python3`.

To confirm the fix closes it, build with the patched package instead
(`apk add openssh-server` without the `@local` pin, giving `10.3_p1-r2`): the
same `exploit.sh` is then denied, because the fix adds a
`strlen(stored_field) >= 4` guard that rejects the 1-character `*`.

---

## Fixed Alpine package versions

The fix shipped in these Alpine **point releases**:

> **3.21.10, 3.22.8, 3.23.8, 3.24.4**

and in the following `openssh` package versions per branch (per the advisory):

| Alpine branch | Fixed `openssh` version |
|---------------|-------------------------|
| edge          | `10.6_p2-r0` |
| 3.24          | `10.3_p1-r2` |
| 3.23          | `10.2_p1-r1` |
| 3.22          | `10.0_p1-r11` |
| 3.21          | `9.9_p2-r1` |
| 3.20          | `9.7_p1-r6` |
| 3.19          | `9.6_p1-r3` |
| 3.18          | `9.3_p2-r4` |
| 3.17          | `9.1_p1-r7` |
| 3.16          | `9.0_p1-r6` |

Upstream, **OpenSSH 10.6p2** avoids the problem in `sshd`; the Alpine
stable-branch packages above carry a backported patch for the same issue.
No CVE identifier had been assigned at the time the advisory was written.

### Affected

Every Alpine release checked, **3.21 through 3.24 and edge**, plus the older
releases that no longer receive regular updates (**3.16 to 3.20**).

### Fix / mitigation

```bash
apk upgrade -U -a         # upgrade to a fixed package
rc-service sshd restart   # upgrading the package does NOT restart a running sshd
```

If you cannot upgrade immediately, set `PasswordAuthentication no` in your
`sshd_config` and restart `sshd`. Running `openssh-server-pam` with `UsePAM yes`
is also not affected.
