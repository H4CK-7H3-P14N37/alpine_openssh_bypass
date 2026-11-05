# Reproduces the Alpine/musl OpenSSH password-auth bypass described in:
# https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
# Fixed in point releases 3.21.10 / 3.22.8 / 3.23.8 / 3.24.4, openssh-server-10.3_p1-r2
# on the v3.24/main branch (rebuilt 2026-11-05), and upstream OpenSSH 10.6p2.
#
# IMPORTANT: apk's v3.24/main branch is rolling. A plain `apk add openssh-server`
# now pulls the already-patched r2 build regardless of the Docker base image tag,
# so this Dockerfile builds the PRE-PATCH package from aports source instead,
# pinned to the last commit before today's fix landed.
#
# Isolated repro only — do not expose this container's port 22 beyond a local/private network.

# ---- Stage 1: build the vulnerable openssh-server package from pre-patch aports source ----
FROM alpine:3.24.3 AS builder

RUN apk add --no-cache alpine-sdk git sudo

RUN adduser -D builder \
    && addgroup builder abuild \
    && echo "builder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/builder

USER builder
WORKDIR /home/builder
RUN abuild-keygen -a -i -n

# Shallow clone of the branch this Alpine point release tracks
RUN git clone --branch 3.24-stable --filter=blob:none \
      https://gitlab.alpinelinux.org/alpine/aports.git \
    && cd aports/main/openssh \
    && COMMIT=$(git log --before="2026-11-05T00:00:00Z" -1 --format=%H -- APKBUILD) \
    && echo "Building openssh from pre-patch commit: $COMMIT" > /home/builder/PINNED_COMMIT.txt \
    && git checkout "$COMMIT" -- . \
    && grep -E '^(pkgver|pkgrel)=' APKBUILD

# Refresh the apk package index before abuild installs makedepends. The earlier
# `apk add --no-cache` leaves no cached APKINDEX, so without this abuild's builddeps
# step fails with "unable to select packages" for autoconf/openssl-dev/etc.
RUN sudo apk update \
    && cd aports/main/openssh && abuild -r

# Build an apk index so the next stage can install straight from the package dir.
# abuild emits everything (incl. noarch subpackages like openssh-server-common)
# under x86_64/, but apk resolves a noarch package's file from a sibling noarch/
# dir, so mirror that dir too — otherwise the install fails with
# "openssh-server-common ... package mentioned in index not found".
RUN cd ~/packages/main/x86_64 \
    && apk index -o APKINDEX.tar.gz *.apk \
    && abuild-sign APKINDEX.tar.gz \
    && cp -r ~/packages/main/x86_64 ~/packages/main/noarch

# ---- Stage 2: the actual repro image, installing the pinned pre-patch build ----
FROM alpine:3.24.3

# apk expects a repo laid out as <repo>/<arch>/APKINDEX.tar.gz, so copy the whole
# repo root (both the x86_64/ and the mirrored noarch/ dirs built in stage 1).
COPY --from=builder /home/builder/packages/main /tmp/local-repo
COPY --from=builder /home/builder/.abuild/*.rsa.pub /etc/apk/keys/

# Install the locally-built pre-patch openssh-server instead of the live repo's.
# The local repo is given a pin tag (@local) and the packages are requested as
# name@local, which forces apk to take them from that repo even though the live
# mirror offers a higher version (the patched r2). A plain --repository only ADDS
# the repo, so apk would still pick the newest (patched) build. Dependencies still
# resolve from the normal online repos.
RUN apk add --no-cache --repository "@local /tmp/local-repo" --allow-untrusted \
      openssh-server@local openssh-client@local \
    && ssh-keygen -A \
    && rm -rf /tmp/local-repo

# Condition 2: PasswordAuthentication yes (the Alpine/OpenSSH default — set explicitly for clarity).
# PermitRootLogin yes is required because the target here is root: OpenSSH's default
# prohibit-password would otherwise block root's password path (and thus the bypass).
RUN sed -i \
    -e 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' \
    -e 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' \
    /etc/ssh/sshd_config

# Condition 3: the target account's stored password field is '*' (no password set).
# Here the target is root, which the base image already ships as 'root:*'. We move that
# '*' into the passwd database and drop root's /etc/shadow entry so it becomes root:*:0:0.
#
# IMPORTANT: the '*' must be a STABLE value, i.e. live in the passwd database with NO
# /etc/shadow entry (exactly the shape of an NSS/directory account — nslcd/sssd/winbind).
# This is one of the account shapes the advisory calls out as affected.
#
# A '*' left in /etc/shadow instead does NOT reproduce here: OpenSSH's shadow_pw() returns
# a pointer into musl's single static getspnam() buffer, and pick_salt() (which borrows
# Condition 4's salt) calls getspnam() again, overwriting that buffer before the final
# strcmp(). With no shadow entry, shadow_pw() falls back to the stable pw_passwd copy, so the
# '*' survives to the comparison and the bypass fires. (The fix's strlen(pw_password) >= 4
# guard rejects the 1-char '*' regardless.)
RUN sed -i 's/^root:x:/root:*:/' /etc/passwd \
    && sed -i '/^root:/d' /etc/shadow

# Condition 4: at least one other account with a real $6$ (or $5$) crypt hash
RUN adduser -D -s /bin/sh otheruser \
    && echo 'otheruser:some-real-password' | chpasswd

# Allow SSH login for root (the target) plus the salt-provider account
RUN echo 'AllowUsers root otheruser' >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
