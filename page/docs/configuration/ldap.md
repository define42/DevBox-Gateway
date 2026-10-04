# LDAP

For local development, the bundled `glauth` container is configured in
`testldap/default-config.cfg` and is reachable from the gateway container at
`ldaps://127.0.0.1:389` (a host-loopback published port). For production, point
`LDAP_URL` at your own directory and adjust `LDAP_BASE_DN`, `LDAP_USER_FILTER`,
`LDAP_USERNAME_ATTRIBUTE`, and `LDAP_USER_DOMAIN` to match.
Users must enter only their bare username (for example, `alice`). The gateway
rejects domain-qualified input and always appends `LDAP_USER_DOMAIN` before the
LDAP bind and search; an empty or malformed `LDAP_USER_DOMAIN` is therefore a
startup error.

After authentication, the gateway takes the account name from
`LDAP_USERNAME_ATTRIBUTE` on the returned directory entry, preserving the
directory's spelling. With the default `mail`, `alice@example.com` becomes
`alice`. A login entered as `ALICE` that resolves to this entry therefore uses
the same sessions, VM ownership, connection limit and VM quota as `alice`.
For an AD filter such as `(userPrincipalName=%s)`, set
`LDAP_USERNAME_ATTRIBUTE=userPrincipalName` (or `sAMAccountName` for a bare
account name). The resulting bare name must identify one account uniquely
across the search base: for example, `alice` and `alice@example.com` both
produce `alice`. Missing, ambiguous, invalid or foreign-domain values reject login.

**Upgrading existing ownership:** previous versions used the submitted login
spelling as the VM owner. Before rollout, compare existing owner metadata with
the canonical directory values. A VM whose owner differs remains visible to
administrators but will not appear for the canonical user until an operator
migrates its owner. Follow [the ownership migration procedure](https://github.com/define42/DevBox-Gateway/blob/main/docs/ldap-identity-migration.md).
Keep the chosen identity attribute stable; changing it or renaming an account
requires the same ownership review.

Prefer `ldaps://` or `LDAP_STARTTLS=true`. Certificate verification is on by
default; only set `LDAP_SKIP_TLS_VERIFY=true` as a stopgap for a directory
whose CA chain is not yet trusted (the bundled glauth container uses a
self-signed certificate, which is why the Docker Compose dev setup sets it).

To restrict login to members of specific directory groups, set
`LDAP_REQUIRED_GROUPS`. A user is allowed when their `memberOf` attribute
contains **at least one** of the listed groups; when the variable is empty,
every user found by `LDAP_USER_FILTER` may log in. Entries can be bare group
names or full group DNs:

```bash
# Bare names, ','- or ';'-delimited — matched against the group DN's first RDN
# value (e.g. the cn), case-insensitively:
LDAP_REQUIRED_GROUPS="vdi-users, admins"

# Full DNs contain commas, so they must be ';'-delimited:
LDAP_REQUIRED_GROUPS="cn=vdi-users,ou=groups,dc=example,dc=com;cn=admins,ou=groups,dc=example,dc=com"
```

When `LDAP_REQUIRED_GROUPS` is set, the login page shows an informational box
below the sign-in form listing the groups that give access (full DNs are
shortened to their first RDN value, e.g. the `cn`).

To grant administrator access, set `ADMIN_GROUP` to exactly one bare group name
or full group DN. This grants a role only: the user must still pass the normal
LDAP login checks, including `LDAP_REQUIRED_GROUPS` when configured. The role is
determined from `memberOf` at login and retained for that session, so directory
membership changes take effect after the user logs in again or the current
session expires.

Administrators get an **Admin** button on their dashboard. It opens an inventory
of every persistent VM known to the gateway, grouped by its recorded owner. VMs
without owner metadata appear under **Unowned**. Administrators can start, stop,
restart, and remove any VM in this inventory, including **Unowned** entries.
RDP, serial-console, and noVNC access to another user's VM remain owner-only.
The administrator page also has a **Base Images** button. Its modal lists the
current image library and lets administrators upload QCOW2 images named `.img`,
`.qcow2`, or `.raw` and delete existing images. Uploads are streamed, validated
using the QCOW2 magic header, never overwrite a file with the same name, and are
limited to the configured `VM_DISK_SIZE_GB` capacity. The modal also shows the
filesystem space currently available in the configured base-image directory.

Both access and administrator group checks use direct membership only — nested
group membership is not resolved, so the group must appear directly in the
user's `memberOf`. Directories where `memberOf` is an operational attribute
(e.g. OpenLDAP's `memberof` overlay) are supported; the gateway requests the
attribute explicitly.
