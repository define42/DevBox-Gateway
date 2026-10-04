# Login flow

For an installed gateway, open its configured HTTPS address and sign in with
your LDAP credentials. See [LDAP configuration](../configuration/ldap.md) for
username and group requirements. The test accounts below belong only to the
bundled Docker Compose development environment.

## Local development sign-in

After starting the [Docker Compose stack](../installation/docker-compose.md),
open `https://localhost` in a browser. If the gateway generated a self-signed
certificate (the default for local runs without `CERT_FILE` / `KEY_FILE`), the
browser will warn — choose **Advanced** → **Proceed to localhost (unsafe)**.

Sign in with the seeded test account:

- username: `johndoe`
- password: `dogood`

## Managing VMs

A successful login redirects to `/api/dashboard`, where you can:

- Create a new VM (name, base image, guest username). The guest account is
  provisioned with the password you logged in to the gateway with: only its
  salted sha512_crypt hash is kept in the in-memory session at login and
  embedded in the VM's cloud-init seed. The cleartext password is not kept in
  the session or seed. Every VM gets the operator-configured CPU and memory
  (`VM_VCPU_COUNT` / `VM_MEMORY_MIB`); users cannot pick or change them.
- Start / restart / shutdown / remove existing VMs that you own.
- Open a serial console or noVNC session in the browser.
- Download an `.rdp` file (named after the VM, e.g. `alice-desktop.rdp`)
  preconfigured for the gateway.

**Stop** asks the guest to shut down gracefully through its ACPI power button.
The request returns before shutdown completes; the VM stays running if the
guest does not respond. **Force power off** immediately cuts power after a
confirmation and can lose unsaved work or damage files. Use it when the guest
cannot shut down normally. Manual Stop does not automatically escalate; the
optional idle-shutdown policy has its own escalation timer (see
`VDI_AUTO_SHUTDOWN_HOURS`).

If **Remove** fails during storage or network cleanup, the VM remains listed
with its ownership intact. Restore the failing dependency and retry Remove.
Start and restart are refused once deletion has begun, including after a
gateway restart, because some VM resources may already have been removed.

The same `johndoe` / `dogood` credentials are exercised by the LDAP
integration tests, so they are also the recommended local smoke-test account.
To exercise the administrator inventory in the Docker Compose environment, use
the seeded `admin` / `dogood` account; it belongs to the `devbox-admins` group
configured through `ADMIN_GROUP`.
