# Migrating existing VM owners to directory identities

The gateway now uses `LDAP_USERNAME_ATTRIBUTE` from the authenticated directory
entry as the account name. It defaults to `mail`, with the configured domain
suffix removed. Earlier versions stored the spelling submitted on the login
form. For example, existing VMs owned by `ALICE` need migration if that
directory entry supplies `alice@example.com`.

Ownership comparisons remain exact. Do not merge names solely because they
differ in capitalization: a directory may contain separate accounts with those
names. Verify the directory entry and the intended VM owner first.

## Procedure

1. Select a unique, stable directory attribute and check its returned value for
   each affected account. Names must remain unique after removing the configured
   domain suffix: `alice` and `alice@example.com` both produce `alice`. Set
   `LDAP_USERNAME_ATTRIBUTE` to that attribute.
2. Stop the gateway during the migration. This prevents concurrent lifecycle
   operations and clears the old in-memory sessions and inventory on restart.
   Guest VMs do not need to be renamed or have their disks moved.
3. List the persistent domains, back up each affected definition, and read its
   existing owner. These examples assume `qemu:///system`; use the same libvirt
   URI as the gateway.

   ```bash
   sudo virsh -c qemu:///system list --all --persistent --name
   sudo virsh -c qemu:///system dumpxml ALICE.desktop --inactive > ALICE.desktop.xml
   sudo virsh -c qemu:///system metadata ALICE.desktop \
     urn:devboxgateway:domain:owner --config
   ```

4. After confirming that `ALICE` and the canonical `alice` refer to the same
   directory account, update only its persistent owner metadata:

   ```bash
   sudo virsh -c qemu:///system metadata ALICE.desktop \
     urn:devboxgateway:domain:owner --config --key devboxgateway \
     --set '<owner>alice</owner>'
   ```

   Repeat for every VM belonging to that account, including names created with
   other capitalization. Preserve the domain name, guest username and all other
   metadata. The gateway authorizes ownership from this metadata; the old name
   prefix may remain visible and does not grant access by itself.

5. Read the metadata again, start the upgraded gateway, and log in. Check that
   all migrated VMs appear and that logins with alternative spellings accepted
   by the directory show the same inventory. All VMs now attributed to the
   canonical account count toward its quota; an account already above its limit
   must remove VMs before creating more.

To undo an incorrect mapping, stop the gateway and restore the original owner
value from the saved XML using the same metadata command. Do not restore an
entire old domain definition over unrelated subsequent changes.

Apply this procedure again if the canonical directory attribute changes or an
account is renamed. Changing the owner does not rename the account inside an
existing guest or change its password.
