# PLB-9 — SSH bootstrap on the Windows VM

You only do this once. Should take ~5 minutes.

## What you need

- Windows 11 Pro VM at **10.0.3.10** running and reachable from WSL (already verified by `ping`).
- Administrator access on the VM.
- The two files below copied onto the VM (shared folder, USB stick, drag-and-drop, or `Invoke-WebRequest` from a temporary HTTP server on WSL — pick whichever is easiest).

## The WSL public key (paste this into a file on the VM)

Save the line below verbatim as `C:\Temp\wsl_key.pub` on the VM (create `C:\Temp\` if it doesn't exist):

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFbVY913UWtzJGaBFCPG12Gtkn9SowxVgmczgznNZpuC yallewb@coventry.ac.uk
```

## The bootstrap script

Copy **`verification/plb9/setup/windows_ssh_bootstrap.ps1`** onto the VM as `C:\Temp\windows_ssh_bootstrap.ps1`.

## Run it (on the VM, as Administrator)

1. Press <kbd>Win</kbd>, type **PowerShell**, right-click → **Run as administrator**.
2. Run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\Temp\windows_ssh_bootstrap.ps1 -PubKeyPath C:\Temp\wsl_key.pub
   ```

3. When prompted, set a password for the new `aipet` local account. (Make it whatever you like — we never need it again; SSH key auth replaces it.)

## Expected output (last 6 lines)

```
============================================================
  SSH bootstrap complete.
============================================================

    From WSL, test with:
      ssh aipet@10.0.3.10 'whoami'
```

## Verify from WSL

Once the script reports success, come back to this session and reply **`ssh ready`**. I'll re-probe SSH automatically. If it works, we proceed to Phase 2. If it doesn't, I'll run `ssh -vvv …` and walk through the verbose log.

## Common failures (in order of frequency)

1. **It still asks for a password after setup.**
   The ACLs on `C:\Users\aipet\.ssh\authorized_keys` or `C:\ProgramData\ssh\administrators_authorized_keys` are wrong. Re-run the script — the `icacls` steps are idempotent and will fix it.

2. **`The user is in the Administrators group, so administrators_authorized_keys is consulted.`**
   That's a feature of Windows OpenSSH, not a bug. The script handles it by mirroring the key to both files.

3. **`PubkeyAuthentication no` in `C:\ProgramData\ssh\sshd_config`.**
   Rare but it has been observed in some hardened images. The script patches it to `yes` automatically.

4. **Connection times out from WSL.**
   Either the firewall rule didn't take effect, or the VM's network adapter isn't on the host-only network. From the VM run `Get-NetFirewallRule -Name sshd | Format-List Enabled, Direction, Action, Profile`. From WSL run `ping 10.0.3.10` — must succeed before SSH will.

5. **Profile not created.**
   On a freshly imaged VM, `C:\Users\aipet\` doesn't exist until the user logs in interactively at least once. The script tries to trigger creation; if it fails you'll see a warning and it will create the directory manually. Either way the rest of the steps work.
