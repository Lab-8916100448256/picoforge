<script lang="ts">
  import { Button, buttonVariants } from "$lib/components/ui/button";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import * as Card from "$lib/components/ui/card";
  import * as Alert from "$lib/components/ui/alert";
  import * as Dialog from "$lib/components/ui/dialog";
  import * as AlertDialog from "$lib/components/ui/alert-dialog";
  import * as Drawer from "$lib/components/ui/drawer";
  import { Badge } from "$lib/components/ui/badge";
  import { Separator } from "$lib/components/ui/separator";
  import { TriangleAlert, KeyRound, Trash2, Lock, Unlock, Loader2, Shield } from "@lucide/svelte";
  import { device } from "$lib/device/manager.svelte";
  import type { StoredCredential } from "$lib/device/types.svelte";

  let loading = $state(false);
  let pin = $state("");
  let error = $state("");
  let showPinDialog = $state(false);
  let pinDialogShown = $state(false);

  let detailsOpen = $state(false);
  let selectedCredential: StoredCredential | null = $state(null);

  let deleteDialogOpen = $state(false);
  let credentialToDelete: StoredCredential | null = $state(null);
  let deleteConfirmationInput = $state("");

  $effect(() => {
    if (device.connected && !device.unlocked && !pinDialogShown) {
      showPinDialog = true;
      pinDialogShown = true;
    } else if (!device.connected) {
      showPinDialog = false;
      pinDialogShown = false;
    }
  });

  async function handleUnlock() {
    if (!pin) {
      error = "Please enter your PIN";
      return;
    }

    loading = true;
    const res = await device.getCredentials(pin);

    if (res.success) {
      showPinDialog = false;
      pinDialogShown = false;
    } else {
      error = typeof res.msg === "string" ? res.msg : "Failed to verify PIN";
    }

    loading = false;
  }

  function initiateDelete(cred: StoredCredential) {
    credentialToDelete = cred;
    deleteConfirmationInput = "";
    deleteDialogOpen = true;
  }

  async function executeDelete() {
    if (!credentialToDelete) return;

    loading = true;
    const { credentialId } = credentialToDelete;

    const res = await device.deleteCredential(pin, credentialId);

    if (res.success) {
      await device.getCredentials(pin);

      if (selectedCredential?.credentialId === credentialId) {
        detailsOpen = false;
        selectedCredential = null;
      }

      deleteDialogOpen = false;
      credentialToDelete = null;
    } else {
      deleteDialogOpen = false;
      error = typeof res.msg === "string" ? res.msg : "Failed to delete credential";
    }

    loading = false;
  }

  function handleLock() {
    device.lock();
    pin = "";
    error = "";
    pinDialogShown = false;
  }

  function openDetails(cred: StoredCredential) {
    selectedCredential = cred;
    detailsOpen = true;
  }
</script>

<!-- TODO: Move the dialogs to their own files in src/lib/components/dialogs -->
<div class="space-y-6">
  <div>
    <h1 class="text-3xl font-bold tracking-tight">Passkeys</h1>
    <p class="text-muted-foreground">Manage resident credentials (passkeys) stored on your device.</p>
  </div>

  {#if !device.connected}
    <Alert.Root>
      <TriangleAlert class="h-4 w-4" />
      <Alert.Title>No Device Connected</Alert.Title>
      <Alert.Description>Connect your pico-key to manage passkeys.</Alert.Description>
    </Alert.Root>
  {:else}
    <Dialog.Root bind:open={showPinDialog}>
      <Dialog.Content class="sm:max-w-md">
        <Dialog.Header>
          <Dialog.Title class="flex items-center gap-2">
            <Shield class="h-5 w-5 text-primary" /> Authenticate to View Passkeys
          </Dialog.Title>
          <Dialog.Description>Enter your FIDO2 PIN to access and manage stored credentials.</Dialog.Description>
        </Dialog.Header>
        <div class="space-y-4 py-4">
          <div class="space-y-2">
            <Label for="auth-pin">Device PIN</Label>
            <Input
              id="auth-pin"
              type="password"
              placeholder="Enter your PIN..."
              bind:value={pin}
              disabled={loading}
              onkeydown={(e) => e.key === "Enter" && handleUnlock()}
              autofocus
            />
          </div>
          {#if error}
            <Alert.Root variant="destructive" class="animate-in fade-in slide-in-from-top-1">
              <Alert.Description>{error}</Alert.Description>
            </Alert.Root>
          {/if}
        </div>
        <Dialog.Footer>
          <Button class="w-full" onclick={handleUnlock} disabled={loading}>
            {#if loading}
              <Loader2 class="mr-2 h-4 w-4 animate-spin" />
              Verifying...
            {:else}
              <Unlock class="mr-2 h-4 w-4" /> Unlock Storage
            {/if}
          </Button>
        </Dialog.Footer>
      </Dialog.Content>
    </Dialog.Root>

    {#if device.unlocked}
      <div class="flex items-center justify-between flex-wrap gap-4">
        <div class="flex items-center gap-3">
          <Badge variant="outline" class="bg-green-500/10 text-green-600 border-green-200 px-3 py-1">
            <Lock class="h-3 w-3 mr-1.5" />
            Unlocked
          </Badge>
          <Separator orientation="vertical" class="h-6" />
          <span class="text-sm text-muted-foreground font-medium">
            {device.credentials.length}
            {device.credentials.length === 1 ? "credential" : "credentials"} stored
          </span>
        </div>
        <Button variant="outline" size="sm" onclick={handleLock}>
          <Lock class="mr-2 h-3.5 w-3.5" />
          Lock Storage
        </Button>
      </div>

      {#if device.credentials.length === 0}
        <Card.Root class="border-dashed">
          <Card.Content class="flex flex-col items-center justify-center py-16">
            <div class="rounded-full bg-muted p-4 mb-4">
              <KeyRound class="h-8 w-8 text-muted-foreground" />
            </div>
            <h3 class="text-lg font-semibold mb-2">No Passkeys Found</h3>
            <p class="text-muted-foreground text-center max-w-sm">
              This device doesn't have any resident credentials stored yet. Create passkeys on websites to see them here.
            </p>
          </Card.Content>
        </Card.Root>
      {:else}
        <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {#each device.credentials as cred}
            <button class="text-left w-full h-full" onclick={() => openDetails(cred)}>
              <Card.Root class="overflow-hidden transition-all hover:shadow-md hover:border-primary/50 cursor-pointer h-full">
                <Card.Header>
                  <div class="flex items-center justify-between gap-3">
                    <div class="flex items-center gap-3 flex-1 min-w-0">
                      <div
                        class="h-10 w-10 rounded-lg bg-linear-to-br from-primary/20 to-primary/5 flex items-center justify-center shrink-0"
                      >
                        <KeyRound class="h-5 w-5 text-primary" />
                      </div>

                      <div class="flex-1 min-w-0">
                        <h4 class="font-semibold text-base truncate">
                          {cred.rpName || cred.rpId || "Unknown Service"}
                        </h4>
                        <p class="text-sm text-muted-foreground truncate">{cred.userName}</p>
                      </div>
                    </div>

                    <Button
                      variant="ghost"
                      size="icon"
                      class="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10 shrink-0"
                      onclick={(e) => {
                        e.stopPropagation();
                        initiateDelete(cred);
                      }}
                      disabled={loading}
                    >
                      {#if loading && credentialToDelete?.credentialId === cred.credentialId}
                        <Loader2 class="h-4 w-4 animate-spin" />
                      {:else}
                        <Trash2 class="h-4 w-4" />
                      {/if}
                    </Button>
                  </div>
                </Card.Header>
              </Card.Root>
            </button>
          {/each}
        </div>
      {/if}

      <Drawer.Root bind:open={detailsOpen}>
        <Drawer.Content>
          <div class="mx-auto w-full max-w-lg">
            <Drawer.Header>
              <Drawer.Title class="text-xl">
                {selectedCredential?.rpName || selectedCredential?.rpId || "Passkey Details"}
              </Drawer.Title>
              <Drawer.Description>
                Credential details for user <span class="font-medium text-foreground">{selectedCredential?.userName}</span>
              </Drawer.Description>
            </Drawer.Header>

            <div class="p-4 space-y-4">
              <div class="flex items-center gap-3 p-4 bg-muted/30 rounded-lg border">
                <div class="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center">
                  <KeyRound class="h-6 w-6 text-primary" />
                </div>
                <div>
                  <div class="font-semibold">{selectedCredential?.rpId}</div>
                  <div class="text-sm text-muted-foreground font-mono">{selectedCredential?.userName}</div>
                </div>
              </div>

              <Separator />

              <div class="space-y-4">
                <div class="space-y-1">
                  <p class="text-sm font-medium text-muted-foreground">Display Name</p>
                  <p class="text-base font-medium">{selectedCredential?.userDisplayName || "N/A"}</p>
                </div>

                <div class="space-y-1">
                  <p class="text-sm font-medium text-muted-foreground">User ID (Hex)</p>
                  <p class="text-xs font-mono bg-muted p-2 rounded break-all select-all">
                    {selectedCredential?.userId}
                  </p>
                </div>

                <div class="space-y-1">
                  <p class="text-sm font-medium text-muted-foreground">Credential ID (Hex)</p>
                  <p class="text-xs font-mono bg-muted p-2 rounded break-all select-all">{selectedCredential?.credentialId}</p>
                </div>
              </div>
            </div>

            <Drawer.Footer>
              <Drawer.Close class={buttonVariants({ variant: "outline" })}>Close</Drawer.Close>
            </Drawer.Footer>
          </div>
        </Drawer.Content>
      </Drawer.Root>

      <AlertDialog.Root bind:open={deleteDialogOpen}>
        <AlertDialog.Content>
          <AlertDialog.Header>
            <AlertDialog.Title>Are you sure?</AlertDialog.Title>
            <AlertDialog.Description>
              This action cannot be undone. This will permanently delete the passkey for
              <span class="font-semibold text-foreground">{credentialToDelete?.rpId}</span>.
            </AlertDialog.Description>
          </AlertDialog.Header>

          <div class="py-4 space-y-3">
            <Label for="confirm-delete">
              Type <span class="font-mono text-xs bg-muted px-1 py-0.5 rounded">{credentialToDelete?.rpId}</span> to confirm
            </Label>
            <Input
              id="confirm-delete"
              bind:value={deleteConfirmationInput}
              placeholder={credentialToDelete?.rpId}
              autocomplete="off"
              class="font-mono"
            />
          </div>

          <AlertDialog.Footer>
            <AlertDialog.Cancel disabled={loading}>Cancel</AlertDialog.Cancel>
            <Button
              variant="destructive"
              onclick={executeDelete}
              disabled={deleteConfirmationInput !== credentialToDelete?.rpId || loading}
            >
              {#if loading}
                <Loader2 class="mr-2 h-4 w-4 animate-spin" />
                Deleting...
              {:else}
                Delete Passkey
              {/if}
            </Button>
          </AlertDialog.Footer>
        </AlertDialog.Content>
      </AlertDialog.Root>
    {/if}
  {/if}
</div>
