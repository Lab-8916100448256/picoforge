<script lang="ts">
  // import { Button } from "$lib/components/ui/button";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import * as AlertDialog from "$lib/components/ui/alert-dialog";

  import { configViewState as state } from "$lib/state/configState.svelte";
</script>

<AlertDialog.Root bind:open={state.setPinDialogOpen}>
  <AlertDialog.Content>
    <AlertDialog.Header>
      <AlertDialog.Title
        >{state.isSettingPin ? "Set PIN" : "Change PIN"}</AlertDialog.Title
      >
      <AlertDialog.Description>
        {state.isSettingPin
          ? "Set a PIN for your FIDO2 device. Minimum length is " +
            (state.minPinLength || 4) +
            " characters."
          : "Enter your current PIN and choose a new one."}
      </AlertDialog.Description>
    </AlertDialog.Header>
    <div class="space-y-4 py-4">
      {#if !state.isSettingPin}
        <div class="space-y-2">
          <Label for="current-pin">Current PIN</Label>
          <Input
            id="current-pin"
            type="password"
            bind:value={state.currentPin}
            placeholder="Enter current PIN"
            autofocus
          />
        </div>
      {/if}
      <div class="space-y-2">
        <Label for="new-pin">New PIN</Label>
        <Input
          id="new-pin"
          type="password"
          bind:value={state.newPin}
          placeholder="Enter new PIN"
          autofocus={state.isSettingPin}
        />
      </div>
      <div class="space-y-2">
        <Label for="confirm-pin">Confirm New PIN</Label>
        <Input
          id="confirm-pin"
          type="password"
          bind:value={state.confirmPin}
          placeholder="Confirm new PIN"
        />
      </div>
      {#if state.pinError}
        <p class="text-sm text-destructive">{state.pinError}</p>
      {/if}
    </div>
    <AlertDialog.Footer>
      <AlertDialog.Cancel onclick={() => (state.setPinDialogOpen = false)}
        >Cancel</AlertDialog.Cancel
      >
      <AlertDialog.Action onclick={() => state.handlePinChange()}
        >Confirm</AlertDialog.Action
      >
    </AlertDialog.Footer>
  </AlertDialog.Content>
</AlertDialog.Root>
