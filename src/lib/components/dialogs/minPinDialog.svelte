<script lang="ts">
  // import { Button } from "$lib/components/ui/button";
  import { Input } from "$lib/components/ui/input";
  import { Label } from "$lib/components/ui/label";
  import { Slider } from "$lib/components/ui/slider/index.js";
  import * as AlertDialog from "$lib/components/ui/alert-dialog";

  import { configViewState as state } from "$lib/state/configState.svelte";
</script>

<AlertDialog.Root bind:open={state.minPinDialogOpen}>
  <AlertDialog.Content>
    <AlertDialog.Header>
      <AlertDialog.Title>Update Minimum PIN Length</AlertDialog.Title>
      <AlertDialog.Description>
        Set the minimum allowed PIN length (4-63 characters) and enter a new PIN
        that meets this requirement.
      </AlertDialog.Description>
    </AlertDialog.Header>
    <div class="space-y-4 py-4">
      <div class="space-y-2">
        <Label for="min-pin-length"
          >Minimum PIN Length ({state.minPinLength})</Label
        >
        <Slider
          type="single"
          bind:value={state.minPinLength}
          min={4}
          max={63}
          step={1}
        />
      </div>
      <div class="space-y-2">
        <Label for="min-pin-current">Current PIN</Label>
        <Input
          id="min-pin-current"
          type="password"
          bind:value={state.minPinCurrentPin}
          placeholder="Enter current PIN"
          autofocus
        />
      </div>
      <div class="space-y-2">
        <Label for="min-pin-new">New PIN (min {state.minPinLength} chars)</Label
        >
        <Input
          id="min-pin-new"
          type="password"
          bind:value={state.minPinNewPin}
          placeholder="Enter new PIN"
        />
      </div>
      <div class="space-y-2">
        <Label for="min-pin-confirm">Confirm New PIN</Label>
        <Input
          id="min-pin-confirm"
          type="password"
          bind:value={state.minPinConfirmPin}
          placeholder="Confirm new PIN"
        />
      </div>
      {#if state.minPinError}
        <p class="text-sm text-destructive">{state.minPinError}</p>
      {/if}
    </div>
    <AlertDialog.Footer>
      <AlertDialog.Cancel onclick={() => (state.minPinDialogOpen = false)}
        >Cancel</AlertDialog.Cancel
      >
      <AlertDialog.Action onclick={state.handleMinPinChange}
        >Update</AlertDialog.Action
      >
    </AlertDialog.Footer>
  </AlertDialog.Content>
</AlertDialog.Root>
