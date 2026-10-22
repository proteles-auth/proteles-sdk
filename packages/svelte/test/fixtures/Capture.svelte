<!-- Test fixture: passes the auth store from context to `capture`. -->
<script>
  import { getAuth } from "../../src/context.js";

  export let capture;
  capture(getAuth());
</script>
