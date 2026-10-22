// The entire OAuth flow (login, callback, logout, me) is handled here.
// Configuration comes from PROTELES_* env vars.
import { protelesAuthHandler } from "@proteles/vue/server";

export default defineEventHandler((event) => protelesAuthHandler(event));
