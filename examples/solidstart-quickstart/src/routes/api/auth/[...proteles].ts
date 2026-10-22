// The entire OAuth flow (login, callback, logout, me) is handled here.
// Configuration comes from PROTELES_* env vars.
import { protelesAuthHandler } from "@proteles/solid/server";

export const GET = protelesAuthHandler;
export const POST = protelesAuthHandler;
