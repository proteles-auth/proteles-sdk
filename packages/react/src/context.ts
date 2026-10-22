"use client";

//! The React context carrying auth state + actions. Separated from the provider
//! so tests can supply a value directly.

import { createContext } from "react";

import type { AuthContextValue } from "./types.js";

export const AuthContext = createContext<AuthContextValue | null>(null);
