#!/usr/bin/env node

// Resolve tsx from this installed package, not from the caller's working
// directory (which is where `node --import tsx` resolves a shebang import).
import { tsImport } from "tsx/esm/api";

await tsImport("./pi-enclave.ts", import.meta.url);
