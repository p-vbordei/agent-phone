# agent-phone conformance suite

Run: `bun conformance/run.ts`

Each vector is a standalone `.ts` file that exits 0 on pass, non-zero on fail.
`run.ts` is the single entry point — it imports all vectors and prints a summary.
