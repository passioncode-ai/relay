// #region portable-store — docs: docs/adr/0001-relay-repository.md#two-builds
// Blobs of the self-hosted relay: one file per digest under <dataDir>/blobs/sha256/, owner-only
// (directories 0700, files 0600), written to a temporary name and renamed so a reader never sees half a blob.

import { randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { BlobStore } from "../core/digest.ts";
import { isDigest } from "../core/digest.ts";

export class FsBlobStore implements BlobStore {
  readonly #root: string;
  constructor(dataDir: string) {
    this.#root = join(dataDir, "blobs", "sha256");
  }

  #path(digest: string): string {
    if (!isDigest(digest)) throw new TypeError("not a sha256 digest");
    return join(this.#root, digest.slice("sha256:".length));
  }

  async write(digest: string, bytes: Uint8Array): Promise<void> {
    const target = this.#path(digest);
    await mkdir(this.#root, { recursive: true, mode: 0o700 });
    const temporary = `${target}.${randomBytes(6).toString("hex")}.tmp`;
    try {
      await writeFile(temporary, bytes, { mode: 0o600, flag: "wx" });
      await rename(temporary, target);
    } catch (error) {
      await rm(temporary, { force: true });
      throw error;
    }
  }

  async read(digest: string): Promise<Uint8Array | null> {
    try {
      return new Uint8Array(await readFile(this.#path(digest)));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
  }
}
// #endregion portable-store
