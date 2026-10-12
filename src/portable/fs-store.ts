// #region portable-store — docs: docs/adr/0001-relay-repository.md#two-builds
// Blobs of the self-hosted relay: one file per digest under <dataDir>/blobs/sha256/, owner-only
// (directories 0700, files 0600), written to a temporary name and renamed so a reader never sees half a blob.

import { randomBytes } from "node:crypto";
import { mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { EstateSource } from "../core/admission.ts";
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

/**
 * The estate as the operator placed it under <dataDir>/estate/: `pinned.json` (the estate's first passkeys, public keys
 * pinned at setup) and `revisions/<n>.json`. Nothing here is trusted: every revision is verified by the contract.
 */
export class FsEstateSource implements EstateSource {
  readonly #root: string;
  constructor(dataDir: string) {
    this.#root = join(dataDir, "estate");
  }
  async pinned(): Promise<unknown[]> {
    try {
      const value = JSON.parse(await readFile(join(this.#root, "pinned.json"), "utf8")) as unknown;
      return Array.isArray(value) ? value : [];
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }
  async revisions(): Promise<unknown[]> {
    let names: string[];
    try {
      names = (await readdir(join(this.#root, "revisions"))).filter((name) => name.endsWith(".json"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    return Promise.all(names.map(async (name) => JSON.parse(await readFile(join(this.#root, "revisions", name), "utf8")) as unknown));
  }
}
// #endregion portable-store
