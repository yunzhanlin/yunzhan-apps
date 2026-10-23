import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { historicalMobileRepository } from "../tools/historical-mobile-repository.mjs";
const root = fileURLToPath(new URL("../", import.meta.url));
const predecessor = "registry/reviewed-catalogs/before-native-mobile132-24bkep";
test("older Nginx observer retains current-root default but explicitly accepts only the genuine signed predecessor", () => {
  assert.equal(historicalMobileRepository([], root), root);
  assert.equal(historicalMobileRepository(["--repo-root", predecessor], root), root + predecessor);
});
test("historical native observer refuses arbitrary paths, aliases, traversal, extra flags and inline signatures", () => {
  for (const args of [
    ["--repo-root"], ["--repo-root", "."], ["--repo-root", "/tmp/forged"],
    ["--repo-root", predecessor + "/../fake"], ["--repo-root=" + predecessor],
    ["--repo-root", predecessor, "--skip-signature"], ["--repo-root", predecessor + "/"],
    ["--repo-root", predecessor, "--key", "inline"],
  ]) assert.throws(() => historicalMobileRepository(args, root));
});
