import { db } from "../db/client.js";
import { RepositoryRow } from "../db/schema.js";

/**
 * Standard NotFoundError thrown when authorization check fails or resource does not exist.
 * Standardizing on NotFoundError guarantees identical HTTP 404 responses for "not yours" and "does not exist".
 */
export class NotFoundError extends Error {
  constructor(message = "Not found") {
    super(message);
    this.name = "NotFoundError";
  }
}

/**
 * Asserts that the given userId is authorized to access the given repoId.
 * Default DENY policy:
 * 1. Unauthenticated users (userId missing/null) -> throw NotFoundError
 * 2. Non-existent repositories -> throw NotFoundError
 * 3. Users lacking confirmed GitHub App access -> throw NotFoundError
 */
export async function assertRepoAccess(
  userId: string | undefined | null,
  repoId: string
): Promise<{ authorized: true; repository: RepositoryRow }> {
  // 1. Default Deny: Unauthenticated user
  if (!userId || userId.trim() === "") {
    throw new NotFoundError("Not found");
  }

  // 2. Resolve repository
  const repository = await db.getRepositoryById(repoId);
  if (!repository) {
    throw new NotFoundError("Not found");
  }

  // 3. Confirm repository access
  const hasAccess = await db.checkUserRepoAccess(userId, repoId);
  if (!hasAccess) {
    throw new NotFoundError("Not found");
  }

  return { authorized: true, repository };
}
