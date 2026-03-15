import path from 'path';
import { getStoragePaths, loadMeta } from '../storage/repo-manager.js';
import { isGitRepo, getGitRoot } from '../storage/git.js';
import { generateAIContextFiles } from './ai-context.js';

export const syncDocsCommand = async () => {
  console.log('\n  GitNexus Doc Sync\n');

  const gitRoot = getGitRoot(process.cwd());
  if (!gitRoot) {
    console.log('  Not inside a git repository\n');
    process.exitCode = 1;
    return;
  }

  if (!isGitRepo(gitRoot)) {
    console.log('  Not a git repository\n');
    process.exitCode = 1;
    return;
  }

  const { storagePath } = getStoragePaths(gitRoot);
  const existingMeta = await loadMeta(storagePath);

  if (!existingMeta) {
    console.log('  No GitNexus index found. Run `npx gitnexus analyze` first.\n');
    process.exitCode = 1;
    return;
  }

  const projectName = path.basename(gitRoot);

  const aiContext = await generateAIContextFiles(
    gitRoot,
    storagePath,
    projectName,
    existingMeta.stats
  );

  console.log(`  Materialized context into:`);
  for (const file of aiContext.files) {
    console.log(`  - ${file}`);
  }
  console.log('');
};
