// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// A tsserver plugin that resolves what a repository's own layout cannot:
// workspace packages from their source, and dependencies from Kin's
// analysis environment. It computes no mapping of its own; everything it
// knows comes from the JSON file named by KIN_TSSERVER_WORKSPACE, written by
// Kin outside the repository:
//
//   {"root": ..., "packages": [{"name", "dir", "tsconfig"}],
//    "workspaceMap": {"<package>": "<source entry>", "<package>/<sub>": "<file>",
//                     "<package>/*": "<dir>/*"},
//    "layout": "<Kin's node_modules layout>" | null}
//
// 1. A file inside another workspace package resolves its imports with that
//    package's own tsconfig, so its path aliases (`~/*` -> `src/*`) mean what
//    they mean to its own build rather than to the project that reached it.
// 2. An import of a workspace package that tsserver could not resolve (it is
//    linked to build output not built yet, `workspace:./drizzle-orm/dist`) is
//    resolved through the workspace map: an exact entry names the file, and a
//    `name/*` entry names the directory a subpath resolves under.
// 3. Any other import tsserver could not resolve is resolved as if from the
//    importing file's mirror in the layout, where Kin laid out exactly the
//    dependencies the lock gives that importer; and the layout's `@types`
//    directories join the project's type roots.
//
// An import tsserver resolved itself is never replaced, except in rule 1's
// files, where the owning package's answer is the right one.

'use strict';

const fs = require('fs');
const path = require('path');

const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.d.ts'];

function readWorkspace(log) {
  const file = process.env.KIN_TSSERVER_WORKSPACE;
  if (!file) {
    return undefined;
  }
  try {
    const workspace = JSON.parse(fs.readFileSync(file, 'utf8'));
    const packages = Array.isArray(workspace.packages) ? workspace.packages : [];
    if (packages.length === 0 && !workspace.layout) {
      return undefined;
    }
    return {
      root: typeof workspace.root === 'string' ? path.resolve(workspace.root) : undefined,
      packages,
      workspaceMap: workspace.workspaceMap && typeof workspace.workspaceMap === 'object'
        ? workspace.workspaceMap
        : {},
      layout: typeof workspace.layout === 'string' ? path.resolve(workspace.layout) : undefined,
    };
  } catch (error) {
    log(`could not read ${file}: ${error}`);
    return undefined;
  }
}

function within(file, dir) {
  return file === dir || file.startsWith(dir + path.sep) || file.startsWith(dir + '/');
}

function createResolver(ts, workspace, projectDir) {
  // Longest directory first, so a package nested in another owns its own files.
  const packages = workspace.packages
    .filter((pkg) => pkg && typeof pkg.name === 'string' && typeof pkg.dir === 'string')
    .map((pkg) => ({ name: pkg.name, dir: path.resolve(pkg.dir), tsconfig: pkg.tsconfig }))
    .sort((a, b) => b.dir.length - a.dir.length);
  // Exact entries, and `name/*` patterns with the longest prefix first.
  const exact = new Map();
  const patterns = [];
  for (const [key, target] of Object.entries(workspace.workspaceMap)) {
    if (typeof target !== 'string') {
      continue;
    }
    if (key.endsWith('/*')) {
      patterns.push({ prefix: key.slice(0, -1), target });
    } else {
      exact.set(key, target);
    }
  }
  patterns.sort((a, b) => b.prefix.length - a.prefix.length);
  const options = new Map();
  const configHost = {
    ...ts.sys,
    onUnRecoverableConfigFileDiagnostic: () => {},
  };
  const layoutCache = new Map();

  function ownerOf(file) {
    return packages.find((pkg) => within(file, pkg.dir));
  }

  // A package's own compiler options, with a resolution cache of its own.
  function optionsOf(pkg) {
    if (!pkg.tsconfig) {
      return undefined;
    }
    if (!options.has(pkg.dir)) {
      let parsed;
      try {
        parsed = ts.getParsedCommandLineOfConfigFile(pkg.tsconfig, {}, configHost);
      } catch (_) {
        parsed = undefined;
      }
      options.set(
        pkg.dir,
        parsed
          ? {
              compilerOptions: parsed.options,
              cache: ts.createModuleResolutionCache(pkg.dir, (name) => name, parsed.options),
            }
          : undefined,
      );
    }
    return options.get(pkg.dir);
  }

  function resolved(file) {
    return {
      resolvedFileName: file,
      extension: ts.extensionFromPath(file),
      isExternalLibraryImport: false,
      resolvedUsingTsExtension: false,
    };
  }

  // A file or directory named without its extension, as a source file.
  function probe(base) {
    const stem = base.replace(/\.(m|c)?js$/, '');
    for (const candidate of [stem, path.join(stem, 'index')]) {
      for (const extension of SOURCE_EXTENSIONS) {
        const file = candidate + extension;
        if (ts.sys.fileExists(file)) {
          return file;
        }
      }
    }
    return ts.sys.fileExists(base) ? base : undefined;
  }

  // Rule 2: a workspace package, through the workspace map.
  function fromWorkspaceMap(specifier) {
    const entry = exact.get(specifier);
    if (entry && ts.sys.fileExists(entry)) {
      return resolved(entry);
    }
    const pattern = patterns.find((candidate) => specifier.startsWith(candidate.prefix));
    if (!pattern) {
      return undefined;
    }
    const rest = specifier.slice(pattern.prefix.length);
    const file = probe(pattern.target.replace('*', rest));
    return file ? resolved(file) : undefined;
  }

  function isBare(specifier) {
    return !(specifier.startsWith('.') || path.isAbsolute(specifier) || specifier.startsWith('/'));
  }

  // The importing file's mirror in the layout, where its importer's locked
  // dependencies are; undefined for a file outside the repository.
  function mirrorOf(containingFile) {
    if (!workspace.layout || !workspace.root) {
      return undefined;
    }
    const file = path.resolve(containingFile);
    if (!within(file, workspace.root) || within(file, workspace.layout)) {
      return undefined;
    }
    return path.join(workspace.layout, path.relative(workspace.root, file));
  }

  // Rule 3: a dependency, from the layout.
  function fromLayout(specifier, containingFile, compilerOptions) {
    const mirror = isBare(specifier) ? mirrorOf(containingFile) : undefined;
    if (!mirror) {
      return undefined;
    }
    let cache = layoutCache.get(compilerOptions);
    if (!cache) {
      cache = ts.createModuleResolutionCache(workspace.layout, (name) => name, compilerOptions);
      layoutCache.set(compilerOptions, cache);
    }
    const answer = ts.resolveModuleName(specifier, mirror, compilerOptions, ts.sys, cache);
    return answer && answer.resolvedModule;
  }

  function typeFromLayout(name, containingFile, compilerOptions) {
    const mirror = mirrorOf(containingFile);
    if (!mirror) {
      return undefined;
    }
    const answer = ts.resolveTypeReferenceDirective(name, mirror, compilerOptions, ts.sys);
    return answer && answer.resolvedTypeReferenceDirective;
  }

  // The better answer for one import, or undefined to keep tsserver's own.
  function improve(specifier, containingFile, found, compilerOptions) {
    const owner = ownerOf(path.resolve(containingFile));
    if (owner && !(projectDir && within(projectDir, owner.dir))) {
      const own = optionsOf(owner);
      if (own) {
        const answer = ts.resolveModuleName(
          specifier,
          containingFile,
          own.compilerOptions,
          ts.sys,
          own.cache,
        );
        if (answer && answer.resolvedModule) {
          return answer.resolvedModule;
        }
      }
    }
    if (found) {
      return undefined;
    }
    return fromWorkspaceMap(specifier) || fromLayout(specifier, containingFile, compilerOptions);
  }

  // The type roots of a project whose configuration lives in `configDir`,
  // with the layout's mirrored `@types` directories added: the defaults
  // TypeScript finds by walking up, or the configured roots, and the mirror
  // of each.
  function withLayoutTypeRoots(compilerOptions, configDir) {
    if (!workspace.layout || !workspace.root) {
      return compilerOptions;
    }
    const explicit = Array.isArray(compilerOptions.typeRoots);
    const roots = [];
    if (explicit) {
      roots.push(...compilerOptions.typeRoots);
    } else {
      // TypeScript's own default: every node_modules/@types from the
      // configuration's directory up.
      for (let dir = path.resolve(configDir); ; dir = path.dirname(dir)) {
        const candidate = path.join(dir, 'node_modules', '@types');
        if (ts.sys.directoryExists(candidate)) {
          roots.push(candidate);
        }
        if (dir === path.dirname(dir)) {
          break;
        }
      }
    }
    const mirrored = [];
    for (const root of roots) {
      const mirror = mirrorOf(root);
      if (mirror && ts.sys.directoryExists(mirror)) {
        mirrored.push(mirror);
      }
    }
    if (!explicit && within(path.resolve(configDir), workspace.root)) {
      // The same walk in the layout, from the configuration's mirror up to
      // the layout's root.
      for (let dir = path.resolve(configDir); ; dir = path.dirname(dir)) {
        const mirror = path.join(workspace.layout, path.relative(workspace.root, dir));
        const candidate = path.join(mirror, 'node_modules', '@types');
        if (ts.sys.directoryExists(candidate)) {
          mirrored.push(candidate);
        }
        if (dir === workspace.root || dir === path.dirname(dir)) {
          break;
        }
      }
    }
    if (mirrored.length === 0) {
      return compilerOptions;
    }
    return { ...compilerOptions, typeRoots: [...new Set([...roots, ...mirrored])] };
  }

  return { improve, typeFromLayout, withLayoutTypeRoots };
}

function init(modules) {
  const ts = modules.typescript;

  function create(info) {
    const logger = info.project.projectService.logger;
    const log = (message) => logger.info(`[kin-workspace-sources] ${message}`);
    const workspace = readWorkspace(log);
    if (!workspace) {
      return info.languageService;
    }
    const projectDir =
      info.project.projectKind === ts.server.ProjectKind.Configured
        ? path.dirname(path.resolve(info.project.getProjectName()))
        : undefined;
    const resolver = createResolver(ts, workspace, projectDir);
    const host = info.languageServiceHost;
    const settings = () =>
      typeof host.getCompilationSettings === 'function' ? host.getCompilationSettings() : {};

    if (workspace.layout && typeof host.getCompilationSettings === 'function') {
      const original = host.getCompilationSettings.bind(host);
      let last;
      let lastResult;
      host.getCompilationSettings = () => {
        const options = original();
        if (options !== last) {
          last = options;
          lastResult = resolver.withLayoutTypeRoots(
            options,
            projectDir || info.project.getCurrentDirectory(),
          );
        }
        return lastResult;
      };
    }

    if (typeof host.resolveModuleNameLiterals === 'function') {
      const original = host.resolveModuleNameLiterals.bind(host);
      host.resolveModuleNameLiterals = (literals, containingFile, redirected, options, ...rest) => {
        const answers = original(literals, containingFile, redirected, options, ...rest);
        return answers.map((answer, index) => {
          const better = resolver.improve(
            literals[index].text,
            containingFile,
            answer && answer.resolvedModule,
            options || settings(),
          );
          return better ? { resolvedModule: better, failedLookupLocations: [] } : answer;
        });
      };
    } else if (typeof host.resolveModuleNames === 'function') {
      const original = host.resolveModuleNames.bind(host);
      host.resolveModuleNames = (names, containingFile, reused, redirected, options, ...rest) => {
        const answers = original(names, containingFile, reused, redirected, options, ...rest);
        return answers.map(
          (answer, index) =>
            resolver.improve(names[index], containingFile, answer, options || settings()) ||
            answer,
        );
      };
    } else {
      return info.languageService;
    }

    if (workspace.layout && typeof host.resolveTypeReferenceDirectiveReferences === 'function') {
      const original = host.resolveTypeReferenceDirectiveReferences.bind(host);
      host.resolveTypeReferenceDirectiveReferences = (
        references,
        containingFile,
        redirected,
        options,
        ...rest
      ) => {
        const answers = original(references, containingFile, redirected, options, ...rest);
        return answers.map((answer, index) => {
          if (answer && answer.resolvedTypeReferenceDirective) {
            return answer;
          }
          const reference = references[index];
          const name = typeof reference === 'string' ? reference : reference.fileName;
          const better = resolver.typeFromLayout(name, containingFile, options || settings());
          return better ? { resolvedTypeReferenceDirective: better, failedLookupLocations: [] } : answer;
        });
      };
    }
    log(
      `resolving ${workspace.packages.length} workspace packages from source` +
        (workspace.layout ? ` and dependencies from ${workspace.layout}` : ''),
    );
    return info.languageService;
  }

  return { create };
}

module.exports = init;
