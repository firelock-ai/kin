import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

let contractsPromise;

export async function assertKinContract(name, payload) {
  const contracts = await loadKinContracts();
  await contracts.assertContract(name, payload);
  return payload;
}

async function loadKinContracts() {
  if (!contractsPromise) {
    contractsPromise = importKinContracts();
  }
  return contractsPromise;
}

async function importKinContracts() {
  const specifiers = [];
  const configuredRoot = process.env.KIN_BOUNDARY_CONTRACTS_PATH || '';
  if (configuredRoot) {
    specifiers.push(pathToFileURL(resolveContractEntry(configuredRoot)).href);
  }
  specifiers.push('@kin/boundary-contracts');
  specifiers.push(pathToFileURL(resolveSiblingContractsEntry()).href);

  let lastError;
  for (const specifier of specifiers) {
    try {
      return await import(specifier);
    } catch (error) {
      if (!isMissingModuleError(error)) {
        throw error;
      }
      lastError = error;
    }
  }

  throw new Error(
    `Unable to load @kin/boundary-contracts. Set KIN_BOUNDARY_CONTRACTS_PATH.${lastError instanceof Error ? ` ${lastError.message}` : ''}`
  );
}

function resolveContractEntry(target) {
  const resolved = path.resolve(target);
  return resolved.endsWith('.js')
    ? resolved
    : path.join(resolved, 'src', 'index.js');
}

function resolveSiblingContractsEntry() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'boundary-contracts', 'src', 'index.js');
}

function isMissingModuleError(error) {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes('Cannot find package')
    || message.includes('Cannot find module')
    || message.includes('ERR_MODULE_NOT_FOUND')
    || message.includes('no such file or directory');
}
