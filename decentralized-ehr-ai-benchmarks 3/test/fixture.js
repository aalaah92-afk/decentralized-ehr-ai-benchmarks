"use strict";
const { ethers } = require("hardhat");
const H = require("./helpers");

const TEST_MODEL_HASH = H.bytes32("DenseNet121-ChestXray14-TEST-CHECKPOINT");

/** Deploys the registry and registers one record (version 1) for `patient`. */
async function deployFixture() {
  const [governance, relayer, funder] = await ethers.getSigners();
  const patient = await H.fundedWallet(funder);
  const patientB = await H.fundedWallet(funder);
  const clinA = await H.fundedWallet(funder);
  const clinB = await H.fundedWallet(funder);
  const outsider = await H.fundedWallet(funder);

  const Registry = await ethers.getContractFactory("EHRRegistry");
  const registry = await Registry.deploy(governance.address);
  await registry.waitForDeployment();
  await (await registry.connect(governance).approveModel(TEST_MODEL_HASH)).wait();

  const store = new H.LocalCASStore();
  const recordId = H.bytes32("record-001");
  const v1 = await H.prepareRecordVersion({
    registry, store, patient, recordId, version: 1, plaintext: H.randomPayload(512 * 1024),
  });
  await (await registry.connect(patient).registerRecord(v1.input, v1.signature)).wait();

  return { registry, store, governance, relayer, funder, patient, patientB, clinA, clinB, outsider, recordId, v1 };
}

const PROBS = [0.12, 0.81, 0.33, 0.47, 0.09, 0.15, 0.05, 0.21, 0.02, 0.11, 0.07, 0.04, 0.06, 0.01];

module.exports = { deployFixture, TEST_MODEL_HASH, PROBS };
