// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title  EHRRegistry — patient-centric access governance and AI provenance registry
/// @notice Reference implementation for Sections 3.3, 3.3.1, 3.4 and 4.1 of the manuscript.
///
///         CONFIDENTIALITY BOUNDARY (Section 5.4). Every value stored or emitted by this
///         contract, and every transaction input, is readable by any node operator. Solidity
///         `private` and view-function access checks are NOT confidentiality controls.
///         Therefore the contract stores ONLY:
///           - content identifiers (CIDs) of AES-256-GCM encrypted IPFS objects,
///           - SHA-256 digests / commitments (H_P, H_C, Hash_infer),
///           - ECIES-wrapped symmetric keys (ciphertext decryptable only by the recipient),
///           - permission flags, versions, epochs, addresses and timestamps.
///         Plaintext DICOM pixel data, plaintext AI probability vectors and unwrapped keys
///         never appear on-chain.
///
///         State model (Section 3.3.1): M : P x R x C -> {0,1} is implemented literally as
///         permissions[patient][recordId][clinician], i.e. CanView[Patient][RecordID][Clinician].
contract EHRRegistry is EIP712, ReentrancyGuard, Ownable {
    // ------------------------------------------------------------------ errors
    error Unauthorized();
    error InvalidInput();
    error InvalidSignature();
    error RecordAlreadyExists();
    error RecordNotFound();
    error AccessNotGranted();
    error KeyNotAvailable();
    error Replay();
    error AuthorizationExpired();
    error StaleRecordVersion();
    error StalePermissionEpoch();
    error ModelNotApproved();

    // --------------------------------------------------------------- constants
    /// @dev ECIES wrapped key = R (33-byte compressed secp256k1 point) || IV_wrap (12)
    ///      || C_key (32) || T_key (16) = 93 bytes (Section 3.4, step 4).
    uint256 public constant WRAPPED_KEY_LENGTH = 93;
    /// @dev Upper bound on recipients re-keyed in one updateRecord call (gas-DoS bound).
    uint256 public constant MAX_RECIPIENTS = 32;
    /// @dev Maximum tolerated client clock skew for signed record timestamps.
    uint256 public constant MAX_CLOCK_SKEW = 300;

    /// @dev ECDSA (EIP-712) signature scope for record registration / update.
    ///      Binds H_P || H_C || RecordID || Timestamp (manuscript Section 3.4) plus the patient,
    ///      record version and CID; the EIP-712 domain adds chainId and this contract's address
    ///      (cross-chain / cross-contract replay protection).
    bytes32 public constant RECORD_ATTESTATION_TYPEHASH = keccak256(
        "RecordAttestation(address patient,bytes32 recordId,uint64 version,string encryptedPayloadCID,bytes32 payloadDigest,bytes32 ciphertextDigest,uint64 timestamp)"
    );

    /// @dev Reviewing-clinician authorization for appending an AI inference commitment.
    ///      Replay protection: per-clinician nonce + deadline + permission epoch + record version.
    bytes32 public constant DIAGNOSTIC_AUTHORIZATION_TYPEHASH = keccak256(
        "DiagnosticAuthorization(address patient,bytes32 recordId,uint64 recordVersion,bytes32 aiPayloadHash,string encryptedAiCID,bytes32 modelVersionHash,address clinician,uint64 permissionEpoch,uint256 nonce,uint256 deadline)"
    );

    // ----------------------------------------------------------------- structs
    struct Record {
        string encryptedPayloadCID; // CID of IPFS bundle C || IV || T
        bytes32 payloadDigest;      // H_P = SHA-256(P)            (image-identity commitment)
        bytes32 ciphertextDigest;   // H_C = SHA-256(C||IV||T||CID) (ciphertext-integrity digest)
        uint64 version;             // V_n, incremented on every update (fresh key K per version)
        uint64 signedAt;            // Timestamp covered by the patient's ECDSA signature
        uint64 createdAt;
        uint64 updatedAt;
        bool exists;
    }

    struct Permission {
        bool canView;  // read access + eligibility to receive wrapped keys
        bool canEdit;  // append diagnostic AI inferences (canEdit implies canView)
        uint64 epoch;  // incremented on every grant/revoke; binds signed authorizations
    }

    struct AIInferenceRecord {
        bytes32 aiPayloadHash;      // Hash_infer = SHA-256(Vector_AI || Salt) commitment
        string encryptedAiCID;      // CID_infer of AES-256-GCM encrypted inference object
        bytes32 modelVersionHash;   // SHA-256 of the DenseNet121 checkpoint (approved model)
        address reviewingClinician; // EIP-712 signer holding CanEdit
        uint64 timestamp;           // block timestamp of the commitment
        uint64 recordVersion;       // record version the inference refers to (links to H_P)
    }

    /// @dev Input bundle for registerRecord / updateRecord (struct avoids stack-too-deep).
    struct RecordInput {
        bytes32 recordId;
        string encryptedPayloadCID; // CID of the IPFS bundle C || IV || T
        bytes32 payloadDigest;      // H_P
        bytes32 ciphertextDigest;   // H_C
        uint64 signedAt;            // Timestamp inside the ECDSA signature scope
    }

    /// @dev Input bundle for appendDiagnosticAI (struct avoids stack-too-deep).
    struct DiagnosticAuthorization {
        address patient;
        bytes32 recordId;
        uint64 recordVersion;
        bytes32 aiPayloadHash;
        string encryptedAiCID;
        bytes32 modelVersionHash;
        address clinician;
        uint64 permissionEpoch;
        uint256 nonce;
        uint256 deadline;
    }

    // ----------------------------------------------------------------- storage
    mapping(address => mapping(bytes32 => Record)) private records;
    mapping(address => mapping(bytes32 => mapping(address => Permission))) private permissions;
    /// @dev wrappedKeys[patient][recordId][version][clinician] = WK_clinician for K_version
    mapping(address => mapping(bytes32 => mapping(uint64 => mapping(address => bytes)))) private wrappedKeys;
    mapping(address => mapping(bytes32 => AIInferenceRecord[])) private inferences;

    /// @notice Model registry maintained by the institutional governance account (owner).
    mapping(bytes32 => bool) public approvedModels;
    /// @notice Next valid DiagnosticAuthorization nonce per clinician.
    mapping(address => uint256) public nonces;

    // ------------------------------------------------------------------ events
    event RecordRegistered(address indexed patient, bytes32 indexed recordId, uint64 version, string encryptedPayloadCID, bytes32 payloadDigest, bytes32 ciphertextDigest, uint64 signedAt);
    event RecordUpdated(address indexed patient, bytes32 indexed recordId, uint64 version, string encryptedPayloadCID, bytes32 payloadDigest, bytes32 ciphertextDigest, uint64 signedAt);
    event AccessChanged(address indexed patient, bytes32 indexed recordId, address indexed clinician, bool canView, bool canEdit, uint64 epoch);
    event WrappedKeyPublished(address indexed patient, bytes32 indexed recordId, address indexed clinician, uint64 version);
    event DiagnosticAIAppended(address indexed patient, bytes32 indexed recordId, uint256 indexed inferenceIndex, uint64 recordVersion, bytes32 aiPayloadHash, string encryptedAiCID, bytes32 modelVersionHash, address reviewingClinician);
    event IntegrityViolationAlert(address indexed patient, bytes32 indexed recordId, address indexed reporter, bytes32 violationType, bytes32 expectedDigest, bytes32 observedDigest);
    event ModelApproved(bytes32 indexed modelVersionHash);
    event ModelRevoked(bytes32 indexed modelVersionHash);

    // --------------------------------------------------------------- modifiers
    /// @dev msg.sender must own an existing record (the "onlyPatient" check of Eq. (1)/(2)).
    modifier onlyPatient(bytes32 recordId) {
        if (!records[msg.sender][recordId].exists) revert Unauthorized();
        _;
    }

    modifier recordExists(address patient, bytes32 recordId) {
        if (!records[patient][recordId].exists) revert RecordNotFound();
        _;
    }

    /// @dev Patient or a clinician holding CanView. NOTE: for view functions this is an
    ///      interface policy only — eth_call lets any caller choose `from`, and storage is public.
    modifier onlyViewer(address patient, bytes32 recordId) {
        if (msg.sender != patient && !permissions[patient][recordId][msg.sender].canView) revert Unauthorized();
        _;
    }

    constructor(address governance) EIP712("EHRRegistry", "1") Ownable(governance) {}

    // =========================================================== record lifecycle

    /// @notice Register version 1 of a record. `signature` is the patient's EIP-712 ECDSA
    ///         signature over RecordAttestation; the signer must be msg.sender.
    function registerRecord(RecordInput calldata input, bytes calldata signature) external nonReentrant {
        _validateRecordInput(input);
        Record storage r = records[msg.sender][input.recordId];
        if (r.exists) revert RecordAlreadyExists();

        _verifyRecordSignature(msg.sender, 1, input, signature);

        r.encryptedPayloadCID = input.encryptedPayloadCID;
        r.payloadDigest = input.payloadDigest;
        r.ciphertextDigest = input.ciphertextDigest;
        r.version = 1;
        r.signedAt = input.signedAt;
        r.createdAt = uint64(block.timestamp);
        r.updatedAt = uint64(block.timestamp);
        r.exists = true;

        emit RecordRegistered(msg.sender, input.recordId, 1, input.encryptedPayloadCID, input.payloadDigest, input.ciphertextDigest, input.signedAt);
    }

    /// @notice Publish version n+1, encrypted under a FRESH symmetric key K_{n+1}. Wrapped keys
    ///         can only be published for clinicians that currently hold CanView, so revoked
    ///         clinicians are cryptographically excluded from all subsequent versions.
    function updateRecord(
        RecordInput calldata input,
        bytes calldata signature,
        address[] calldata recipients,
        bytes[] calldata recipientWrappedKeys
    ) external nonReentrant onlyPatient(input.recordId) {
        _validateRecordInput(input);
        if (recipients.length != recipientWrappedKeys.length || recipients.length > MAX_RECIPIENTS) revert InvalidInput();

        Record storage r = records[msg.sender][input.recordId];
        uint64 newVersion = r.version + 1;
        _verifyRecordSignature(msg.sender, newVersion, input, signature);

        r.encryptedPayloadCID = input.encryptedPayloadCID;
        r.payloadDigest = input.payloadDigest;
        r.ciphertextDigest = input.ciphertextDigest;
        r.version = newVersion;
        r.signedAt = input.signedAt;
        r.updatedAt = uint64(block.timestamp);

        emit RecordUpdated(msg.sender, input.recordId, newVersion, input.encryptedPayloadCID, input.payloadDigest, input.ciphertextDigest, input.signedAt);

        for (uint256 i = 0; i < recipients.length; ++i) {
            if (!permissions[msg.sender][input.recordId][recipients[i]].canView) revert AccessNotGranted();
            _storeWrappedKey(msg.sender, input.recordId, newVersion, recipients[i], recipientWrappedKeys[i]);
        }
    }

    // ========================================================= access governance

    /// @notice Grant (or re-grant) access to the CURRENT record version. Publishes the
    ///         recipient-specific ECIES wrapped key WK_clinician in the same transaction.
    ///         canEdit = true yields CanView AND CanEdit (they coexist; CanEdit implies CanView).
    function grantAccess(bytes32 recordId, address clinician, bool canEdit, bytes calldata wrappedKey)
        external
        nonReentrant
        onlyPatient(recordId)
    {
        if (clinician == address(0) || clinician == msg.sender) revert InvalidInput();
        Permission storage p = permissions[msg.sender][recordId][clinician];
        unchecked { p.epoch += 1; }
        p.canView = true;
        p.canEdit = canEdit;
        emit AccessChanged(msg.sender, recordId, clinician, true, canEdit, p.epoch);
        _storeWrappedKey(msg.sender, recordId, records[msg.sender][recordId].version, clinician, wrappedKey);
    }

    /// @notice Prospective revocation (Eq. (2)): clears CanView/CanEdit, bumps the permission
    ///         epoch (invalidating any outstanding signed authorizations) and deletes the wrapped
    ///         key for the current version from contract storage. It cannot erase keys or
    ///         plaintext the clinician already obtained (Section 5.4.1).
    function revokeAccess(bytes32 recordId, address clinician) external nonReentrant onlyPatient(recordId) {
        Permission storage p = permissions[msg.sender][recordId][clinician];
        if (!p.canView) revert AccessNotGranted();
        unchecked { p.epoch += 1; }
        p.canView = false;
        p.canEdit = false;
        delete wrappedKeys[msg.sender][recordId][records[msg.sender][recordId].version][clinician];
        emit AccessChanged(msg.sender, recordId, clinician, false, false, p.epoch);
    }

    // ============================================================ AI provenance

    /// @notice Append an AI inference COMMITMENT (never the plaintext probability vector).
    ///         Authorized by the reviewing clinician's EIP-712 signature; may be submitted by
    ///         the clinician or by a relayer. Checks, in order: record exists, non-empty
    ///         inputs, deadline, record version, approved model, CanEdit, permission epoch,
    ///         nonce (replay), signature.
    function appendDiagnosticAI(DiagnosticAuthorization calldata a, bytes calldata signature) external nonReentrant {
        Record storage r = records[a.patient][a.recordId];
        if (!r.exists) revert RecordNotFound();
        if (a.aiPayloadHash == bytes32(0) || a.modelVersionHash == bytes32(0) || bytes(a.encryptedAiCID).length == 0 || a.clinician == address(0)) revert InvalidInput();
        if (block.timestamp > a.deadline) revert AuthorizationExpired();
        if (a.recordVersion != r.version) revert StaleRecordVersion();
        if (!approvedModels[a.modelVersionHash]) revert ModelNotApproved();

        Permission storage p = permissions[a.patient][a.recordId][a.clinician];
        if (!p.canEdit) revert Unauthorized();
        if (a.permissionEpoch != p.epoch) revert StalePermissionEpoch();
        if (a.nonce != nonces[a.clinician]) revert Replay();

        _verifyDiagnosticSignature(a, signature);

        unchecked { nonces[a.clinician] += 1; }
        AIInferenceRecord[] storage list = inferences[a.patient][a.recordId];
        list.push(AIInferenceRecord(a.aiPayloadHash, a.encryptedAiCID, a.modelVersionHash, a.clinician, uint64(block.timestamp), a.recordVersion));
        _emitDiagnostic(a, list.length - 1);
    }

    function _verifyDiagnosticSignature(DiagnosticAuthorization calldata a, bytes calldata signature) private view {
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hashDiagnosticAuthorization(a), signature);
        if (err != ECDSA.RecoverError.NoError || signer != a.clinician) revert InvalidSignature();
    }

    function _emitDiagnostic(DiagnosticAuthorization calldata a, uint256 index) private {
        emit DiagnosticAIAppended(a.patient, a.recordId, index, a.recordVersion, a.aiPayloadHash, a.encryptedAiCID, a.modelVersionHash, a.clinician);
    }

    // ============================================================ audit pathway

    /// @notice Persist a client-detected integrity anomaly (Section 3.3). Detection happens
    ///         client-side (H_C / H_P / signature / CID mismatch); because logs from a REVERTED
    ///         call are discarded (EIP-140), the client submits this separate, successful
    ///         transaction, which emits an immutable IntegrityViolationAlert.
    function reportIntegrityViolation(
        address patient,
        bytes32 recordId,
        bytes32 violationType,
        bytes32 expectedDigest,
        bytes32 observedDigest
    ) external recordExists(patient, recordId) onlyViewer(patient, recordId) {
        if (violationType == bytes32(0) || expectedDigest == observedDigest) revert InvalidInput();
        emit IntegrityViolationAlert(patient, recordId, msg.sender, violationType, expectedDigest, observedDigest);
    }

    // ======================================================== model governance

    function approveModel(bytes32 modelVersionHash) external onlyOwner {
        if (modelVersionHash == bytes32(0)) revert InvalidInput();
        approvedModels[modelVersionHash] = true;
        emit ModelApproved(modelVersionHash);
    }

    function revokeModel(bytes32 modelVersionHash) external onlyOwner {
        approvedModels[modelVersionHash] = false;
        emit ModelRevoked(modelVersionHash);
    }

    // ==================================================================== views

    function getRecord(address patient, bytes32 recordId)
        external
        view
        recordExists(patient, recordId)
        onlyViewer(patient, recordId)
        returns (string memory encryptedPayloadCID, bytes32 payloadDigest, bytes32 ciphertextDigest, uint64 version, uint64 signedAt)
    {
        Record storage r = records[patient][recordId];
        return (r.encryptedPayloadCID, r.payloadDigest, r.ciphertextDigest, r.version, r.signedAt);
    }

    /// @notice Returns the caller's wrapped key for the CURRENT version. Reverts for callers
    ///         without CanView (ST-01) and when no key was wrapped for them for this version.
    function getRecordKey(address patient, bytes32 recordId)
        external
        view
        recordExists(patient, recordId)
        returns (bytes memory wrappedKey, uint64 version)
    {
        if (!permissions[patient][recordId][msg.sender].canView) revert Unauthorized();
        version = records[patient][recordId].version;
        wrappedKey = wrappedKeys[patient][recordId][version][msg.sender];
        if (wrappedKey.length == 0) revert KeyNotAvailable();
    }

    /// @notice Permission state is public information by construction (see contract header).
    function getPermission(address patient, bytes32 recordId, address clinician)
        external
        view
        returns (bool canView_, bool canEdit_, uint64 epoch)
    {
        Permission storage p = permissions[patient][recordId][clinician];
        return (p.canView, p.canEdit, p.epoch);
    }

    /// @notice CanView[Patient][RecordID][Clinician] predicate used by the invariant tests.
    function canView(address patient, bytes32 recordId, address clinician) external view returns (bool) {
        return permissions[patient][recordId][clinician].canView;
    }

    function recordVersion(address patient, bytes32 recordId) external view returns (uint64) {
        return records[patient][recordId].version;
    }

    function inferenceCount(address patient, bytes32 recordId) external view returns (uint256) {
        return inferences[patient][recordId].length;
    }

    function getInference(address patient, bytes32 recordId, uint256 index)
        external
        view
        recordExists(patient, recordId)
        onlyViewer(patient, recordId)
        returns (AIInferenceRecord memory)
    {
        if (index >= inferences[patient][recordId].length) revert InvalidInput();
        return inferences[patient][recordId][index];
    }

    // ============================================================ EIP-712 helpers
    // abi.encode of static 32-byte words is plain concatenation, so bytes.concat of two
    // abi.encode calls equals one abi.encode of all fields (split only to limit stack depth).

    function hashRecordAttestation(address patient, uint64 version, RecordInput calldata input) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(bytes.concat(
            abi.encode(RECORD_ATTESTATION_TYPEHASH, patient, input.recordId, version),
            abi.encode(keccak256(bytes(input.encryptedPayloadCID)), input.payloadDigest, input.ciphertextDigest, input.signedAt)
        )));
    }

    function hashDiagnosticAuthorization(DiagnosticAuthorization calldata a) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(bytes.concat(
            abi.encode(DIAGNOSTIC_AUTHORIZATION_TYPEHASH, a.patient, a.recordId, a.recordVersion, a.aiPayloadHash, keccak256(bytes(a.encryptedAiCID))),
            abi.encode(a.modelVersionHash, a.clinician, a.permissionEpoch, a.nonce, a.deadline)
        )));
    }

    // ================================================================ internals

    function _validateRecordInput(RecordInput calldata input) private view {
        if (
            input.recordId == bytes32(0) || bytes(input.encryptedPayloadCID).length == 0 || input.payloadDigest == bytes32(0)
                || input.ciphertextDigest == bytes32(0) || input.signedAt == 0 || input.signedAt > block.timestamp + MAX_CLOCK_SKEW
        ) revert InvalidInput();
    }

    function _verifyRecordSignature(address patient, uint64 version, RecordInput calldata input, bytes calldata signature) private view {
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hashRecordAttestation(patient, version, input), signature);
        if (err != ECDSA.RecoverError.NoError || signer != patient) revert InvalidSignature();
    }

    function _storeWrappedKey(address patient, bytes32 recordId, uint64 version, address clinician, bytes calldata wrappedKey) private {
        if (wrappedKey.length != WRAPPED_KEY_LENGTH) revert InvalidInput();
        wrappedKeys[patient][recordId][version][clinician] = wrappedKey;
        emit WrappedKeyPublished(patient, recordId, clinician, version);
    }
}
