// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {EHRRegistry} from "../../contracts/EHRRegistry.sol";

/// @dev Random-action handler for invariant testing. Tracks a "ghost" model of the
///      permission mapping M : P x R x C -> {0,1} that only patient-issued grant/revoke may change.
contract Handler is Test {
    EHRRegistry public reg;
    address public constant OUTSIDER = address(0xBAD);

    uint256[3] internal patientKeys = [uint256(0xA11CE), uint256(0xB0B), uint256(0xCA11)];
    address[3] public patients;
    address[3] public clinicians;
    bytes32[3] public recordIds = [bytes32("rec-1"), bytes32("rec-2"), bytes32("rec-3")];

    mapping(address => mapping(bytes32 => mapping(address => bool))) public ghostCanView;
    mapping(address => mapping(bytes32 => mapping(address => bool))) public ghostCanEdit;
    mapping(address => mapping(bytes32 => uint64)) public ghostVersion;
    uint256 public unauthorizedSuccesses;
    uint256 public calls;

    constructor(EHRRegistry _reg) {
        reg = _reg;
        for (uint256 i = 0; i < 3; ++i) {
            patients[i] = vm.addr(patientKeys[i]);
            clinicians[i] = address(uint160(0xC0 + i));
        }
    }

    function _input(bytes32 rid, uint64 v) internal view returns (EHRRegistry.RecordInput memory in_) {
        in_ = EHRRegistry.RecordInput({
            recordId: rid,
            encryptedPayloadCID: "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
            payloadDigest: keccak256(abi.encode("P", rid, v)),
            ciphertextDigest: keccak256(abi.encode("C", rid, v)),
            signedAt: uint64(block.timestamp)
        });
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _wk(uint256 seed) internal pure returns (bytes memory w) {
        w = new bytes(93);
        w[0] = bytes1(uint8(seed));
    }

    function register(uint256 pSeed, uint256 rSeed) external {
        calls++;
        uint256 pi = pSeed % 3; address p = patients[pi]; bytes32 rid = recordIds[rSeed % 3];
        if (ghostVersion[p][rid] != 0) return;
        EHRRegistry.RecordInput memory in_ = _input(rid, 1);
        bytes memory sig = _sign(patientKeys[pi], reg.hashRecordAttestation(p, 1, in_));
        vm.prank(p);
        reg.registerRecord(in_, sig);
        ghostVersion[p][rid] = 1;
    }

    function grant(uint256 pSeed, uint256 rSeed, uint256 cSeed, bool edit) external {
        calls++;
        address p = patients[pSeed % 3]; bytes32 rid = recordIds[rSeed % 3]; address c = clinicians[cSeed % 3];
        if (ghostVersion[p][rid] == 0) return;
        vm.prank(p);
        reg.grantAccess(rid, c, edit, _wk(cSeed));
        ghostCanView[p][rid][c] = true;
        ghostCanEdit[p][rid][c] = edit;
    }

    function revoke(uint256 pSeed, uint256 rSeed, uint256 cSeed) external {
        calls++;
        address p = patients[pSeed % 3]; bytes32 rid = recordIds[rSeed % 3]; address c = clinicians[cSeed % 3];
        if (!ghostCanView[p][rid][c]) return;
        vm.prank(p);
        reg.revokeAccess(rid, c);
        ghostCanView[p][rid][c] = false;
        ghostCanEdit[p][rid][c] = false;
    }

    function update(uint256 pSeed, uint256 rSeed) external {
        calls++;
        uint256 pi = pSeed % 3; address p = patients[pi]; bytes32 rid = recordIds[rSeed % 3];
        uint64 v = ghostVersion[p][rid];
        if (v == 0) return;
        EHRRegistry.RecordInput memory in_ = _input(rid, v + 1);
        bytes memory sig = _sign(patientKeys[pi], reg.hashRecordAttestation(p, v + 1, in_));
        vm.prank(p);
        reg.updateRecord(in_, sig, new address[](0), new bytes[](0));
        ghostVersion[p][rid] = v + 1;
    }

    /// @dev Adversarial action: a non-owner (clinician, outsider or another patient) tries to
    ///      grant/revoke on someone else's record. Any success is a violation.
    function attackerMutate(uint256 aSeed, uint256 pSeed, uint256 rSeed, uint256 cSeed, bool doGrant) external {
        calls++;
        bytes32 rid = recordIds[rSeed % 3];
        address[5] memory attackers = [OUTSIDER, clinicians[0], clinicians[1], patients[(pSeed % 3 + 1) % 3], patients[(pSeed % 3 + 2) % 3]];
        address a = attackers[aSeed % 5];
        // another patient that owns a record with the same id acts on ITS OWN record (allowed);
        // skip that case so only genuine cross-owner attempts are counted.
        if (ghostVersion[a][rid] != 0) return;
        vm.prank(a);
        if (doGrant) {
            try reg.grantAccess(rid, OUTSIDER, true, _wk(1)) { unauthorizedSuccesses++; } catch {}
        } else {
            try reg.revokeAccess(rid, clinicians[cSeed % 3]) { unauthorizedSuccesses++; } catch {}
        }
    }
}

contract EHRRegistryInvariantTest is StdInvariant, Test {
    EHRRegistry internal reg;
    Handler internal handler;

    function setUp() public {
        reg = new EHRRegistry(address(this));
        handler = new Handler(reg);
        targetContract(address(handler));
    }

    /// Invariant 1: an address never granted access can never view any record.
    function invariant_outsiderNeverCanView() public view {
        for (uint256 i = 0; i < 3; ++i) for (uint256 j = 0; j < 3; ++j) {
            assertFalse(reg.canView(handler.patients(i), handler.recordIds(j), handler.OUTSIDER()));
        }
    }

    /// Invariant 2 (Non-Delegation): on-chain CanView/CanEdit equal the ghost model, which only
    /// patient-issued grant/revoke can change.
    function invariant_permissionsMatchPatientActions() public view {
        for (uint256 i = 0; i < 3; ++i) for (uint256 j = 0; j < 3; ++j) for (uint256 k = 0; k < 3; ++k) {
            address p = handler.patients(i); bytes32 r = handler.recordIds(j); address c = handler.clinicians(k);
            (bool v, bool e,) = reg.getPermission(p, r, c);
            assertEq(v, handler.ghostCanView(p, r, c));
            assertEq(e, handler.ghostCanEdit(p, r, c));
        }
    }

    /// Invariant 3: CanEdit implies CanView.
    function invariant_editImpliesView() public view {
        for (uint256 i = 0; i < 3; ++i) for (uint256 j = 0; j < 3; ++j) for (uint256 k = 0; k < 3; ++k) {
            (bool v, bool e,) = reg.getPermission(handler.patients(i), handler.recordIds(j), handler.clinicians(k));
            assertTrue(!e || v);
        }
    }

    /// Invariant 4: record versions only advance through signed patient updates.
    function invariant_versionMatchesGhost() public view {
        for (uint256 i = 0; i < 3; ++i) for (uint256 j = 0; j < 3; ++j) {
            address p = handler.patients(i); bytes32 r = handler.recordIds(j);
            assertEq(reg.recordVersion(p, r), handler.ghostVersion(p, r));
        }
    }

    /// Invariant 5: no non-owner grant/revoke attempt ever succeeded.
    function invariant_noUnauthorizedMutation() public view {
        assertEq(handler.unauthorizedSuccesses(), 0);
    }
}

/// @dev Stateless property (fuzz) tests; runs = [fuzz].runs in foundry.toml (10^5).
contract EHRRegistryFuzzTest is Test {
    EHRRegistry internal reg;
    uint256 internal constant PATIENT_PK = 0xA11CE;
    address internal patient;
    bytes32 internal constant RID = bytes32("rec-fuzz");

    function setUp() public {
        reg = new EHRRegistry(address(this));
        patient = vm.addr(PATIENT_PK);
        EHRRegistry.RecordInput memory in_ = _input();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PATIENT_PK, reg.hashRecordAttestation(patient, 1, in_));
        vm.prank(patient);
        reg.registerRecord(in_, abi.encodePacked(r, s, v));
    }

    function _input() internal view returns (EHRRegistry.RecordInput memory) {
        return EHRRegistry.RecordInput(RID, "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku", keccak256("P"), keccak256("C"), uint64(block.timestamp));
    }

    function testFuzz_nonPatientCannotGrant(address caller, address clinician) public {
        vm.assume(caller != patient);
        vm.expectRevert(EHRRegistry.Unauthorized.selector);
        vm.prank(caller);
        reg.grantAccess(RID, clinician, true, new bytes(93));
    }

    function testFuzz_nonPatientCannotRevoke(address caller, address clinician) public {
        vm.assume(caller != patient);
        vm.expectRevert(EHRRegistry.Unauthorized.selector);
        vm.prank(caller);
        reg.revokeAccess(RID, clinician);
    }

    function testFuzz_ungrantedCannotGetRecordKey(address caller) public {
        vm.expectRevert(EHRRegistry.Unauthorized.selector);
        vm.prank(caller);
        reg.getRecordKey(patient, RID);
    }

    function testFuzz_foreignSignatureRejected(uint256 pk) public {
        pk = bound(pk, 1, 115792089237316195423570985008687907852837564279074904382605163141518161494336);
        vm.assume(pk != PATIENT_PK);
        EHRRegistry.RecordInput memory in_ = _input();
        in_.recordId = bytes32("rec-other");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, reg.hashRecordAttestation(patient, 1, in_));
        vm.expectRevert(EHRRegistry.InvalidSignature.selector);
        vm.prank(patient);
        reg.registerRecord(in_, abi.encodePacked(r, s, v));
    }

    function testFuzz_wrappedKeyLengthEnforced(bytes calldata wk) public {
        vm.assume(wk.length != 93);
        vm.expectRevert(EHRRegistry.InvalidInput.selector);
        vm.prank(patient);
        reg.grantAccess(RID, address(0xC0), false, wk);
    }
}
