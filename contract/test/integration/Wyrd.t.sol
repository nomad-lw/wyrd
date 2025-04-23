// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Wyrd} from "src/Wyrd.sol";
import {OwnableRoles} from "solady/auth/OwnableRoles.sol";

import "test/config.sol" as cfg;
import {VRFTestData} from "test/utils/VRFTestData.sol";
import {TestableWyrd, WyrdTestHelpers} from "test/integration/Helpers.t.sol";

import {MockPythEntropy, MockRandomizer} from "test/mocks/MockRandomProviders.t.sol";
import {IEntropy} from "@pythnetwork/entropy-sdk-solidity/IEntropy.sol";
import {IRandomizer} from "src/interfaces/ext/IRandomizer.sol";

contract WyrdTests is WyrdTestHelpers {
    uint8 expected_source_flags;

    // Role flags
    uint256 role_operator;
    uint256 role_sav_prover;

    // Helper functions

    // a nominal behaviour test
    function setUp() public {
        // Deploy mock providers
        mock_pyth_entropy = new MockPythEntropy();
        mock_randomizer = new MockRandomizer();

        uint256[2] memory sav_pk = [uint256(0x1), uint256(0x2)];

        // Prank as deployer and create Wyrd with mock providers
        vm.prank(cfg.ADDR_DEPLOYER);
        wyrd = new TestableWyrd(cfg.FLAG_ALL_SOURCES, address(mock_pyth_entropy), cfg.ADDR_PYTH_PROVIDER, address(mock_randomizer), sav_pk, true);

        twyrd = TestableWyrd(address(wyrd));
        sav_pk = twyrd.vrf_tester().get_pk();
        role_operator = twyrd.get_role_operator();
        role_sav_prover = twyrd.get_role_sav_prover();

        expected_source_flags = cfg.FLAG_ALL_SOURCES;

        // Fund address with ETH for tests
        vm.deal(cfg.ADDR_DEPLOYER, 10 ether);
        vm.deal(cfg.ADDR_OPERATOR, 10 ether);
        vm.deal(cfg.ADDR_SAV_PROVER, 10 ether);
        vm.deal(address(this), 10 ether);
    }

    function test_user_role_management() public {
        // Test ownership
        console.log("Deployer:", cfg.ADDR_DEPLOYER);
        assertEq(wyrd.owner(), cfg.ADDR_DEPLOYER);

        // Check deployer has all expected roles
        vm.startPrank(cfg.ADDR_DEPLOYER);

        // Test deployer has operator role
        console.log("Testing deployer has ROLE_OPERATOR");
        assertTrue(wyrd.hasAnyRole(cfg.ADDR_DEPLOYER, role_operator), "Deployer should have operator role");

        // Test deployer has SAV prover role
        console.log("Testing deployer has ROLE_SAV_PROVER");
        assertTrue(wyrd.hasAnyRole(cfg.ADDR_DEPLOYER, role_sav_prover), "Deployer should have SAV prover role");

        // Grant operator role to ADDR_OPERATOR
        console.log("Granting ROLE_OPERATOR to ADDR_OPERATOR");
        wyrd.grantRoles(cfg.ADDR_OPERATOR, role_operator);

        // Grant SAV_PROVER role to ADDR_SAV_PROVER
        console.log("Granting ROLE_SAV_PROVER to ADDR_SAV_PROVER");
        wyrd.grantRoles(cfg.ADDR_SAV_PROVER, role_sav_prover);

        // Verify roles were granted correctly
        assertTrue(wyrd.hasAnyRole(cfg.ADDR_OPERATOR, role_operator), "ADDR_OPERATOR should have operator role");
        assertTrue(wyrd.hasAnyRole(cfg.ADDR_SAV_PROVER, role_sav_prover), "ADDR_SAV_PROVER should have SAV prover role");

        vm.stopPrank();
    }

    function test_provider_flags() public {
        console.log("Testing randomness source provider flags");

        // Initial test with all sources active
        uint8 sources = wyrd.get_active_sources();
        assertEq(sources, expected_source_flags);

        vm.startPrank(cfg.ADDR_DEPLOYER);

        // Test with only Pyth source active
        wyrd.set_sources(cfg.FLAG_PYTH);
        sources = wyrd.get_active_sources();
        assertEq(sources, cfg.FLAG_PYTH);

        // Test with only Randomizer source active
        wyrd.set_sources(cfg.FLAG_RANDOMIZER);
        sources = wyrd.get_active_sources();
        assertEq(sources, cfg.FLAG_RANDOMIZER);

        // Test with only SAV source active
        wyrd.set_sources(cfg.FLAG_SAV);
        sources = wyrd.get_active_sources();
        assertEq(sources, cfg.FLAG_SAV);

        // Test with Pyth and Randomizer active
        wyrd.set_sources(cfg.FLAG_PYTH | cfg.FLAG_RANDOMIZER);
        sources = wyrd.get_active_sources();
        assertEq(sources, cfg.FLAG_PYTH | cfg.FLAG_RANDOMIZER);

        // Test with Pyth and SAV active
        wyrd.set_sources(cfg.FLAG_PYTH | cfg.FLAG_SAV);
        sources = wyrd.get_active_sources();
        assertEq(sources, cfg.FLAG_PYTH | cfg.FLAG_SAV);

        // Test with Randomizer and SAV active
        wyrd.set_sources(cfg.FLAG_RANDOMIZER | cfg.FLAG_SAV);
        sources = wyrd.get_active_sources();
        assertEq(sources, cfg.FLAG_RANDOMIZER | cfg.FLAG_SAV);

        // Reset to all sources active
        wyrd.set_sources(cfg.FLAG_ALL_SOURCES);
        sources = wyrd.get_active_sources();
        assertEq(sources, cfg.FLAG_ALL_SOURCES);

        vm.stopPrank();
    }

    function test_request() public {
        uint256 req_id = 12345;
        bytes32 alpha = bytes32(uint256(0xABCDEF));
        uint8 sources = wyrd.get_active_sources();

        // Give operator role permission to make the request
        grant_roles(cfg.ADDR_OPERATOR, twyrd.get_role_operator());

        // Make request as operator with enough ETH to cover fees
        make_request(req_id, alpha);
        verify_request_status(req_id, true, sources);

        // Verify alpha was stored if STORE_ALPHA_INPUTS is true
        if (twyrd.get_store_alpha_inputs()) {
            bytes32 stored_alpha = wyrd.get_alpha(req_id);
            assertEq(stored_alpha, alpha, "Stored alpha doesn't match request alpha");
        } else {
            revert("STORE_ALPHA_INPUTS is expected to be true by default");
        }
    }

    function test_all_providers__request_and_process() public {
        uint256 req_id = 12345;
        bytes32 alpha = bytes32(req_id);
        // (uint256[2] memory pk, bytes memory alpha,,,,,,) = twyrd.vrf_tester().get_valid_vrf_proof();
        (uint256[2] memory pk,,,,,,) = twyrd.vrf_tester().generate_vrf_proof(alpha);

        // Grant operator role to ADDR_OPERATOR and SAV_PROVER role to ADDR_SAV_PROVER
        grant_roles(cfg.ADDR_OPERATOR, role_operator);
        grant_roles(cfg.ADDR_SAV_PROVER, role_sav_prover);

        // Revoke operator and SAV_PROVER roles from deployer
        revoke_roles(cfg.ADDR_DEPLOYER, role_operator);
        revoke_roles(cfg.ADDR_DEPLOYER, role_sav_prover);

        // Fast forward time and make sure SAV pk is correct
        vm.warp(block.timestamp + 5 hours);
        vm.prank(cfg.ADDR_SAV_PROVER);
        wyrd.set_sav_public_key(pk);

        // Make request as operator with enough ETH to cover fees
        make_request(req_id, bytes32(alpha));

        // Verify request status before callbacks
        verify_request_status(req_id, true, wyrd.get_active_sources());
        ext_process_request_callbacks(req_id);
        verify_request_status(req_id, false, 0);

        // Verify random value is available
        verify_random_value(req_id, true);
    }

    function test_a_rediculously_long_fn_name_that_takes_in_no_parameters_just_like_the_other_tests_in_this_contract_and_simply_asserts_that_the_static_boolean_value_true_is_indeed_true(
    ) public pure {
        assertTrue(true, "Static boolean value true should be true");
    }
}
