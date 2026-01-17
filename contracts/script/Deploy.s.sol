// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../AnankeAttestationRegistry.sol";
import "../AnankeRevocationRegistry.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        vm.startBroadcast(deployerPrivateKey);

        // Deploy contracts
        AnankeAttestationRegistry attestation = new AnankeAttestationRegistry();
        AnankeRevocationRegistry revocation = new AnankeRevocationRegistry();

        console.log("AnankeAttestationRegistry deployed to:", address(attestation));
        console.log("AnankeRevocationRegistry deployed to:", address(revocation));

        vm.stopBroadcast();
    }
}
