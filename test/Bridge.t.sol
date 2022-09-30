// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/BridgeProxy.sol";
import "../src/BridgeData.sol";
import "../src/BridgeLogic.sol";

contract BridgeTest is Test {
    BridgeProxy public proxy;
    BridgeData public data;
    BridgeLogic public logic;

    uint16 public srcChainID;
    uint16 public dstChainID;
    uint256 pk1;
    uint256 pk2;
    uint256 pk3;

    function setUp() public {
        srcChainID = 1;
        dstChainID = 2;
        pk1 = 1;
        pk2 = 2;
        pk3 = 3;

        // 创建三个管理员钱包地址 用于多签准备
        address[] memory keepers = new address[](3);
        // https://book.getfoundry.sh/cheatcodes/addr
        
        keepers[0] = address(vm.addr(pk1));
        keepers[1] = address(vm.addr(pk2));
        keepers[2] = address(vm.addr(pk3));

        proxy = new BridgeProxy();
        data = new BridgeData(srcChainID, address(proxy), keepers);
        logic = new BridgeLogic(address(proxy), address(data));
        proxy.upgradeLogic(address(logic));
    }

    function testSend() external {
        // 将本合约加入白名单
        data.addWhiteListFrom(address(this));
        // 发送入口
        logic.send(dstChainID, Utils.addressToBytes(address(0)), bytes(""));
    }

    function onReceive(
        uint16,
        bytes calldata,
        uint256,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function testReceive(
        uint16 _srcChainID,
        uint256 _nonce,
        address _srcAddress,
        bytes memory _payload
    ) external {
        // 本合约加入到白名单
        address _dstAddress = address(this);
        data.addWhiteListTo(_dstAddress);


        bytes memory sigs = bytes("");

        bytes32 hash = keccak256(
            abi.encodePacked(
                _srcChainID,
                data.chainID(),
                _nonce,
                _srcAddress,
                _dstAddress,
                _payload
            )
        );

        // 用私钥1 对hash进行签名
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk1, hash);

        // 签名者1验证
        address signer = ecrecover(hash, v, r, s);
        assertEq(signer, vm.addr(pk1));

        // 将签名者1的密钥和空消息 进行打包
        sigs = abi.encodePacked(sigs, r, s, v); // sigs 长度 65

        // 签名者2对hash签名
        (v, r, s) = vm.sign(pk2, hash);

        // 将签名者2的密钥和bytes消息进行打包
        sigs = abi.encodePacked(sigs, r, s, v); // sigs 长度 65 * 2

        // 签名者3对hash签名
        (v, r, s) = vm.sign(pk3, hash);

        // 将签名者3的密钥和消息进行打包
        sigs = abi.encodePacked(sigs, r, s, v); // sigs 长度 65 * 3

        // bytes的长度为三个签名者
        assertEq(sigs.length, 65 * 3);

        logic.receivePayload(
            _srcChainID, // 原链id
            _nonce, // 自增id
            Utils.addressToBytes(_srcAddress), // 钱包地址
            _dstAddress, // 目标地址
            _payload,
            sigs, // 签名消息
            200000
        );
    }
}
