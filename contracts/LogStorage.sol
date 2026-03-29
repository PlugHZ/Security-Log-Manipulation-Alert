// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract LogStorage {
    address public owner;
    
    // โครงสร้างสำหรับเก็บข้อมูลของแต่ละ Block (1 Block = สูงสุด 20 Logs หรือทุก 5 นาที)
    struct BlockEntry {
        string batchHash;     // ค่า Hash ตัวท๊อปของก้อนนี้
        string masterHash;    // โซ่ Master สรุปยอด (sha256(batchHash + previousMasterHash))
        uint256 recordCount;  //  จำนวนแถวจริงในก้อนนี้ (เพื่อตรวจจับการลบ)
        uint256 timestamp;    // เวลาที่ประทับตราบนเชน
        address recorder;     // กระเป๋าที่ทำการบันทึก
    }

    // เก็บข้อมูลแยกตามชื่อ Block (เช่น "GROUP_1", "GROUP_2")
    mapping(string => BlockEntry) private blocks;
    
    //  ตัวนับจำนวน Group ทั้งหมดที่เคยบันทึก (ป้องกันการลบทั้งตาราง)
    uint256 public totalGroups;
    
    // Event แจ้งเตือนเมื่อมีการบันทึก Block ใหม่สำเร็จ
    event BlockSecured(string indexed blockId, string batchHash, string masterHash, uint256 recordCount, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    // จำกัดสิทธิ์ให้เฉพาะเจ้าของระบบ (Backend ของเรา) เป็นคนส่งข้อมูลได้
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    //  ฟังก์ชันบันทึก (เพิ่ม _recordCount)
    function storeBatch(
        string memory _blockId, 
        string memory _batchHash, 
        string memory _masterHash,
        uint256 _recordCount
    ) public onlyOwner {
        blocks[_blockId] = BlockEntry({
            batchHash: _batchHash,
            masterHash: _masterHash,
            recordCount: _recordCount,
            timestamp: block.timestamp,
            recorder: msg.sender
        });

        totalGroups++;
        emit BlockSecured(_blockId, _batchHash, _masterHash, _recordCount, block.timestamp);
    }

    //  ฟังก์ชันดึงข้อมูล (return recordCount ด้วย)
    function getLog(string memory _blockId) public view returns (
        string memory batchHash, 
        string memory masterHash, 
        uint256 recordCount,
        uint256 timestamp, 
        address recorder
    ) {
        BlockEntry memory entry = blocks[_blockId];
        require(bytes(entry.masterHash).length > 0, "Block not found");
        
        return (entry.batchHash, entry.masterHash, entry.recordCount, entry.timestamp, entry.recorder);
    }
}