const mysql = require('mysql2/promise');
const hre = require("hardhat");
const crypto = require("crypto");
require('dotenv').config();

async function main() {
    const db = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASS || '1234',
        database: process.env.DB_NAME || 'company_db',
        dateStrings: true
    });

    const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
    if (!CONTRACT_ADDRESS) {
        throw new Error(" หา CONTRACT_ADDRESS ไม่เจอ! ตรวจสอบไฟล์ .env");
    }

    const [signer] = await hre.ethers.getSigners();
    const abi = [
        "function addLog(string memory _id, string memory _hash) public",
        "function getLog(string memory _id) public view returns (string memory, uint256, address)"
    ];
    const contract = new hre.ethers.Contract(CONTRACT_ADDRESS, abi, signer);

    // สร้างตาราง audit_ledger ถ้ายังไม่มี
    await db.execute(`
        CREATE TABLE IF NOT EXISTS audit_ledger (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            group_number INT NOT NULL,
            row_index INT NOT NULL,
            event_time DATETIME(6) NOT NULL,
            log_source VARCHAR(100) NOT NULL,
            log_content TEXT NOT NULL,
            current_hash VARCHAR(64) NOT NULL,
            is_anchor TINYINT DEFAULT 0,
            tx_hash VARCHAR(100),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_alert TINYINT DEFAULT 0,
            tamper_first_detected_at DATETIME,
            INDEX idx_group (group_number),
            INDEX idx_event_time (event_time)
        )
    `);

    // ดึง Log ทั้งหมดจาก general_log (กรองแค่ของระบบ audit)
    const [rows] = await db.execute(`
        SELECT event_time, user_host, argument 
        FROM mysql.general_log 
        WHERE argument NOT LIKE '%audit_ledger%'
        ORDER BY event_time ASC
    `);
    console.log(`📦 พบ Log ทั้งหมด ${rows.length} รายการ`);

    if (rows.length === 0) {
        console.log("⚠️ ไม่มี Log ให้ประมวลผล");
        await db.end();
        return;
    }

    // Row-by-Row Hash Chaining
    let previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    let groupNumber = 1;
    let rowIndex = 0;

    for (let i = 0; i < rows.length; i++) {
        const log = rows[i];
        rowIndex++;

        const content = `${log.user_host} | ${log.argument}`;
        const dataString = `${rowIndex}${log.event_time}general_log${content}${previousHash}`;
        const currentHash = crypto.createHash('sha256').update(dataString).digest('hex');

        // INSERT 1 แถว
        await db.execute(
            `INSERT INTO audit_ledger (group_number, row_index, event_time, log_source, log_content, current_hash) 
             VALUES (?, ?, ?, ?, ?, ?)`,
            [groupNumber, rowIndex, log.event_time, 'general_log', content, currentHash]
        );

        console.log(` Group ${groupNumber} | Row ${rowIndex}/20 | Hash: ${currentHash.substring(0, 16)}...`);
        previousHash = currentHash;

        // ครบ 20 → ส่ง Blockchain
        if (rowIndex >= 20) {
            const blockId = `GROUP_${groupNumber}`;
            console.log(` ส่ง ${blockId} ขึ้น Blockchain...`);

            try {
                const tx = await contract.addLog(blockId, currentHash);
                await tx.wait();

                await db.execute(
                    "UPDATE audit_ledger SET is_anchor = 1, tx_hash = ? WHERE group_number = ? AND row_index = 20",
                    [tx.hash, groupNumber]
                );

                console.log(` ${blockId} สำเร็จ! TX: ${tx.hash}`);
                groupNumber++;
                rowIndex = 0;
            } catch (err) {
                console.error(` Blockchain fail ที่ ${blockId}:`, err.message);
                await db.execute("DELETE FROM audit_ledger WHERE group_number = ?", [groupNumber]);
                break;
            }
        }
    }

    if (rowIndex > 0 && rowIndex < 20) {
        console.log(`\n เศษที่เหลือ ${rowIndex} รายการ (Group ${groupNumber}) จะถูกประมวลผลต่อโดย server.js`);
    }

    console.log(`\n✨ Initial Sync เสร็จสมบูรณ์!`);
    await db.end();
}

main().catch((error) => {
    console.error(" เกิดข้อผิดพลาด:", error);
    process.exitCode = 1;
});