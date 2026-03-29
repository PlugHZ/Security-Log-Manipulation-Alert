require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const { ethers } = require('ethers');
const crypto = require('crypto');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

// ===== Adapter Pattern =====
const AdapterManager = require('./adapters/manager');
const MySQLGeneralLogAdapter = require('./adapters/mysql-general-log');
const WindowsEventAdapter = require('./adapters/windows-event');
const WebhookAdapter = require('./adapters/webhook');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('frontend'));  // เสิร์ฟไฟล์รูป/CSS ในโฟลเดอร์ frontend

// เสิร์ฟแดชบอร์ดและจับยัด API_KEY จาก .env ให้โดยตรง
app.get('/dashboard', (req, res) => {
    try {
        const filePath = path.join(__dirname, 'frontend', 'dashboard.html');
        let html = fs.readFileSync(filePath, 'utf-8');
        html = html.replace('{{INJECT_API_KEY}}', process.env.API_KEY || '');
        res.send(html);
    } catch (e) {
        res.status(500).send('File not found');
    }
});

//  LINE Messaging API 
const LINE_CHANNEL_TOKEN = process.env.LINE_CHANNEL_TOKEN;
const LINE_USER_ID = process.env.LINE_USER_ID;
const notifiedGroups = new Set();

async function sendLineAlert(groupNum, auditHash, blockchainHash, reason) {
    if (!LINE_CHANNEL_TOKEN || !LINE_USER_ID) return;
    if (notifiedGroups.has(groupNum)) return;

    const message = ` SECURITY ALERT \n\nพบการดัดแปลง Log!\n Group: ${groupNum}\n สาเหตุ: ${reason}\n Audit Hash: ${auditHash ? auditHash.substring(0, 20) + '...' : 'N/A'}\n Blockchain Hash: ${blockchainHash ? blockchainHash.substring(0, 20) + '...' : 'N/A'}\n เวลา: ${new Date().toLocaleString('th-TH')}\n\n⚠️ Log ในฐานข้อมูลไม่ตรงกับ Blockchain!`;

    try {
        const res = await fetch('https://api.line.me/v2/bot/message/push', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${LINE_CHANNEL_TOKEN}` },
            body: JSON.stringify({ to: LINE_USER_ID, messages: [{ type: 'text', text: message }] })
        });
        if (res.ok) {
            notifiedGroups.add(groupNum);
            console.log(` LINE แจ้งเตือน Group ${groupNum} สำเร็จ!`);
        } else {
            const err = await res.json();
            console.error(` LINE Error:`, err.message || JSON.stringify(err));
        }
    } catch (e) {
        console.error(` LINE ส่งไม่ได้:`, e.message);
    }
}

//  Middleware 
const API_KEY = process.env.API_KEY;
function authMiddleware(req, res, next) {
    const key = req.headers['x-api-key'] || req.query.apiKey;
    if (API_KEY && key !== API_KEY) return res.status(401).json({ error: 'API Key ไม่ถูกต้อง' });
    next();
}
app.use('/api', authMiddleware);

//  Database 
const pool = mysql.createPool({
    host: process.env.DB_HOST, user: process.env.DB_USER,
    password: process.env.DB_PASS, database: process.env.DB_NAME,
    dateStrings: true, waitForConnections: true, connectionLimit: 10
});

//  Blockchain 
const provider = new ethers.JsonRpcProvider(process.env.INFURA_URL || process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const abi = [
    "function storeBatch(string memory _blockId, string memory _batchHash, string memory _masterHash, uint256 _recordCount) public",
    "function getLog(string memory _blockId) public view returns (string memory batchHash, string memory masterHash, uint256 recordCount, uint256 timestamp, address recorder)",
    "function totalGroups() public view returns (uint256)"
];
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, abi, wallet);

//  Config 
const BATCH_SIZE = parseInt(process.env.BATCH_SIZE) || 20;
const TIME_TRIGGER_MS = 5 * 60 * 1000;

//  State (In-Memory) 
let currentGroupNumber = 1;
let currentRowIndex = 0;
let previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
let previousMasterHash = '0000000000000000000000000000000000000000000000000000000000000000';
let lastCommitTime = Date.now();
let isProcessing = false;
let isAuditing = false;
let serverRunning = true;

//  Adapter Manager (ศูนย์กลาง Log ทุกประเภท) 
const adapterManager = new AdapterManager();
let webhookAdapter; // เก็บ reference ไว้ใช้ใน API route

//  1เริ่มต้น Server 
async function initServer() {
    try {
        await pool.execute("DROP TABLE IF EXISTS audit_ledger"); //  ล้างตารางเก่าเพื่อเพิ่มคอลัมน์ record_count
        // สร้างตาราง audit_ledger (ถ้ายังไม่มี)
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS audit_ledger (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                group_number INT NOT NULL,
                row_index INT NOT NULL,
                event_time DATETIME(6) NOT NULL,
                log_source VARCHAR(100) NOT NULL,
                log_content TEXT NOT NULL,
                current_hash VARCHAR(64) NOT NULL,
                master_hash VARCHAR(64),
                record_count INT,
                is_anchor TINYINT DEFAULT 0,
                tx_hash VARCHAR(100),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_alert TINYINT DEFAULT 0,
                alert_reason VARCHAR(200),
                tamper_first_detected_at DATETIME,
                INDEX idx_group (group_number),
                INDEX idx_event_time (event_time)
            )
        `);

        // ดึง state ล่าสุดจาก audit_ledger (กรณี restart)
        const [lastRow] = await pool.execute(
            "SELECT group_number, row_index, current_hash, event_time FROM audit_ledger ORDER BY id DESC LIMIT 1"
        );

        let lastProcessedTime = '1970-01-01 00:00:00';

        if (lastRow.length > 0) {
            const last = lastRow[0];
            previousHash = last.current_hash;
            lastProcessedTime = last.event_time;

            if (last.row_index >= BATCH_SIZE) {
                currentGroupNumber = last.group_number + 1;
                currentRowIndex = 0;
            } else {
                currentGroupNumber = last.group_number;
                currentRowIndex = last.row_index;
            }

            const [lastAnchor] = await pool.execute(
                "SELECT master_hash FROM audit_ledger WHERE is_anchor = 1 ORDER BY id DESC LIMIT 1"
            );
            if (lastAnchor.length > 0 && lastAnchor[0].master_hash) {
                previousMasterHash = lastAnchor[0].master_hash;
            }
        }

        
        //  ลงทะเบียน Adapters ทั้งหมด
        
        // Adapter 1 MySQL General Log
        const mysqlAdapter = new MySQLGeneralLogAdapter(pool, {
            lastProcessedTime: lastProcessedTime,
            batchLimit: 10
        });
        adapterManager.register(mysqlAdapter);

        // Adapter 2 Windows Event Viewer
        const windowsAdapter = new WindowsEventAdapter({
            channels: ['Application', 'System', 'Security'],
            maxEvents: 5
        });
        adapterManager.register(windowsAdapter);

        // Adapter 3 Webhook / External API
        webhookAdapter = new WebhookAdapter();
        adapterManager.register(webhookAdapter);

        console.log(` ระบบพร้อม! Group: ${currentGroupNumber}, Row: ${currentRowIndex}/${BATCH_SIZE}`);
        console.log(` Master Hash (RAM): ${previousMasterHash.substring(0, 16)}...`);
        console.log(` Adapters ลงทะเบียน: ${adapterManager.listAdapters().length} ตัว`);
    } catch (error) {
        console.error(" เชื่อมต่อฐานข้อมูลไม่ได้:", error.message);
        process.exit(1);
    }
}

//  2. Ingest ผ่าน Adapter Manager (รองรับ Log ทุกประเภท!)
async function processNextLog() {
    if (isProcessing || !serverRunning) return;
    try {
        isProcessing = true;

        // ดึง Log จากทุก Adapter ทีเดียว (MySQL, Windows, Webhook)
        const normalizedLogs = await adapterManager.fetchAll();

        // Hash Chaining ทีละ Log
        for (const logEntry of normalizedLogs) {
            currentRowIndex++;
            const dataString = `${currentRowIndex}${logEntry.event_time}${logEntry.source}${logEntry.content}${previousHash}`;
            const currentHash = crypto.createHash('sha256').update(dataString).digest('hex');

            await pool.execute(
                `INSERT INTO audit_ledger (group_number, row_index, event_time, log_source, log_content, current_hash) 
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [currentGroupNumber, currentRowIndex, logEntry.event_time, logEntry.source, logEntry.content, currentHash]
            );

            console.log(` [${logEntry.source}] Group ${currentGroupNumber} | Row ${currentRowIndex}/${BATCH_SIZE} | Hash: ${currentHash.substring(0, 16)}...`);
            previousHash = currentHash;

            //  Dual Trigger: ครบ BATCH_SIZE → ส่งเชนทันที 
            if (currentRowIndex >= BATCH_SIZE) {
                await commitToBlockchain("ครบ " + BATCH_SIZE + " logs");
            }
        }

        //  Time Trigger: ยังไม่ครบ แต่เกิน 5 นาที 
        const timePassedMs = Date.now() - lastCommitTime;
        if (currentRowIndex > 0 && timePassedMs >= TIME_TRIGGER_MS) {
            await commitToBlockchain("ครบ 5 นาที");
        }

    } catch (error) {
        console.error(" processNextLog Error:", error.message);
    } finally {
        isProcessing = false;
    }
}

//  2.1  แยกฟังก์ชัน Commit ขึ้น Blockchain 
async function commitToBlockchain(triggerReason) {
    const blockId = `GROUP_${currentGroupNumber}`;
    const recordCount = currentRowIndex;
    const newMasterHash = crypto.createHash('sha256').update(previousHash + previousMasterHash).digest('hex');

    console.log(` Trigger (${triggerReason}): ส่ง ${blockId} (${recordCount} records) ขึ้น Blockchain...`);

    try {
        if (process.env.CONTRACT_ADDRESS) {
            const tx = await contract.storeBatch(blockId, previousHash, newMasterHash, recordCount);
            await tx.wait();
            console.log(` บันทึกสำเร็จ! TX: ${tx.hash}`);

            await pool.execute(
                "UPDATE audit_ledger SET is_anchor = 1, tx_hash = ?, master_hash = ?, record_count = ? WHERE group_number = ? AND row_index = ?",
                [tx.hash, newMasterHash, recordCount, currentGroupNumber, currentRowIndex]
            );
        } else {
            console.log(` ไม่พบ CONTRACT_ADDRESS`);
            await pool.execute(
                "UPDATE audit_ledger SET is_anchor = 1, master_hash = ?, record_count = ? WHERE group_number = ? AND row_index = ?",
                [newMasterHash, recordCount, currentGroupNumber, currentRowIndex]
            );
        }

        previousMasterHash = newMasterHash;
        currentGroupNumber++;
        currentRowIndex = 0;
        lastCommitTime = Date.now();
    } catch (bcError) {
        console.error(` Blockchain fail!`, bcError.message);
    }
}

//  3 Audit: ตรวจ Hash Chain + Sequence + Count
async function runAudit() {
    if (isAuditing) return;
    try {
        isAuditing = true;

        const [allGroups] = await pool.execute(
            "SELECT DISTINCT group_number FROM audit_ledger WHERE is_anchor = 1 ORDER BY group_number ASC"
        );
        if (allGroups.length === 0) return;

        console.log(` [Audit] ตรวจสอบ ${allGroups.length} groups...`);
        let calcMasterHash = '0000000000000000000000000000000000000000000000000000000000000000';

        for (const gn of allGroups) {
            const groupNum = gn.group_number;
            const [rows] = await pool.execute(
                "SELECT * FROM audit_ledger WHERE group_number = ? ORDER BY row_index ASC", [groupNum]
            );
            if (rows.length === 0) continue;

            // CHECK 1 Sequence
            for (let i = 0; i < rows.length; i++) {
                if (rows[i].row_index !== i + 1) {
                    const reason = `Sequence gap: expected ${i + 1}, got ${rows[i].row_index}`;
                    console.log(` [Sequence] Group ${groupNum}: ${reason}`);
                    await pool.execute("UPDATE audit_ledger SET is_alert = 1, alert_reason = ?, tamper_first_detected_at = COALESCE(tamper_first_detected_at, NOW()) WHERE group_number = ?", [reason, groupNum]);
                    await sendLineAlert(groupNum, null, null, reason);
                    break;
                }
            }

            // CHECK 2 Count (เทียบกับ Blockchain)
            if (process.env.CONTRACT_ADDRESS) {
                try {
                    const onChain = await contract.getLog(`GROUP_${groupNum}`);
                    const onChainCount = Number(onChain.recordCount);
                    if (onChainCount !== rows.length) {
                        const reason = `Count mismatch: DB=${rows.length}, Blockchain=${onChainCount}`;
                        console.log(` [Count] Group ${groupNum}: ${reason}`);
                        await pool.execute("UPDATE audit_ledger SET is_alert = 1, alert_reason = ?, tamper_first_detected_at = COALESCE(tamper_first_detected_at, NOW()) WHERE group_number = ?", [reason, groupNum]);
                        await sendLineAlert(groupNum, null, null, reason);
                        continue;
                    }
                } catch (e) {
                    if (!e.message.includes("Block not found")) console.error(`Count check err:`, e.message);
                }
            }

            // CHECK 3 Hash Chain (Re-hash แล้วเทียบ)
            let calcBatchHash = '0000000000000000000000000000000000000000000000000000000000000000';
            for (const row of rows) {
                let content = row.log_content;

                // ถ้าเป็น MySQL log → ไปตรวจของจริงใน general_log
                if (row.log_source === 'mysql:general_log') {
                    const parts = content.split(' | ');
                    const userHost = parts[0] || '';
                    const argument = parts.slice(1).join(' | ') || '';
                    const mysqlAdapter = adapterManager.get('mysql:general_log');
                    if (mysqlAdapter) {
                        const exists = await mysqlAdapter.verifyLogExists(row.event_time, userHost, argument);
                        if (!exists) content = 'DELETED_OR_MODIFIED';
                    }
                }
                // Log ประเภทอื่น (Windows, Webhook) → ใช้ข้อมูลจาก audit_ledger ตรงๆ
                // (เพราะ source ต้นทางไม่ได้อยู่ใน DB เดียวกัน)

                const dataString = `${row.row_index}${row.event_time}${row.log_source}${content}${calcBatchHash}`;
                calcBatchHash = crypto.createHash('sha256').update(dataString).digest('hex');
            }

            calcMasterHash = crypto.createHash('sha256').update(calcBatchHash + calcMasterHash).digest('hex');

            // เทียบกับ Blockchain
            if (process.env.CONTRACT_ADDRESS) {
                try {
                    const onChain = await contract.getLog(`GROUP_${groupNum}`);
                    if (onChain.masterHash !== calcMasterHash) {
                        const reason = 'Master Hash mismatch with Blockchain!';
                        console.log(` [Hash] Group ${groupNum}: ${reason}`);
                        await pool.execute("UPDATE audit_ledger SET is_alert = 1, alert_reason = ?, tamper_first_detected_at = COALESCE(tamper_first_detected_at, NOW()) WHERE group_number = ?", [reason, groupNum]);
                        await sendLineAlert(groupNum, calcMasterHash, onChain.masterHash, reason);
                        break;
                    } else {
                        await pool.execute("UPDATE audit_ledger SET is_alert = 0 WHERE group_number = ? AND is_alert = 1", [groupNum]);
                    }
                } catch (e) {
                    if (!e.message.includes("Block not found")) console.error(`Audit err:`, e.message);
                }
            }
            await new Promise(resolve => setTimeout(resolve, 500));
        }
        console.log(` [Audit] ตรวจสอบครบ ${allGroups.length} groups`);
    } catch (err) {
        console.error("Audit error:", err.message);
    } finally {
        isAuditing = false;
    }
}

//  4 API: รับ Log จากภายนอก (ผ่าน Webhook Adapter)
app.post('/api/ingest', (req, res) => {
    try {
        const count = webhookAdapter.ingest(req.body);
        console.log(` รับ ${count} log จาก API (Queue: ${webhookAdapter.getQueueSize()})`);
        res.json({ success: true, received: count, queueSize: webhookAdapter.getQueueSize() });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

//  5 API: Dashboard Status
app.get('/api/get-status', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const offset = (page - 1) * limit;

        const [rows] = await pool.execute("SELECT * FROM audit_ledger ORDER BY id DESC LIMIT ? OFFSET ?", [String(limit), String(offset)]);
        const [countResult] = await pool.execute("SELECT COUNT(*) as total FROM audit_ledger");
        const [groups] = await pool.execute(`SELECT group_number, COUNT(*) as row_count, MAX(is_anchor) as has_anchor, MAX(is_alert) as has_alert FROM audit_ledger GROUP BY group_number ORDER BY group_number DESC LIMIT 10`);

        res.json({
            rows, groups,
            state: { currentGroup: currentGroupNumber, currentRow: currentRowIndex, batchSize: BATCH_SIZE, queueSize: webhookAdapter.getQueueSize() },
            adapters: adapterManager.getStats(),
            pagination: { page, limit, total: countResult[0].total, totalPages: Math.ceil(countResult[0].total / limit) }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

//  6 API: Report
app.get('/api/report', async (req, res) => {
    try {
        const [groups] = await pool.execute(`SELECT group_number, COUNT(*) as row_count, MIN(event_time) as start_time, MAX(event_time) as end_time, MAX(is_anchor) as has_anchor, MAX(is_alert) as has_alert FROM audit_ledger GROUP BY group_number ORDER BY group_number ASC`);
        const report = [];

        for (const g of groups) {
            const [anchorRow] = await pool.execute("SELECT current_hash, master_hash, record_count, tx_hash FROM audit_ledger WHERE group_number = ? AND is_anchor = 1 LIMIT 1", [g.group_number]);
            let onChainStatus = 'NOT_ON_CHAIN', blockchainHash = null, blockchainCount = null;

            if (anchorRow.length > 0 && process.env.CONTRACT_ADDRESS) {
                try {
                    const onChain = await contract.getLog(`GROUP_${g.group_number}`);
                    blockchainHash = onChain.masterHash;
                    blockchainCount = Number(onChain.recordCount);
                    const hashMatch = anchorRow[0].master_hash === blockchainHash;
                    const countMatch = g.row_count === blockchainCount;
                    onChainStatus = (hashMatch && countMatch) ? 'MATCH' : (!hashMatch ? 'HASH_MISMATCH' : 'COUNT_MISMATCH');
                } catch (e) {
                    onChainStatus = e.message.includes("Block not found") ? 'PENDING' : 'ERROR';
                }
            }

            let alertRows = [];
            if (g.has_alert === 1) {
                const [aRows] = await pool.execute("SELECT row_index, event_time, log_source, log_content, current_hash, alert_reason, tamper_first_detected_at FROM audit_ledger WHERE group_number = ? AND is_alert = 1 ORDER BY row_index ASC", [g.group_number]);
                alertRows = aRows;
            }

            report.push({
                group_number: g.group_number, row_count: g.row_count, blockchain_count: blockchainCount,
                start_time: g.start_time, end_time: g.end_time, has_anchor: g.has_anchor === 1,
                audit_hash: anchorRow.length > 0 ? anchorRow[0].master_hash : null,
                tx_hash: anchorRow.length > 0 ? anchorRow[0].tx_hash : null,
                blockchain_hash: blockchainHash, status: onChainStatus, alert_rows: alertRows
            });
        }
        res.json({ report, generatedAt: new Date().toISOString() });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

//  7. API: Adapter Stats & Config
app.get('/api/config', (req, res) => {
    res.json({
        contractAddress: process.env.CONTRACT_ADDRESS,
        rpcUrl: process.env.INFURA_URL,
        batchSize: BATCH_SIZE,
        timeTriggerMinutes: TIME_TRIGGER_MS / 60000,
        adapters: adapterManager.listAdapters()
    });
});

//  8. Boot!
let intervals = [];

initServer().then(() => {
    intervals.push(setInterval(processNextLog, 3000));         // ดึง Log ทุก 3 วิ
    intervals.push(setInterval(runAudit, 5 * 60 * 1000));      // Audit ทุก 5 นาที

    console.log(` Batch: ${BATCH_SIZE} logs/group | Time Trigger: ${TIME_TRIGGER_MS / 60000} นาที`);
    console.log(` ตรวจ 3 ชั้น: Hash Chain | Sequence | Count`);
    console.log(` Adapters: MySQL | Windows | Webhook`);
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(` Security Log Guard v3 (Port ${PORT}) — Multi-Source Adapter Pattern `);
});

//  9. Graceful Shutdown
function gracefulShutdown(signal) {
    console.log(`\n ${signal} — กำลังปิด...`);
    serverRunning = false;
    intervals.forEach(id => clearInterval(id));
    const waitForFinish = setInterval(async () => {
        if (!isProcessing && !isAuditing) {
            clearInterval(waitForFinish);
            await pool.end();
            console.log(' ปิดระบบเรียบร้อย!');
            process.exit(0);
        }
    }, 500);
    setTimeout(() => { process.exit(1); }, 10000);
}
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));