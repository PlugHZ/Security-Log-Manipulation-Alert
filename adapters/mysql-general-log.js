/**
 * MySQL General Log Adapter
 วิธีการ Trigger: ใช้ Polling จาก mysql.general_log ทุกๆ 3 วินาที
 (PoC ใช้ Polling เพราะ MySQL general_log ไม่รองรับ Trigger โดยตรง)
 Normalization: แปลงจาก { event_time, user_host, argument } ไปเป็น Standard Format
 */
const BaseAdapter = require('./base');

class MySQLGeneralLogAdapter extends BaseAdapter {
    constructor(pool, config = {}) {
        super('mysql:general_log', config);
        this.pool = pool;
        this.lastProcessedTime = config.lastProcessedTime || '1970-01-01 00:00:00';
    }

    async poll() {
        const [logs] = await this.pool.execute(
            `SELECT event_time, user_host, argument 
             FROM mysql.general_log 
             WHERE event_time > ? 
               AND argument NOT LIKE '%audit_ledger%'
             ORDER BY event_time ASC 
             LIMIT ?`,
            [this.lastProcessedTime, String(this.config.batchLimit || 10)]
        );

        // อัปเดตเวลาล่าสุดที่ดึงมาแล้ว
        if (logs.length > 0) {
            this.lastProcessedTime = logs[logs.length - 1].event_time;
        }

        return logs;
    }

    normalize(rawLog) {
        return {
            event_time: rawLog.event_time,
            source: 'mysql:general_log',
            content: `${rawLog.user_host} | ${rawLog.argument}`,
            metadata: {
                user_host: rawLog.user_host,
                query: rawLog.argument
            }
        };
    }

    /**
     * ใช้ในตอน Audit — ตรวจสอบว่า log ยังอยู่ใน general_log จริงหรือเปล่า
     */
    async verifyLogExists(eventTime, userHost, argument) {
        const [exact] = await this.pool.execute(
            `SELECT event_time FROM mysql.general_log 
             WHERE event_time = ? AND user_host = ? AND argument = ? LIMIT 1`,
            [eventTime, userHost, argument]
        );
        return exact.length > 0;
    }
}

module.exports = MySQLGeneralLogAdapter;
