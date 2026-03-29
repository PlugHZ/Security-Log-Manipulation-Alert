/**
 * Webhook / External API Adapter
  วิธีการ Trigger: รับ Log จากภายนอกผ่าน HTTP POST /api/ingest
  รองรับ n8n, Zapier, Custom Webhook, หรือแอปอื่นๆ ส่งเข้ามา
  Normalization: แปลงจาก { log_source, message, event_time? } ไปเป็น Standard Format
 */
const BaseAdapter = require('./base');

class WebhookAdapter extends BaseAdapter {
    constructor(config = {}) {
        super('webhook:external', config);
        this.queue = [];  // คิวเก็บ Log ที่ยิงเข้ามาทาง API
    }

    /**
     * รับ log ใหม่จาก HTTP request body แล้วใส่คิว
     * @param {Object|Array} body — request body จาก /api/ingest
     * @returns {number} จำนวน log ที่รับเข้าคิว
     */
    ingest(body) {
        let logs = [];

        if (Array.isArray(body.logs)) {
            logs = body.logs;
        } else if (body.log_source && body.message) {
            logs = [body];
        } else {
            throw new Error('ต้องระบุ log_source และ message');
        }

        let count = 0;
        for (const log of logs) {
            if (!log.log_source || !log.message) continue;
            this.queue.push(log);
            count++;
        }

        return count;
    }

    async poll() {
        // ดึงทั้งหมดออกจาก queue ทีเดียว
        const batch = this.queue.splice(0, this.queue.length);
        return batch;
    }

    normalize(rawLog) {
        const eventTime = rawLog.event_time 
            || new Date().toISOString().slice(0, 19).replace('T', ' ');

        return {
            event_time: eventTime,
            source: `api:${rawLog.log_source}`,
            content: rawLog.message,
            metadata: {
                original_source: rawLog.log_source,
                extra: rawLog.extra || null
            }
        };
    }

    getQueueSize() {
        return this.queue.length;
    }
}

module.exports = WebhookAdapter;
