/**
  Base Adapter — คลาสแม่ ที่ทุก Log Adapter ต้อง inherit
 ทุก Adapter ต้อง implement 2 ฟังก์ชัน
    1 poll()   ดึง Log ใหม่ออกมา
    2 normalize(rawLog)  แปลงให้เป็นรูปแบบมาตรฐาน
 */
class BaseAdapter {
    constructor(name, config = {}) {
        this.name = name;           // ชื่อประเภท Log เช่น 'mysql:general_log'
        this.config = config;
        this.enabled = true;
        this.lastPollTime = null;
        this.stats = { total: 0, errors: 0 };
    }

    /**
     * ดึง Log ใหม่ออกมา (ต้อง override)
     * @returns {Array} รายการ raw log entries
     */
    async poll() {
        throw new Error(`${this.name}: poll() ยังไม่ได้ implement!`);
    }

    /**
     * แปลง raw log ให้เป็นรูปแบบมาตรฐาน (ต้อง override)
     * @param {Object} rawLog — ข้อมูล Log ดิบจาก source
     * @returns {Object} — { event_time, source, content }
     */
    normalize(rawLog) {
        throw new Error(`${this.name}: normalize() ยังไม่ได้ implement!`);
    }

    /**
     * ฟังก์ชันหลักที่ระบบเรียกใช้ — ดึง + แปลง + ส่งคืน
     * @returns {Array} — รายการ normalized log entries
     */
    async fetch() {
        if (!this.enabled) return [];
        
        try {
            const rawLogs = await this.poll();
            const normalized = [];

            for (const raw of rawLogs) {
                try {
                    const entry = this.normalize(raw);
                    if (entry) {
                        normalized.push(entry);
                        this.stats.total++;
                    }
                } catch (e) {
                    this.stats.errors++;
                    console.error(`❌ [${this.name}] normalize error:`, e.message);
                }
            }

            this.lastPollTime = new Date();
            return normalized;
        } catch (e) {
            this.stats.errors++;
            console.error(`❌ [${this.name}] poll error:`, e.message);
            return [];
        }
    }
}

module.exports = BaseAdapter;
