/**
 * Adapter Manager — ศูนย์กลางจัดการทุก Log Adapter
 * 
 * หน้าที่
 *  1. ลงทะเบียน (register) Adapter หลายประเภท
 *  2. ดึง Log จากทุก Adapter พร้อมกัน (fetchAll)
 *  3. ส่งคืนเป็น Normalized Format เดียวกันหมด
 * 
 * เมื่อต้องการเพิ่ม Log ประเภทใหม่ในอนาคต:
 *  1. สร้างไฟล์ adapter ใหม่ใน /adapters/ (extend BaseAdapter)
 *  2. register ที่นี่ใน initAdapters()

 */

class AdapterManager {
    constructor() {
        this.adapters = new Map();  // ชื่อ  adapter instance
    }

    /**
     * ลงทะเบียน Adapter ใหม่
     */
    register(adapter) {
        this.adapters.set(adapter.name, adapter);
        console.log(` [AdapterManager] ลงทะเบียน: ${adapter.name} (${adapter.enabled ? ' เปิด' : ' ปิด'})`);
    }

    /**
     * ดึง Adapter ตามชื่อ
     */
    get(name) {
        return this.adapters.get(name);
    }

    /**
     * ดึง Log จากทุก Adapter ที่เปิดใช้งาน
     * @returns {Array} — Normalized log entries จากทุกแหล่ง รวมกัน
     */
    async fetchAll() {
        const allLogs = [];

        for (const [name, adapter] of this.adapters) {
            if (!adapter.enabled) continue;

            try {
                const logs = await adapter.fetch();
                if (logs.length > 0) {
                    allLogs.push(...logs);
                }
            } catch (e) {
                console.error(` [AdapterManager] ${name} fetch error:`, e.message);
            }
        }

        // เรียงตามเวลา (เก่าสุดก่อน) เพื่อให้ Hash Chain เรียงลำดับถูกต้อง
        allLogs.sort((a, b) => new Date(a.event_time) - new Date(b.event_time));

        return allLogs;
    }

    /**
     * สรุปสถิติการทำงานของทุก Adapter
     */
    getStats() {
        const stats = {};
        for (const [name, adapter] of this.adapters) {
            stats[name] = {
                enabled: adapter.enabled,
                total: adapter.stats.total,
                errors: adapter.stats.errors,
                lastPoll: adapter.lastPollTime
            };
        }
        return stats;
    }

    /**
     * รายชื่อ Adapter ทั้งหมดที่ลงทะเบียนไว้
     */
    listAdapters() {
        return Array.from(this.adapters.entries()).map(([name, adapter]) => ({
            name,
            enabled: adapter.enabled,
            stats: adapter.stats
        }));
    }
}

module.exports = AdapterManager;
