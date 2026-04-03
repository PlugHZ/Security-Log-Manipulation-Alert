/**
 * Windows Event Viewer Adapter 
  วิธีการ Trigger ใช้ PowerShell Get-WinEvent ดึง Event ใหม่ทุก 15 วินาที
  รองรับ Channel Application, System
  (Security ต้องใช้สิทธิ์ Admin เปิดใช้ได้ถ้ารัน server เป็น Admin)
  Normalization แปลงจาก { TimeCreated, Id, LevelDisplayName, Message } ไปเป็น Standard Format
 */
const BaseAdapter = require('./base');
const { execSync } = require('child_process');

class WindowsEventAdapter extends BaseAdapter {
    constructor(config = {}) {
        super('windows:event', config);
        this.channels = config.channels || ['Application', 'System'];
        this.maxEvents = config.maxEvents || 5;
        this.lastPollTimeISO = new Date(Date.now() - 60000).toISOString();

        // ตรวจสอบว่ารันบน Windows หรือเปล่า
        if (process.platform !== 'win32') {
            this.enabled = false;
            console.log(` [${this.name}] ปิดใช้งาน (ไม่ใช่ Windows)`);
        }
    }

    async poll() {
        if (!this.enabled) return [];

        const allEvents = [];

        for (const channel of this.channels) {
            try {
                const cmd = `powershell -Command "Get-WinEvent -LogName '${channel}' -MaxEvents ${this.maxEvents} -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt '${this.lastPollTimeISO}' } | Select-Object TimeCreated, Id, LevelDisplayName, Message | ConvertTo-Json -Compress"`;
                
                const output = execSync(cmd, { timeout: 10000, encoding: 'utf-8' });
                if (!output || output.trim() === '') continue;

                let events = JSON.parse(output);
                if (!Array.isArray(events)) events = [events];

                for (const evt of events) {
                    if (!evt.Message) continue;
                    allEvents.push({
                        ...evt,
                        _channel: channel  // แปะ channel ไว้ให้ normalize ใช้
                    });
                }

                if (events.length > 0) {
                    console.log(` [windows:${channel}] ดึง ${events.length} events`);
                }
            } catch (e) {
                // ไม่ทำอะไรถ้าไม่มีสิทธิ์หรือไม่มี event ใหม่
            }
        }

        this.lastPollTimeISO = new Date().toISOString();
        return allEvents;
    }

    normalize(rawLog) {
        let ts = rawLog.TimeCreated;
        // PowerShell 5.1 ConvertTo-Json ส่งวันที่มาในรูปแบบ "/Date(1234567890)/"
        if (typeof ts === 'string' && ts.includes('/Date(')) {
            const match = ts.match(/\d+/);
            if (match) ts = parseInt(match[0], 10);
        }

        let eventTime;
        try {
            eventTime = new Date(ts).toISOString().slice(0, 19).replace('T', ' ');
        } catch (e) {
            // สำรองกรณีเกิด Error แปลกๆ อีก
            eventTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
        }
        
        const channel = rawLog._channel || 'Unknown';
        const level = rawLog.LevelDisplayName || 'INFO';
        const eventId = rawLog.Id || 0;
        const message = (rawLog.Message || '').substring(0, 300); // ตัดให้ไม่ยาวเกินไป

        return {
            event_time: eventTime,
            source: `windows:${channel}`,
            content: `[${level}] EventID:${eventId} | ${message}`,
            metadata: {
                channel: channel,
                level: level,
                eventId: eventId,
                fullMessage: rawLog.Message
            }
        };
    }
}

module.exports = WindowsEventAdapter;
