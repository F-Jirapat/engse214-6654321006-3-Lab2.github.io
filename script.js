// script.js (ปรับให้ตรงกับ db.json ของคุณ + auto-fallback ไปยัง mockUsers)

// API config
const API_BASE = 'http://localhost:3000';
const API_USERS_ENDPOINT = `${API_BASE}/users`;

// mockUsers ที่ตรงกับ db.json ของคุณ (fallback)
const mockUsers = [
    { id: 1, username: 'admin', password: 'admin123' },
    { id: 2, username: 'user1', password: 'user123' },
    { id: 3, username: 'test', password: 'test1234' }
];

// DOM elements
const vulnerableBtn = document.getElementById('vulnerableBtn');
const secureBtn = document.getElementById('secureBtn');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const resultArea = document.getElementById('result');

// ช่วยหลบ HTML เพื่อไม่ให้เกิด XSS ในการแสดงผล
function escapeHtml(str) {
    if (str === undefined || str === null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function showResult(html, type = 'info') {
    resultArea.innerHTML = html;
    resultArea.className = `result-area ${type}`;
}

// ฟังก์ชันแสดงข้อมูลผู้ใช้
function renderUserData(data) {
    if (!data) return '';
    if (Array.isArray(data)) {
        if (data.length === 0) return '<i>ไม่มีข้อมูล</i>';
        return '<b>ข้อมูลที่ถูกส่งกลับ:</b><br>' + data.map(u =>
            `- ID: ${escapeHtml(u.id)} , ชื่อผู้ใช้: ${escapeHtml(u.username)} , รหัสผ่าน: ${escapeHtml(u.password)}`
        ).join('<br>');
    } else {
        return `<b>ข้อมูล:</b> ${escapeHtml(JSON.stringify(data, null, 2))}`;
    }
}

// ตรวจจับ SQL Injection แบบ heuristic ง่ายๆ (สำหรับสาธิต)
function detectSqlInjection(input) {
    if (!input) return false;
    const lowered = input.toLowerCase();
    return (
        input.includes("'") ||
        lowered.includes(" or ") ||
        lowered.includes(" and ") ||
        lowered.includes("--") ||
        lowered.includes(";")
    );
}

/* ---------- API reachability & fetch helpers ---------- */
let useApi = false;

async function testApiReachable() {
    try {
        const resp = await fetch(API_USERS_ENDPOINT, { method: 'HEAD' });
        if (resp.ok) {
            useApi = true;
            console.info('[script] json-server detected, using API:', API_USERS_ENDPOINT);
            return true;
        }
    } catch (err) {
        console.info('[script] json-server not reachable — using mockUsers.');
    }
    useApi = false;
    return false;
}

async function fetchAllUsers() {
    if (useApi) {
        const res = await fetch(API_USERS_ENDPOINT);
        if (!res.ok) throw new Error(`API returned ${res.status}`);
        return await res.json();
    } else {
        return mockUsers.slice();
    }
}

async function fetchUserByCredentials(username, password) {
    if (useApi) {
        const url = new URL(API_USERS_ENDPOINT);
        url.searchParams.append('username', username);
        url.searchParams.append('password', password);
        const res = await fetch(url.toString());
        if (!res.ok) throw new Error(`API returned ${res.status}`);
        return await res.json(); // array
    } else {
        return mockUsers.filter(u => u.username === username && u.password === password);
    }
}

/* ---------- Vulnerable & Secure simulations ---------- */
async function runVulnerable(username, password) {
    try {
        const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
        const hasInjection = detectSqlInjection(username) || detectSqlInjection(password);
        const isClassicOR = (username.includes("' OR '1'='1") || password.includes("' OR '1'='1"));

        const users = await fetchAllUsers();

        if (hasInjection && isClassicOR) {
            const html =
                `<div class="result-header">🔴 ผลลัพธ์ของคิวรีที่มีช่องโหว่:</div><br>` +
                `<b>คิวรี:</b> ${escapeHtml(query)}<br><br>` +
                `<b>สถานะ:</b> ⚠️ มีช่องโหว่: SQL Injection สำเร็จ! (จำลอง)<br><br>` +
                `${renderUserData(users)}`;
            showResult(html, 'error');
            return;
        }

        // ปกติ: หา match
        const matched = (await fetchUserByCredentials(username, password))[0] ?? null;

        const html =
            `<div class="result-header">🔴 ผลลัพธ์ของคิวรีที่มีช่องโหว่:</div><br>` +
            `<b>คิวรี:</b> ${escapeHtml(query)}<br><br>` +
            `<b>สถานะ:</b> ${matched ? '✅ เข้าสู่ระบบสำเร็จ' : '❌ เข้าสู่ระบบไม่สำเร็จ - ข้อมูลไม่ถูกต้อง'}<br><br>` +
            (matched ? renderUserData(matched) : '');
        showResult(html, matched ? 'success' : 'error');

    } catch (err) {
        showResult(`เกิดข้อผิดพลาด: ${escapeHtml(err.message)}`, 'error');
    }
}

async function runSecure(username, password) {
    try {
        const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
        const results = await fetchUserByCredentials(username, password);
        const success = Array.isArray(results) && results.length > 0;

        const html =
            `<div class="result-header">🟢 ผลลัพธ์ของคิวรีที่ปลอดภัย:</div><br>` +
            `<b>คิวรี:</b> ${escapeHtml(query)}<br>` +
            `<b>พารามิเตอร์:</b> [${escapeHtml(username)}, ${escapeHtml(password)}]<br><br>` +
            `<b>สถานะ:</b> ${success ? '✅ เข้าสู่ระบบสำเร็จ (ปลอดภัย)' : '❌ เข้าสู่ระบบไม่สำเร็จ - ข้อมูลไม่ถูกต้อง (ปลอดภัย)'}<br><br>` +
            (success ? renderUserData(results[0]) : '');
        showResult(html, success ? 'success' : 'error');
    } catch (err) {
        showResult(`เกิดข้อผิดพลาด: ${escapeHtml(err.message)}`, 'error');
    }
}

/* ---------- Event wiring ---------- */
function resetResult() {
    showResult('กรุณากรอกชื่อผู้ใช้และรหัสผ่าน จากนั้นเลือก "คิวรีที่มีช่องโหว่" หรือ "คิวรีที่ปลอดภัย"', 'info');
}

document.addEventListener('DOMContentLoaded', async () => {
    await testApiReachable();

    if (!usernameInput.value) usernameInput.placeholder = "ลองใส่: admin' OR '1'='1' --";

    usernameInput.addEventListener('input', resetResult);
    passwordInput.addEventListener('input', resetResult);

    vulnerableBtn.addEventListener('click', async () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        if (!username || !password) {
            showResult('❗ โปรดระบุชื่อผู้ใช้และรหัสผ่าน', 'error');
            return;
        }
        if (detectSqlInjection(username) || detectSqlInjection(password)) {
            showResult('⚠️ พบ pattern ที่อาจเป็น SQL Injection — จะรัน query ที่มีช่องโหว่เพื่อสาธิต...', 'warning');
            setTimeout(() => runVulnerable(username, password), 600);
        } else {
            await runVulnerable(username, password);
        }
    });

    secureBtn.addEventListener('click', async () => {
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        if (!username || !password) {
            showResult('❗ โปรดระบุชื่อผู้ใช้และรหัสผ่าน', 'error');
            return;
        }
        await runSecure(username, password);
    });

    // keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === '1') {
            e.preventDefault();
            vulnerableBtn.click();
        } else if (e.ctrlKey && e.key === '2') {
            e.preventDefault();
            secureBtn.click();
        }
    });

    resetResult();
});
