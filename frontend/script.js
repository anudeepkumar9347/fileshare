let token = '';
const API_BASE = 'https://fileshare-o1fc.onrender.com'; // ✅ No trailing slash

async function register() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const res = await fetch(${API_BASE}/api/auth/register, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Registration failed');

        document.getElementById('auth-status').textContent = data.message;
    } catch (err) {
        document.getElementById('auth-status').textContent = err.message;
    }
}

async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const res = await fetch(${API_BASE}/api/auth/login, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.message || 'Login failed');

        if (data.token) {
            token = data.token;
            document.getElementById('auth-status').textContent = 'Logged in!';
            document.getElementById('auth-section').style.display = 'none';
            document.getElementById('upload-section').style.display = 'block';
            loadFiles(); // Load user files after login
        }
    } catch (err) {
        document.getElementById('auth-status').textContent = err.message;
    }
}

document.getElementById('uploadForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch(${API_BASE}/api/files/upload, {
            method: 'POST',
            headers: {
                'Authorization': Bearer ${token} // ✅ Bearer prefix required
            },
            body: formData
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.message);

        document.getElementById('result').textContent = Uploaded: ${data.fileName};
        loadFiles(); // Refresh file list
    } catch (err) {
        document.getElementById('result').textContent = 'Upload failed: ' + err.message;
    }
});

async function loadFiles() {
    try {
        const res = await fetch(${API_BASE}/api/files, {
            method: 'GET',
            headers: {
                'Authorization': Bearer ${token} // ✅ Must use Bearer here too
            }
        });

        const files = await res.json();
        const list = document.getElementById('fileList');
        list.innerHTML = '';

        files.forEach(file => {
            const li = document.createElement('li');
            li.innerHTML = `
                <a href="${API_BASE}/api/files/download/${file.fileId}" target="_blank">${file.fileName}</a>
                <button onclick="deleteFile('${file.fileId}')">Delete</button>
            `;
            list.appendChild(li);
        });
    } catch (err) {
        console.error("Error loading files:", err.message);
    }
}

async function deleteFile(id) {
    if (!confirm("Are you sure you want to delete this file?")) return;

    try {
        const res = await fetch(${API_BASE}/api/files/${id}, {
            method: 'DELETE',
            headers: {
                'Authorization': Bearer ${token} // ✅ Again, Bearer here
            }
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.message);

        alert(data.message);
        loadFiles(); // Refresh list
    } catch (err) {
        alert("Delete failed: " + err.message);
    }
}
