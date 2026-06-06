// CyberGuardian — Live Elements

// Matrix Rain Background
function initMatrixRain() {
    var canvas = document.getElementById('matrix-canvas');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    var chars = '01アカサタナハマヤラワABCDEFGH0123456789#@!?<>$%';
    var fontSize = 14;
    var columns = Math.floor(canvas.width / fontSize);
    var drops = [];
    for (var i = 0; i < columns; i++) drops[i] = Math.random() * canvas.height / fontSize;

    function draw() {
        ctx.fillStyle = 'rgba(5, 8, 22, 0.07)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00ff88';
        ctx.font = fontSize + "px 'Share Tech Mono', monospace";
        for (var i = 0; i < drops.length; i++) {
            var text = chars.charAt(Math.floor(Math.random() * chars.length));
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
            drops[i]++;
        }
    }

    setInterval(draw, 50);

    window.addEventListener('resize', function() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// Live Clock
function initLiveClock() {
    var clockEl = document.getElementById('live-clock');
    if (!clockEl) return;

    function updateClock() {
        var now = new Date();
        var h = String(now.getHours()).padStart(2, '0');
        var m = String(now.getMinutes()).padStart(2, '0');
        var s = String(now.getSeconds()).padStart(2, '0');
        var d = String(now.getDate()).padStart(2, '0');
        var mo = String(now.getMonth() + 1).padStart(2, '0');
        var y = now.getFullYear();
        clockEl.innerHTML = d + '/' + mo + '/' + y + ' <span class="clock-dot">|</span> ' + h + ':' + m + ':' + s;
    }

    updateClock();
    setInterval(updateClock, 1000);
}

// Animated Counter
function animateCounter(el, target, duration, suffix) {
    suffix = suffix || '';
    var start = 0;
    var startTime = null;
    function step(timestamp) {
        if (!startTime) startTime = timestamp;
        var progress = Math.min((timestamp - startTime) / duration, 1);
        var value = Math.floor(progress * (target - start) + start);
        el.innerText = value + suffix;
        if (progress < 1) requestAnimationFrame(step);
        else el.innerText = target + suffix;
    }
    requestAnimationFrame(step);
}

function initCounters() {
    var counters = document.querySelectorAll('[data-counter]');
    counters.forEach(function(el) {
        var target = parseFloat(el.getAttribute('data-counter'));
        var suffix = el.getAttribute('data-suffix') || '';
        animateCounter(el, target, 1200, suffix);
    });
}

// System Status Bar — fake real-time metrics
function initStatusBar() {
    var cpuEl = document.getElementById('status-cpu');
    var memEl = document.getElementById('status-mem');
    var netEl = document.getElementById('status-net');

    function tick() {
        if (cpuEl) cpuEl.innerText = (15 + Math.random() * 20).toFixed(1) + '%';
        if (memEl) memEl.innerText = (40 + Math.random() * 10).toFixed(1) + '%';
        if (netEl) netEl.innerText = (Math.random() * 500).toFixed(0) + ' KB/s';
    }
    tick();
    setInterval(tick, 2000);
}

// Initialize on load
document.addEventListener('DOMContentLoaded', function() {
    initMatrixRain();
    initLiveClock();
    initCounters();
    initStatusBar();
});
