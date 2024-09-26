document.getElementById('lock-btn').addEventListener('click', function() {
    fetch('/lock', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message));
});

document.getElementById('unlock-btn').addEventListener('click', function() {
    fetch('/unlock', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message));
});
