// main.js - for general UI enhancements

document.addEventListener("DOMContentLoaded", function() {
    // Live Clock in Footer
    const clockElement = document.getElementById("live-clock");
    if (clockElement) {
        setInterval(() => {
            const now = new Date();
            clockElement.textContent = now.toLocaleTimeString();
        }, 1000);
    }

    // Card hover effect
    const cards = document.querySelectorAll('.feature-card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            card.classList.add('shadow-lg');
        });
        card.addEventListener('mouseleave', () => {
            card.classList.remove('shadow-lg');
        });
    });
});