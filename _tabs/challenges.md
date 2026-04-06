---
layout: page
title: Challenges
icon: fas fa-flag
order: 4
---

<style>
/* ── Page header ── */
.htb-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 2rem;
  padding-bottom: 1.25rem;
  border-bottom: 1px solid var(--card-border-color, rgba(134,140,151,0.15));
}
.htb-header img {
  height: 32px;
  width: auto;
  filter: drop-shadow(0 0 6px rgba(159,239,0,0.4));
}
.htb-header span {
  font-size: 0.95rem;
  color: var(--text-muted, #868c97);
}
.htb-header strong {
  color: #9fef00;
}

/* ── Card ── */
.challenge-card {
  position: relative;
  border: 1px solid var(--card-border-color, rgba(134,140,151,0.15));
  border-left: 4px solid var(--accent, #6c757d);
  border-radius: 0.75rem;
  padding: 1.4rem 1.5rem;
  margin-bottom: 1.1rem;
  background: var(--card-bg, var(--main-bg));
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1.25rem;
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
  overflow: hidden;
}
.challenge-card::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, rgba(var(--accent-rgb),0.04) 0%, transparent 60%);
  pointer-events: none;
}
.challenge-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 24px rgba(0,0,0,0.12), 0 0 0 1px var(--accent, #6c757d);
}

/* difficulty accent colours */
.challenge-card.easy   { --accent: #2ecc71; --accent-rgb: 46,204,113; }
.challenge-card.medium { --accent: #e67e22; --accent-rgb: 230,126,34; }
.challenge-card.hard   { --accent: #e74c3c; --accent-rgb: 231,76,60; }

/* ── Icon circle ── */
.challenge-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 2.6rem;
  height: 2.6rem;
  border-radius: 0.6rem;
  background: rgba(var(--accent-rgb), 0.12);
  color: var(--accent);
  font-size: 1.1rem;
  flex-shrink: 0;
}

/* ── Info block ── */
.challenge-body {
  display: flex;
  align-items: center;
  gap: 1rem;
  flex: 1;
  min-width: 0;
}
.challenge-info {
  min-width: 0;
}
.challenge-info h3 {
  margin: 0 0 0.45rem 0;
  font-size: 1.05rem;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* ── Badges ── */
.challenge-badges {
  display: flex;
  gap: 0.4rem;
  flex-wrap: wrap;
  align-items: center;
  margin-bottom: 0.5rem;
}
.badge {
  font-size: 0.72rem;
  font-weight: 600;
  padding: 0.25em 0.6em;
  border-radius: 0.35rem;
  letter-spacing: 0.02em;
  text-transform: uppercase;
}
.badge-easy     { background: rgba(46,204,113,0.15);  color: #2ecc71;  border: 1px solid rgba(46,204,113,0.3); }
.badge-medium   { background: rgba(230,126,34,0.15);  color: #e67e22;  border: 1px solid rgba(230,126,34,0.3); }
.badge-hard     { background: rgba(231,76,60,0.15);   color: #e74c3c;  border: 1px solid rgba(231,76,60,0.3); }
.badge-category { background: rgba(134,140,151,0.12); color: var(--text-muted,#868c97); border: 1px solid rgba(134,140,151,0.25); }

/* ── Star rating ── */
.star-rating {
  display: inline-flex;
  align-items: center;
  gap: 0.12em;
  font-size: 0.8rem;
}
.star-filled, .star-half { color: #f1c40f; }
.star-empty { color: rgba(134,140,151,0.35); }
.star-score {
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--text-muted, #868c97);
  margin-left: 0.35em;
}

/* ── HTB button ── */
.challenge-link { flex-shrink: 0; }
.challenge-link a {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.45rem 1.1rem;
  border-radius: 0.5rem;
  font-size: 0.82rem;
  font-weight: 600;
  text-decoration: none;
  background: rgba(159,239,0,0.08);
  color: #9fef00;
  border: 1px solid rgba(159,239,0,0.3);
  transition: background 0.2s, box-shadow 0.2s, transform 0.15s;
  white-space: nowrap;
}
.challenge-link a:hover {
  background: rgba(159,239,0,0.18);
  box-shadow: 0 0 12px rgba(159,239,0,0.25);
  transform: scale(1.03);
}

@media (max-width: 576px) {
  .challenge-card  { flex-direction: column; align-items: flex-start; }
  .challenge-body  { width: 100%; }
}
</style>

<div class="htb-header">
  <img src="https://www.hackthebox.com/images/logo600.png" alt="HackTheBox" onerror="this.style.display='none'">
  <span>Challenges authored on <strong>HackTheBox</strong></span>
</div>

<div class="challenge-card medium">
  <div class="challenge-body">
    <div class="challenge-icon"><i class="fas fa-microchip"></i></div>
    <div class="challenge-info">
      <h3>Defusal</h3>
      <div class="challenge-badges">
        <span class="badge badge-medium">Medium</span>
        <span class="badge badge-category">Hardware</span>
      </div>
      <span class="star-rating">
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star-half-alt star-half"></i>
        <span class="star-score">4.9</span>
      </span>
    </div>
  </div>
  <div class="challenge-link">
    <a href="https://app.hackthebox.com/challenges/Defusal" target="_blank" rel="noopener">
      <i class="fas fa-external-link-alt"></i> View on HTB
    </a>
  </div>
</div>

<div class="challenge-card easy">
  <div class="challenge-body">
    <div class="challenge-icon"><i class="fas fa-gears"></i></div>
    <div class="challenge-info">
      <h3>Hubbub</h3>
      <div class="challenge-badges">
        <span class="badge badge-easy">Easy</span>
        <span class="badge badge-category">Reverse Engineering</span>
      </div>
      <span class="star-rating">
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-empty"></i>
        <span class="star-score">4.1</span>
      </span>
    </div>
  </div>
  <div class="challenge-link">
    <a href="https://app.hackthebox.com/challenges/Hubbub" target="_blank" rel="noopener">
      <i class="fas fa-external-link-alt"></i> View on HTB
    </a>
  </div>
</div>

<div class="challenge-card medium">
  <div class="challenge-body">
    <div class="challenge-icon"><i class="fas fa-magnifying-glass"></i></div>
    <div class="challenge-info">
      <h3>CrewCrow</h3>
      <div class="challenge-badges">
        <span class="badge badge-medium">Medium</span>
        <span class="badge badge-category">DFIR Sherlock</span>
      </div>
      <span class="star-rating">
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star-half-alt star-half"></i>
        <span class="star-score">4.5</span>
      </span>
    </div>
  </div>
  <div class="challenge-link">
    <a href="https://app.hackthebox.com/sherlocks/CrewCrow" target="_blank" rel="noopener">
      <i class="fas fa-external-link-alt"></i> View on HTB
    </a>
  </div>
</div>
