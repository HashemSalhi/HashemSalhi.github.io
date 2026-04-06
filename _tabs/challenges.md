---
layout: page
title: Challenges
icon: fas fa-flag
order: 4
---

<style>
.challenge-card {
  border: 1px solid var(--card-border-color, rgba(134, 140, 151, 0.15));
  border-radius: 0.75rem;
  padding: 1.5rem;
  margin-bottom: 1.25rem;
  background: var(--card-bg, var(--main-bg));
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
}
.challenge-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}
.challenge-info h3 {
  margin: 0 0 0.5rem 0;
  font-size: 1.15rem;
}
.challenge-badges {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  align-items: center;
  margin-bottom: 0.5rem;
}
.challenge-badges .badge {
  font-size: 0.78rem;
  font-weight: 500;
  padding: 0.3em 0.65em;
  border-radius: 0.4rem;
}
.badge-easy { background-color: #2ecc71; color: #fff; }
.badge-medium { background-color: #e67e22; color: #fff; }
.badge-hard { background-color: #e74c3c; color: #fff; }
.badge-category { background-color: var(--badge-color, #6c757d); color: #fff; }
.badge-solves {
  display: inline-flex;
  align-items: center;
  gap: 0.3em;
  font-size: 0.78rem;
  font-weight: 500;
  padding: 0.3em 0.65em;
  border-radius: 0.4rem;
  background-color: rgba(100, 149, 237, 0.15);
  color: var(--link-color, #6495ed);
  border: 1px solid rgba(100, 149, 237, 0.3);
}
.challenge-meta {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin-top: 0.4rem;
}
.star-rating {
  display: inline-flex;
  gap: 0.1em;
  font-size: 0.85rem;
  line-height: 1;
}
.star-rating .star-filled { color: #f1c40f; }
.star-rating .star-empty  { color: rgba(134, 140, 151, 0.4); }
.challenge-link {
  flex-shrink: 0;
}
.challenge-link a {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 1rem;
  border: 1px solid var(--link-color);
  border-radius: 0.5rem;
  font-size: 0.85rem;
  text-decoration: none;
  color: var(--link-color);
  transition: background 0.2s, color 0.2s;
}
.challenge-link a:hover {
  background: var(--link-color);
  color: var(--main-bg, #fff);
}
@media (max-width: 576px) {
  .challenge-card {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>

Challenges I've authored on [HackTheBox](https://www.hackthebox.com){:target="_blank"}.

<div class="challenge-card">
  <div class="challenge-info">
    <h3><i class="fas fa-microchip me-2"></i>Defusal</h3>
    <div class="challenge-badges">
      <span class="badge badge-medium">Medium</span>
      <span class="badge badge-category">Hardware</span>
    </div>
    <div class="challenge-meta">
      <span class="badge-solves"><i class="fas fa-users"></i> 167 Solves</span>
      <span class="star-rating">
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-empty"></i>
      </span>
    </div>
  </div>
  <div class="challenge-link">
    <a href="https://app.hackthebox.com/challenges/Defusal" target="_blank" rel="noopener">
      <i class="fas fa-external-link-alt"></i> View on HTB
    </a>
  </div>
</div>

<div class="challenge-card">
  <div class="challenge-info">
    <h3><i class="fas fa-gears me-2"></i>Hubbub</h3>
    <div class="challenge-badges">
      <span class="badge badge-easy">Easy</span>
      <span class="badge badge-category">Reverse Engineering</span>
    </div>
    <div class="challenge-meta">
      <span class="badge-solves"><i class="fas fa-users"></i> 312 Solves</span>
      <span class="star-rating">
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
      </span>
    </div>
  </div>
  <div class="challenge-link">
    <a href="https://app.hackthebox.com/challenges/Hubbub" target="_blank" rel="noopener">
      <i class="fas fa-external-link-alt"></i> View on HTB
    </a>
  </div>
</div>

<div class="challenge-card">
  <div class="challenge-info">
    <h3><i class="fas fa-magnifying-glass me-2"></i>CrewCrow</h3>
    <div class="challenge-badges">
      <span class="badge badge-medium">Medium</span>
      <span class="badge badge-category">DFIR Sherlock</span>
    </div>
    <div class="challenge-meta">
      <span class="badge-solves"><i class="fas fa-users"></i> 89 Solves</span>
      <span class="star-rating">
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-filled"></i>
        <i class="fas fa-star star-empty"></i>
      </span>
    </div>
  </div>
  <div class="challenge-link">
    <a href="https://app.hackthebox.com/sherlocks/CrewCrow" target="_blank" rel="noopener">
      <i class="fas fa-external-link-alt"></i> View on HTB
    </a>
  </div>
</div>
