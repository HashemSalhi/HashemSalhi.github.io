---
# the default layout is 'page'
icon: fas fa-info-circle
order: 5
---

<style>
/* ── Section heading ── */
.section-heading {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  font-size: 1.1rem;
  font-weight: 700;
  margin: 2.5rem 0 1.25rem 0;
  color: var(--heading-color, inherit);
}
.section-heading i {
  color: #9fef00;
  font-size: 1rem;
}
.section-heading::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--card-border-color, rgba(134,140,151,0.2));
  margin-left: 0.5rem;
}

/* ── Cert grid ── */
.cert-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}

/* ── Cert card ── */
.cert-card {
  position: relative;
  border: 1px solid var(--card-border-color, rgba(134,140,151,0.15));
  border-radius: 0.75rem;
  padding: 1.25rem 1rem 1rem;
  background: var(--card-bg, var(--main-bg));
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
  text-decoration: none !important;
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
  overflow: hidden;
}
.cert-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
  background: linear-gradient(90deg, #9fef00, #00c8f8);
  opacity: 0;
  transition: opacity 0.2s ease;
}
.cert-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 24px rgba(0,0,0,0.12);
  border-color: rgba(159,239,0,0.3);
}
.cert-card:hover::before {
  opacity: 1;
}

/* ── Badge image placeholder ── */
.cert-img-wrap {
  width: 80px;
  height: 80px;
  border-radius: 0.5rem;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(159,239,0,0.06);
  border: 1px solid rgba(159,239,0,0.15);
}
.cert-img-wrap img {
  width: 100%;
  height: 100%;
  object-fit: contain;
  padding: 6px;
}
.cert-img-placeholder {
  font-size: 2rem;
  color: rgba(159,239,0,0.4);
}

/* ── Cert name ── */
.cert-name {
  font-size: 0.82rem;
  font-weight: 700;
  text-align: center;
  color: var(--heading-color, inherit);
  line-height: 1.3;
}
.cert-issuer {
  font-size: 0.7rem;
  color: var(--text-muted, #868c97);
  text-align: center;
}

/* ── "Verify" label ── */
.cert-verify {
  font-size: 0.68rem;
  color: #9fef00;
  display: flex;
  align-items: center;
  gap: 0.25em;
  opacity: 0;
  transition: opacity 0.2s;
}
.cert-card:hover .cert-verify {
  opacity: 1;
}

@media (max-width: 480px) {
  .cert-grid { grid-template-columns: repeat(2, 1fr); }
}
</style>

<div class="section-heading">
  <i class="fas fa-certificate"></i> Certifications
</div>

<div class="cert-grid">

  <a class="cert-card" href="#" target="_blank" rel="noopener" title="CCDL2">
    <div class="cert-img-wrap">
      <i class="fas fa-shield-alt cert-img-placeholder"></i>
    </div>
    <div class="cert-name">CCDL2</div>
    <div class="cert-issuer"><!-- Issuer --></div>
    <span class="cert-verify"><i class="fas fa-external-link-alt"></i> Verify</span>
  </a>

  <a class="cert-card" href="#" target="_blank" rel="noopener" title="eCIR">
    <div class="cert-img-wrap">
      <i class="fas fa-shield-alt cert-img-placeholder"></i>
    </div>
    <div class="cert-name">eCIR</div>
    <div class="cert-issuer">eLearnSecurity</div>
    <span class="cert-verify"><i class="fas fa-external-link-alt"></i> Verify</span>
  </a>

  <a class="cert-card" href="#" target="_blank" rel="noopener" title="eCTHP">
    <div class="cert-img-wrap">
      <i class="fas fa-shield-alt cert-img-placeholder"></i>
    </div>
    <div class="cert-name">eCTHP</div>
    <div class="cert-issuer">eLearnSecurity</div>
    <span class="cert-verify"><i class="fas fa-external-link-alt"></i> Verify</span>
  </a>

  <a class="cert-card" href="#" target="_blank" rel="noopener" title="CRTP">
    <div class="cert-img-wrap">
      <i class="fas fa-shield-alt cert-img-placeholder"></i>
    </div>
    <div class="cert-name">CRTP</div>
    <div class="cert-issuer">Altered Security</div>
    <span class="cert-verify"><i class="fas fa-external-link-alt"></i> Verify</span>
  </a>

  <a class="cert-card" href="#" target="_blank" rel="noopener" title="eJPT">
    <div class="cert-img-wrap">
      <i class="fas fa-shield-alt cert-img-placeholder"></i>
    </div>
    <div class="cert-name">eJPT</div>
    <div class="cert-issuer">eLearnSecurity</div>
    <span class="cert-verify"><i class="fas fa-external-link-alt"></i> Verify</span>
  </a>

</div>
