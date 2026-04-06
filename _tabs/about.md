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
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 1.1rem;
}

/* ── Cert card ── */
.cert-card {
  position: relative;
  border: 1px solid var(--card-border-color, rgba(134,140,151,0.15));
  border-radius: 0.75rem;
  background: var(--card-bg, var(--main-bg));
  overflow: hidden;
  text-decoration: none !important;
  display: flex;
  flex-direction: column;
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}
.cert-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 10px 28px rgba(0,0,0,0.13);
  border-color: rgba(159,239,0,0.35);
}

/* ── Certificate image preview ── */
.cert-preview {
  position: relative;
  width: 100%;
  aspect-ratio: 600 / 464;
  overflow: hidden;
  background: rgba(134,140,151,0.06);
}
.cert-preview img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: top;
  transition: transform 0.35s ease;
  display: block;
}
.cert-card:hover .cert-preview img {
  transform: scale(1.04);
}

/* ── Overlay on hover ── */
.cert-overlay {
  position: absolute;
  inset: 0;
  background: rgba(0,0,0,0.45);
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: opacity 0.2s ease;
}
.cert-card:hover .cert-overlay {
  opacity: 1;
}
.cert-overlay span {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.82rem;
  font-weight: 700;
  color: #9fef00;
  border: 1px solid rgba(159,239,0,0.5);
  background: rgba(0,0,0,0.5);
  padding: 0.4rem 1rem;
  border-radius: 2rem;
  backdrop-filter: blur(4px);
}

/* ── Card footer ── */
.cert-footer {
  padding: 0.75rem 1rem;
  border-top: 1px solid var(--card-border-color, rgba(134,140,151,0.15));
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
}
.cert-name {
  font-size: 0.88rem;
  font-weight: 700;
  color: var(--heading-color, inherit);
}
.cert-issuer {
  font-size: 0.7rem;
  color: var(--text-muted, #868c97);
}
.cert-badge-label {
  display: inline-flex;
  align-items: center;
  gap: 0.25em;
  font-size: 0.68rem;
  font-weight: 600;
  color: #9fef00;
  background: rgba(159,239,0,0.08);
  border: 1px solid rgba(159,239,0,0.2);
  padding: 0.2em 0.55em;
  border-radius: 0.3rem;
  white-space: nowrap;
}

@media (max-width: 480px) {
  .cert-grid { grid-template-columns: 1fr; }
}
</style>

<div class="section-heading">
  <i class="fas fa-certificate"></i> Certifications
</div>

<div class="cert-grid">

  <a class="cert-card" href="https://www.credly.com/badges/ac5b88a1-7238-4682-b56d-3cb65f438fef/public_url" target="_blank" rel="noopener">
    <div class="cert-preview">
      <img src="/assets/img/certs/CCDL2.png" alt="CCDL2 Certificate" loading="lazy">
      <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> Verify</span></div>
    </div>
    <div class="cert-footer">
      <div>
        <div class="cert-name">CCDL2</div>
        <div class="cert-issuer">CyberDefenders</div>
      </div>
      <span class="cert-badge-label"><i class="fas fa-check-circle"></i> Verified</span>
    </div>
  </a>

  <a class="cert-card" href="https://certs.ine.com/04d7c750-2621-4dd9-a7da-49e6ad5d3576" target="_blank" rel="noopener">
    <div class="cert-preview">
      <img src="/assets/img/certs/eCIR.png" alt="eCIR Certificate" loading="lazy">
      <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> Verify</span></div>
    </div>
    <div class="cert-footer">
      <div>
        <div class="cert-name">eCIR</div>
        <div class="cert-issuer">INE Security</div>
      </div>
      <span class="cert-badge-label"><i class="fas fa-check-circle"></i> Verified</span>
    </div>
  </a>

  <a class="cert-card" href="https://certs.ine.com/69c38171-31cb-47a8-80cf-00b9abed1b18" target="_blank" rel="noopener">
    <div class="cert-preview">
      <img src="/assets/img/certs/eCTHP.png" alt="eCTHP Certificate" loading="lazy">
      <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> Verify</span></div>
    </div>
    <div class="cert-footer">
      <div>
        <div class="cert-name">eCTHP</div>
        <div class="cert-issuer">INE Security</div>
      </div>
      <span class="cert-badge-label"><i class="fas fa-check-circle"></i> Verified</span>
    </div>
  </a>

  <a class="cert-card" href="https://www.credential.net/b26d244a-ae9a-47fc-bbf1-06f86bdac127" target="_blank" rel="noopener">
    <div class="cert-preview">
      <img src="/assets/img/certs/CRTP.png" alt="CRTP Certificate" loading="lazy">
      <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> Verify</span></div>
    </div>
    <div class="cert-footer">
      <div>
        <div class="cert-name">CRTP</div>
        <div class="cert-issuer">Altered Security</div>
      </div>
      <span class="cert-badge-label"><i class="fas fa-check-circle"></i> Verified</span>
    </div>
  </a>

  <a class="cert-card" href="https://www.credential.net/3a82f4b5-4d53-40eb-8264-0314a8a6cfcd" target="_blank" rel="noopener">
    <div class="cert-preview">
      <img src="/assets/img/certs/eJPT.png" alt="eJPT Certificate" loading="lazy">
      <div class="cert-overlay"><span><i class="fas fa-external-link-alt"></i> Verify</span></div>
    </div>
    <div class="cert-footer">
      <div>
        <div class="cert-name">eJPT</div>
        <div class="cert-issuer">INE Security</div>
      </div>
      <span class="cert-badge-label"><i class="fas fa-check-circle"></i> Verified</span>
    </div>
  </a>

</div>
